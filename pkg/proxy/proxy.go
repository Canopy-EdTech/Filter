package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/elazarl/goproxy"
)

func NewServer(addr string, blockingEngine *filter.Engine, logger *slog.Logger, mitmConnect *goproxy.ConnectAction, blockPagePath string) (*http.Server, error) {
	p := goproxy.NewProxyHttpServer()
	blockPage, err := template.ParseFiles(blockPagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load block page template: %w", err)
	}

	// 1. HTTP/HTTPS Request Interception
	p.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Prevent client browsers from using Encrypted Client Hello (ECH) or HTTP/2 framing bypasses
		req.Header.Del("Accept-Encoding") // Forces plain text or simple gzip encoding
		// permessage-deflate would make WebSocket payloads uninspectable.
		req.Header.Del("Sec-WebSocket-Extensions")

		decision, blockReason := blockingEngine.DecideWithReason(req)
		if decision != filter.Block {
			decision, blockReason = blockingEngine.CheckWithReason(req)
		}
		if decision != filter.Block {
			decision, blockReason = inspectRequestBody(req, blockingEngine)
		}
		if decision != filter.Block {
			return req, nil
		}

		logBlock(logger, req.URL.Hostname(), blockReason)
		return req, renderBlockResponse(req, blockPage, blockReason)
	})

	// 2. Response Body/Keyword Interception
	p.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		if resp == nil || resp.Body == nil {
			return resp
		}

		// Streaming and WebSocket filters block mid-body, after the response
		// has started, so they report the block through this callback.
		onBlock := func(reason filter.BlockReason) {
			if resp.Request != nil {
				logBlock(logger, resp.Request.URL.Hostname(), reason)
			}
		}

		if resp.StatusCode == http.StatusSwitchingProtocols ||
			strings.EqualFold(resp.Header.Get("Connection"), "upgrade") ||
			strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			// goproxy hijacks after this hook. Wrapping the upstream body lets us
			// inspect server-to-client text frames without breaking the upgrade.
			if readWriter, ok := resp.Body.(io.ReadWriter); ok {
				resp.Body = &webSocketFilter{
					ReadWriter: readWriter,
					close:      resp.Body.Close,
					engine:     blockingEngine,
					resp:       resp,
					onBlock:    onBlock,
				}
			}
			return resp
		}

		// FIX 2: Only inspect text/HTML content (skips media, binaries, fonts)
		contentType := resp.Header.Get("Content-Type")
		if !isTextContentType(contentType) {
			return resp
		}

		if isStreamingResponse(resp) {
			resp.Body = &streamingFilter{reader: resp.Body, engine: blockingEngine, resp: resp, onBlock: onBlock}
			return resp
		}

		// Read raw body bytes for finite responses so a blocked response can be
		// replaced with the normal local block page.
		rawBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp
		}
		resp.Body.Close()

		// FIX 3: Decompress Gzip/Deflate for keyword scanning
		decompressedBody := decompressBody(resp.Header.Get("Content-Encoding"), rawBody)

		decision, blockReason := checkVariants(decompressedBody, func(b []byte) (filter.Decision, filter.BlockReason) {
			return blockingEngine.CheckResponseWithReason(resp, b)
		})
		if decision == filter.Block && resp.Request != nil {
			logBlock(logger, resp.Request.URL.Hostname(), blockReason)

			// Render a clean local 403 response
			blocked := renderBlockResponse(resp.Request, blockPage, blockReason)

			// Extract custom HTML body
			blockedBody, _ := io.ReadAll(blocked.Body)
			blocked.Body.Close()

			// Overwrite remote server response with 403 Forbidden, keeping the
			// upstream CORS headers so cross-origin fetches (e.g. AI chat apps)
			// still receive the 403 instead of failing with a CORS error.
			corsHeaders := resp.Header.Clone()
			resp.StatusCode = blocked.StatusCode
			resp.Status = blocked.Status
			resp.Header = blocked.Header.Clone()
			for name, values := range corsHeaders {
				if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") || http.CanonicalHeaderKey(name) == "Vary" {
					resp.Header[name] = values
				}
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Del("Content-Encoding") // Clear compression headers since we're serving plain HTML

			rawBody = blockedBody
		}

		// Re-assign body buffer for downstream delivery
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		resp.ContentLength = int64(len(rawBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(rawBody)))
		return resp
	})

	// 3. CONNECT / TLS Handshake Handling
	p.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req, err := http.NewRequest(http.MethodConnect, "https://"+host, nil)
		if err != nil {
			return &goproxy.ConnectAction{Action: goproxy.ConnectReject}, host
		}

		decision, blockReason := blockingEngine.DecideWithReason(req)
		switch decision {
		case filter.Block:
			logBlock(logger, host, blockReason)
			// Return MITM so goproxy can complete the TLS handshake and serve
			// your 403 HTML block page inside OnRequest/OnResponse.
			return mitmConnect, host

		case filter.Accept:
			if logger != nil {
				logger.Info("Allowed CONNECT without decryption", "host", host)
			}
			return &goproxy.ConnectAction{Action: goproxy.ConnectAccept}, host

		default:
			return mitmConnect, host
		}
	})

	return &http.Server{
		Addr:    addr,
		Handler: p,
	}, nil
}

// maxRequestBodyInspect caps how much of a request payload is buffered for
// keyword scanning. Larger bodies are forwarded without inspection.
const maxRequestBodyInspect = 10 << 20

// inspectRequestBody scans a text-like request payload for blocked keywords.
// The body is always restored so the request can still be forwarded.
func inspectRequestBody(req *http.Request, engine requestBodyChecker) (filter.Decision, filter.BlockReason) {
	if req.Body == nil || req.Body == http.NoBody || req.Method == http.MethodConnect ||
		!isInspectableRequestType(req.Header.Get("Content-Type")) {
		return filter.Accept, filter.BlockReason{}
	}

	buffered, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBodyInspect+1))
	// Put back what was read plus anything unread, whatever happens next.
	req.Body = readCloser{
		Reader: io.MultiReader(bytes.NewReader(buffered), req.Body),
		Closer: req.Body,
	}
	if err != nil || len(buffered) > maxRequestBodyInspect {
		return filter.Accept, filter.BlockReason{}
	}

	body := decompressBody(req.Header.Get("Content-Encoding"), buffered)
	if strings.HasPrefix(strings.ToLower(req.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		// Browsers encode spaces as '+' / %20, so match against the decoded form.
		if decoded, err := url.QueryUnescape(string(body)); err == nil {
			body = []byte(decoded)
		}
	}
	return checkVariants(body, func(b []byte) (filter.Decision, filter.BlockReason) {
		return engine.CheckRequestBodyWithReason(req, b)
	})
}

// requestBodyChecker is the part of filter.Engine request inspection needs.
type requestBodyChecker interface {
	CheckRequestBodyWithReason(req *http.Request, body []byte) (filter.Decision, filter.BlockReason)
}

type readCloser struct {
	io.Reader
	io.Closer
}

func isInspectableRequestType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return contentType == "" ||
		isTextContentType(contentType) ||
		strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(contentType, "multipart/form-data")
}

// Helper: Decompresses Gzip and Deflate encoded streams for inspection
func decompressBody(encoding string, body []byte) []byte {
	switch strings.ToLower(encoding) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		decompressed, err := io.ReadAll(r)
		if err != nil {
			return body
		}
		return decompressed

	case "deflate":
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		decompressed, err := io.ReadAll(r)
		if err != nil {
			return body
		}
		return decompressed

	default:
		return body
	}
}

func isStreamingResponse(resp *http.Response) bool {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "text/event-stream") {
		return true
	}
	// HTML documents are buffered even when chunked: once the streaming filter
	// has started sending a 200, a keyword hit can only truncate the page
	// (blank screen), whereas buffering lets us swap in the block page.
	if strings.HasPrefix(contentType, "text/html") {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Transfer-Encoding")), "chunked") ||
		resp.ContentLength < 0
}

func isTextContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "graphql")
}

// streamTailSize is how many trailing bytes of each chunk are held back and
// prepended to the next read, so a keyword match straddling a chunk
// boundary still gets caught. Keyword patterns are DB-driven and vary in
// length, so this is a generous fixed upper bound rather than a per-phrase
// value.
const streamTailSize = 256

// keywordMatcher is the part of filter.Engine the streaming filter needs.
type keywordMatcher interface {
	KeywordMatch(resp *http.Response, data []byte) (loc []int, found bool)
}

type streamingFilter struct {
	reader  io.ReadCloser
	engine  keywordMatcher
	resp    *http.Response
	tail    []byte
	pending []byte
	blocked bool
	readErr error
	onBlock func(filter.BlockReason)
}

func (f *streamingFilter) Read(p []byte) (int, error) {
	for {
		if len(f.pending) > 0 {
			n := copy(p, f.pending)
			f.pending = f.pending[n:]
			return n, nil
		}
		if f.blocked {
			return 0, io.EOF
		}
		if f.readErr != nil {
			return 0, f.readErr
		}

		buffer := make([]byte, 32*1024)
		n, err := f.reader.Read(buffer)
		if n > 0 {
			data := append(append([]byte{}, f.tail...), buffer[:n]...)
			if loc, found := f.engine.KeywordMatch(f.resp, data); found {
				f.pending = append(f.pending, data[:loc[0]]...)
				f.blocked = true
				if f.onBlock != nil {
					f.onBlock(filter.KeywordBlockReason(data, loc))
				}
				continue
			}

			keep := streamTailSize
			if len(data) > keep {
				f.pending = append(f.pending, data[:len(data)-keep]...)
				f.tail = append(f.tail[:0], data[len(data)-keep:]...)
			} else {
				f.tail = append(f.tail[:0], data...)
			}
		}
		if err != nil {
			// The held-back tail was already scanned; release it on a clean EOF
			// even when EOF arrives on a separate, empty read.
			if err == io.EOF {
				f.pending = append(f.pending, f.tail...)
				f.tail = nil
			}
			f.readErr = err
		}
	}
}

func (f *streamingFilter) Close() error { return f.reader.Close() }

// webSocketChecker is the part of filter.Engine WebSocket inspection needs.
type webSocketChecker interface {
	CheckResponseWithReason(resp *http.Response, body []byte) (filter.Decision, filter.BlockReason)
	CheckRequestBodyWithReason(req *http.Request, body []byte) (filter.Decision, filter.BlockReason)
}

// webSocketFilter inspects text messages in both directions. Read sees
// server-to-client frames; Write sees client-to-server frames (goproxy copies
// the client connection into the wrapped upstream body).
type webSocketFilter struct {
	io.ReadWriter
	close       func() error
	engine      webSocketChecker
	resp        *http.Response
	pending     []byte
	blocked     bool
	fragmented  bool
	textPayload []byte
	textFrames  []byte
	onBlock     func(filter.BlockReason)

	// Client-to-server state, touched only by Write.
	outBuf     []byte
	outKind    byte // opcode of the fragmented data message in progress, 0 if none
	outPayload []byte
	outFrames  []byte
	outBlocked bool
}

func (f *webSocketFilter) Read(p []byte) (int, error) {
	if len(f.pending) > 0 {
		n := copy(p, f.pending)
		f.pending = f.pending[n:]
		return n, nil
	}
	if f.blocked {
		return 0, io.EOF
	}

	header := make([]byte, 2)
	if _, err := io.ReadFull(f.ReadWriter, header); err != nil {
		return 0, err
	}
	frameLength := int64(header[1] & 0x7f)
	if frameLength == 126 {
		extended := make([]byte, 2)
		if _, err := io.ReadFull(f.ReadWriter, extended); err != nil {
			return 0, err
		}
		frameLength = int64(binary.BigEndian.Uint16(extended))
	} else if frameLength == 127 {
		extended := make([]byte, 8)
		if _, err := io.ReadFull(f.ReadWriter, extended); err != nil {
			return 0, err
		}
		frameLength = int64(binary.BigEndian.Uint64(extended))
	}
	if frameLength > 16*1024*1024 {
		return 0, fmt.Errorf("websocket frame exceeds inspection limit")
	}
	mask := header[1]&0x80 != 0
	maskKey := make([]byte, 0, 4)
	if mask {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(f.ReadWriter, maskKey); err != nil {
			return 0, err
		}
	}
	payload := make([]byte, frameLength)
	if _, err := io.ReadFull(f.ReadWriter, payload); err != nil {
		return 0, err
	}
	if mask {
		for index := range payload {
			payload[index] ^= maskKey[index%4]
		}
	}

	frame := append([]byte{}, header...)
	if frameLength >= 126 && frameLength <= 65535 {
		extended := make([]byte, 2)
		binary.BigEndian.PutUint16(extended, uint16(frameLength))
		frame = append(frame, extended...)
	}
	if frameLength > 65535 {
		extended := make([]byte, 8)
		binary.BigEndian.PutUint64(extended, uint64(frameLength))
		frame = append(frame, extended...)
	}
	frame = append(frame, maskKey...)
	frame = append(frame, payload...)
	opcode := header[0] & 0x0f
	fin := header[0]&0x80 != 0
	if opcode == 1 && !fin {
		f.fragmented = true
		f.textPayload = append(f.textPayload[:0], payload...)
		f.textFrames = append(f.textFrames[:0], frame...)
		return f.Read(p)
	}
	if opcode == 0 && f.fragmented {
		f.textPayload = append(f.textPayload, payload...)
		f.textFrames = append(f.textFrames, frame...)
		if !fin {
			return f.Read(p)
		}
		decision, reason := f.checkIncoming(f.textPayload)
		if decision == filter.Block {
			f.blocked = true
			f.reportBlock(reason)
			return 0, io.EOF
		}
		f.pending = append(f.pending[:0], f.textFrames...)
		f.fragmented = false
		f.textPayload = nil
		f.textFrames = nil
	} else if opcode == 1 {
		decision, reason := f.checkIncoming(payload)
		if decision == filter.Block {
			f.blocked = true
			f.reportBlock(reason)
			return 0, io.EOF
		}
	}
	f.pending = frame
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *webSocketFilter) checkIncoming(payload []byte) (filter.Decision, filter.BlockReason) {
	return checkVariants(payload, func(b []byte) (filter.Decision, filter.BlockReason) {
		return f.engine.CheckResponseWithReason(f.resp, b)
	})
}

func (f *webSocketFilter) reportBlock(reason filter.BlockReason) {
	if f.onBlock != nil {
		f.onBlock(reason)
	}
}

func (f *webSocketFilter) Close() error { return f.close() }

func renderBlockResponse(req *http.Request, blockPage *template.Template, reason filter.BlockReason) *http.Response {
	if isPreflight(req) {
		return preflightResponse(req)
	}

	resp := renderBlockPage(req, blockPage, reason)
	addCORSHeaders(req, resp)
	return resp
}

func renderBlockPage(req *http.Request, blockPage *template.Template, reason filter.BlockReason) *http.Response {
	var body bytes.Buffer
	data := struct {
		Host   string
		Reason string
	}{
		Host:   req.URL.Hostname(),
		Reason: reason.Reason,
	}

	if err := blockPage.Execute(&body, data); err != nil {
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "request blocked by policy")
	}
	return goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, body.String())
}

func logBlock(logger *slog.Logger, host string, reason filter.BlockReason) {
	if logger != nil {
		logger.Info("Blocked request", "host", host, "admin_reason", reason.AdminReason)
	}
}
