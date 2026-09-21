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

		decision, blockReason := blockingEngine.DecideWithReason(req)
		if decision != filter.Block {
			decision, blockReason = blockingEngine.CheckWithReason(req)
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
			resp.Body = &streamingFilter{reader: resp.Body, engine: blockingEngine, resp: resp}
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

		decision, blockReason := blockingEngine.CheckResponseWithReason(resp, decompressedBody)
		if decision == filter.Block && resp.Request != nil {
			logBlock(logger, resp.Request.URL.Hostname(), blockReason)

			// Render a clean local 403 response
			blocked := renderBlockResponse(resp.Request, blockPage, blockReason)

			// Extract custom HTML body
			blockedBody, _ := io.ReadAll(blocked.Body)
			blocked.Body.Close()

			// Overwrite remote server response with 403 Forbidden
			resp.StatusCode = blocked.StatusCode
			resp.Status = blocked.Status
			resp.Header = blocked.Header.Clone()
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
	return strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Transfer-Encoding")), "chunked") ||
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

type streamingFilter struct {
	reader  io.ReadCloser
	engine  *filter.Engine
	resp    *http.Response
	tail    []byte
	pending []byte
	blocked bool
}

func (f *streamingFilter) Read(p []byte) (int, error) {
	if len(f.pending) > 0 {
		n := copy(p, f.pending)
		f.pending = f.pending[n:]
		return n, nil
	}
	if f.blocked {
		return 0, io.EOF
	}

	phrase := []byte(filter.BlockedPhrase)
	buffer := make([]byte, 32*1024)
	n, err := f.reader.Read(buffer)
	if n > 0 {
		data := append(append([]byte{}, f.tail...), buffer[:n]...)
		decision, _ := f.engine.CheckResponseWithReason(f.resp, data)
		if decision == filter.Block {
			index := bytes.Index(bytes.ToLower(data), phrase)
			if index >= 0 {
				f.pending = append(f.pending, data[:index]...)
			}
			f.blocked = true
			if len(f.pending) > 0 {
				count := copy(p, f.pending)
				f.pending = f.pending[count:]
				return count, nil
			}
			return 0, io.EOF
		}

		keep := len(phrase) - 1
		if len(data) > keep {
			f.pending = append(f.pending, data[:len(data)-keep]...)
			f.tail = append(f.tail[:0], data[len(data)-keep:]...)
		} else {
			f.tail = append(f.tail[:0], data...)
		}
		if err == io.EOF {
			f.pending = append(f.pending, f.tail...)
			f.tail = nil
		}
		if len(f.pending) > 0 {
			count := copy(p, f.pending)
			f.pending = f.pending[count:]
			return count, nil
		}
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func (f *streamingFilter) Close() error { return f.reader.Close() }

type webSocketFilter struct {
	io.ReadWriter
	close       func() error
	engine      *filter.Engine
	resp        *http.Response
	pending     []byte
	blocked     bool
	fragmented  bool
	textPayload []byte
	textFrames  []byte
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
		decision, _ := f.engine.CheckResponseWithReason(f.resp, f.textPayload)
		if decision == filter.Block {
			f.blocked = true
			return 0, io.EOF
		}
		f.pending = append(f.pending[:0], f.textFrames...)
		f.fragmented = false
		f.textPayload = nil
		f.textFrames = nil
	} else if opcode == 1 {
		decision, _ := f.engine.CheckResponseWithReason(f.resp, payload)
		if decision == filter.Block {
			f.blocked = true
			return 0, io.EOF
		}
	}
	f.pending = frame
	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

func (f *webSocketFilter) Close() error { return f.close() }

func renderBlockResponse(req *http.Request, blockPage *template.Template, reason filter.BlockReason) *http.Response {
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
