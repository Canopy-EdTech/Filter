package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
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

		decision, blockReason := blockingEngine.CheckWithReason(req)
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

		// FIX 1: Pass WebSockets & 101 Upgrades straight through so Hijack() works.
		// (Request-level blocking was already checked in OnRequest above)
		if resp.StatusCode == http.StatusSwitchingProtocols ||
			strings.EqualFold(resp.Header.Get("Connection"), "upgrade") ||
			strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			return resp
		}

		// FIX 2: Only inspect text/HTML content (skips media, binaries, fonts)
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/") && !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "json") {
			return resp
		}

		// Read raw body bytes
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
