package proxy

import (
	"bytes"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/elazarl/goproxy"
)

func NewServer(addr string, blockingEngine *filter.Engine, logger *slog.Logger, mitmConnect *goproxy.ConnectAction, blockPagePath string) (*http.Server, error) {
	p := goproxy.NewProxyHttpServer()
	blockPage, err := template.ParseFiles(blockPagePath)
	if err != nil {
		return nil, err
	}

	p.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		decision, blockReason := blockingEngine.CheckWithReason(req)
		if decision != filter.Block {
			return req, nil
		}

		logBlock(logger, req.URL.Hostname(), blockReason)
		return nil, renderBlockResponse(req, blockPage, blockReason)
	})

	p.OnResponse().DoFunc(func(resp *http.Response, _ *goproxy.ProxyCtx) *http.Response {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp
		}
		resp.Body.Close()

		decision, blockReason := blockingEngine.CheckResponseWithReason(resp, body)
		if decision == filter.Block {
			if resp.Request != nil {
				logBlock(logger, resp.Request.URL.Hostname(), blockReason)
				blocked := renderBlockResponse(resp.Request, blockPage, blockReason)
				resp.StatusCode = blocked.StatusCode
				resp.Status = blocked.Status
				resp.Header = blocked.Header
				body, _ = io.ReadAll(blocked.Body)
				blocked.Body.Close()
			}
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return resp
	})

	p.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req, err := http.NewRequest(http.MethodConnect, "https://"+host, nil)
		if err != nil {
			return &goproxy.ConnectAction{Action: goproxy.ConnectReject}, host
		}

		decision, blockReason := blockingEngine.DecideWithReason(req)
		switch decision {
		case filter.Block:
			logBlock(logger, host, blockReason)
			return connectBlockAction(req, blockPage, blockReason), host
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

func renderBlockResponse(req *http.Request, blockPage *template.Template, reason filter.BlockReason) *http.Response {
	var body bytes.Buffer
	data := struct {
		Host   string
		Reason string
	}{Host: req.URL.Hostname(), Reason: reason.Reason}
	if err := blockPage.Execute(&body, data); err != nil {
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "request blocked by policy")
	}
	return goproxy.NewResponse(req, goproxy.ContentTypeHtml, http.StatusForbidden, body.String())
}

func connectBlockAction(req *http.Request, blockPage *template.Template, reason filter.BlockReason) *goproxy.ConnectAction {
	return &goproxy.ConnectAction{
		Action: goproxy.ConnectHijack,
		Hijack: func(_ *http.Request, client net.Conn, _ *goproxy.ProxyCtx) {
			response := renderBlockResponse(req, blockPage, reason)
			_ = response.Write(client)
			_ = client.Close()
		},
	}
}

func logBlock(logger *slog.Logger, host string, reason filter.BlockReason) {
	if logger != nil {
		logger.Info("Blocked request", "host", host, "admin_reason", reason.AdminReason)
	}
}
