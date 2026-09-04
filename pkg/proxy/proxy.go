package proxy

import (
	"log/slog"
	"net/http"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/elazarl/goproxy"
)

func NewServer(addr string, blockingEngine *filter.Engine, logger *slog.Logger, mitmConnect *goproxy.ConnectAction) *http.Server {
	p := goproxy.NewProxyHttpServer()

	p.OnRequest().DoFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if !blockingEngine.IsBlocked(req) {
			return req, nil
		}

		if logger != nil {
			logger.Info("Blocked request", "host", req.URL.Hostname())
		}
		return nil, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "request blocked by policy")
	})

	p.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req, err := http.NewRequest(http.MethodConnect, "https://"+host, nil)
		if err == nil && blockingEngine.IsBlocked(req) {
			if logger != nil {
				logger.Info("Blocked CONNECT", "host", host)
			}
			return goproxy.RejectConnect, host
		}
		return mitmConnect, host
	})

	return &http.Server{
		Addr:    addr,
		Handler: p,
	}
}
