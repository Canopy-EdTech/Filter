package proxy

import (
	"net/http"

	"github.com/elazarl/goproxy"
)

// addCORSHeaders lets a cross-origin caller read a locally generated block
// response. Without them the browser reports an opaque CORS failure instead of
// the 403, which breaks web apps that handle error statuses.
func addCORSHeaders(req *http.Request, resp *http.Response) {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return
	}
	resp.Header.Set("Access-Control-Allow-Origin", origin)
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	resp.Header.Add("Vary", "Origin")
}

func isPreflight(req *http.Request) bool {
	return req.Method == http.MethodOptions &&
		req.Header.Get("Origin") != "" &&
		req.Header.Get("Access-Control-Request-Method") != ""
}

// preflightResponse approves a CORS preflight for a request that is about to
// be blocked, so the browser goes on to send the real request and receives
// the block response (with CORS headers) rather than a preflight failure.
func preflightResponse(req *http.Request) *http.Response {
	resp := goproxy.NewResponse(req, "", http.StatusNoContent, "")
	resp.Header.Del("Content-Type")
	addCORSHeaders(req, resp)
	resp.Header.Set("Access-Control-Allow-Methods", req.Header.Get("Access-Control-Request-Method"))
	if headers := req.Header.Get("Access-Control-Request-Headers"); headers != "" {
		resp.Header.Set("Access-Control-Allow-Headers", headers)
	}
	return resp
}
