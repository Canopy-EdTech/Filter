package filter

import "net/http"

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) IsBlocked(req *http.Request) bool {
	host := req.URL.Hostname()

	if host == "example.com" {
		return true
	}

	return false
}
