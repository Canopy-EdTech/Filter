package filter

import (
	"bytes"
	"net/http"
	"strings"
)

type Engine struct{}

type Decision int

type BlockReason struct {
	Reason      string
	AdminReason string
}

const (
	Accept Decision = iota
	Block
	Inspect
)

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Decide(req *http.Request) Decision {
	decision, _ := e.DecideWithReason(req)
	return decision
}

func (e *Engine) DecideWithReason(req *http.Request) (Decision, BlockReason) {
	host := req.URL.Hostname()

	if host == "blocked.example" {
		return Block, BlockReason{
			Reason:      "This site is blocked.",
			AdminReason: "site is on the blocked site list: blocked.example",
		}
	}
	if host == "accepted.example" {
		return Accept, BlockReason{}
	}

	return Inspect, BlockReason{}
}

func (e *Engine) Check(req *http.Request) Decision {
	decision, _ := e.CheckWithReason(req)
	return decision
}

func (e *Engine) CheckWithReason(req *http.Request) (Decision, BlockReason) {
	if strings.HasPrefix(req.URL.Path, "/blocked") {
		return Block, BlockReason{
			Reason:      "This URL path is blocked.",
			AdminReason: "path rule matched: /blocked",
		}
	}

	return Accept, BlockReason{}
}

func (e *Engine) CheckResponse(resp *http.Response, body []byte) Decision {
	decision, _ := e.CheckResponseWithReason(resp, body)
	return decision
}

func (e *Engine) CheckResponseWithReason(resp *http.Response, body []byte) (Decision, BlockReason) {
	if resp == nil || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/") {
		return Accept, BlockReason{}
	}

	if bytes.Contains(bytes.ToLower(body), []byte("blocked phrase")) {
		return Block, BlockReason{
			Reason:      "This page contains blocked content.",
			AdminReason: "page content matched phrase: blocked phrase",
		}
	}

	return Accept, BlockReason{}
}

func (e *Engine) IsBlocked(req *http.Request) bool {
	return e.Check(req) == Block
}
