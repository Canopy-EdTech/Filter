package proxy

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"log/slog"

	"github.com/Canopy-EdTech/Filter/internal/fakedb"
	"github.com/Canopy-EdTech/Filter/pkg/filter"
	"github.com/elazarl/goproxy"
)

// These tests run real HTTP traffic through NewServer. Upstream servers listen
// on 127.0.0.1, so the hostnames "127.0.0.1" and "localhost" act as two
// different sites for domain rules.

const keyword = "bad phrase"

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t         *testing.T
	proxy     *httptest.Server
	proxyURL  *url.URL
	client    *http.Client
	logs      *syncBuffer
	pagePath  string
	pageCheck string
}

func defaultE2ERules() map[int64][]fakedb.Rule {
	return map[int64][]fakedb.Rule{
		filter.DefaultGroupID: {
			{Type: "domain", Pattern: "localhost", Action: "block"},
			{Type: "keyword", Pattern: keyword, Action: "block"},
		},
	}
}

func newHarness(t *testing.T, rules map[int64][]fakedb.Rule) *harness {
	t.Helper()

	db, _ := fakedb.New(t, rules)
	engine := filter.NewEngine(db)

	pagePath := filepath.Join(t.TempDir(), "blockpage.html")
	if err := os.WriteFile(pagePath, []byte("<html>BLOCKED host={{.Host}} reason={{.Reason}}</html>"), 0o600); err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	mitm := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxy.GoproxyCa),
	}
	srv, err := NewServer("", engine, logger, mitm, pagePath)
	if err != nil {
		t.Fatal(err)
	}

	ps := httptest.NewServer(srv.Handler)
	t.Cleanup(ps.Close)
	proxyURL, _ := url.Parse(ps.URL)

	caPool := x509.NewCertPool()
	caPool.AddCert(mustParseCA(t))
	return &harness{
		t:        t,
		proxy:    ps,
		proxyURL: proxyURL,
		logs:     logs,
		pagePath: pagePath,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy:              http.ProxyURL(proxyURL),
				DisableCompression: true,
				TLSClientConfig:    &tls.Config{RootCAs: caPool},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func mustParseCA(t *testing.T) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func (h *harness) do(method, target string, body io.Reader, headers map[string]string) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		h.t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read body of %s %s: %v", method, target, err)
	}
	return resp, string(data)
}

func (h *harness) get(target string) (*http.Response, string) {
	h.t.Helper()
	return h.do(http.MethodGet, target, nil, nil)
}

// blockReasons returns the admin_reason of every "Blocked request" log line.
func (h *harness) blockReasons() []string {
	var reasons []string
	for _, line := range strings.Split(h.logs.String(), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Msg         string `json:"msg"`
			AdminReason string `json:"admin_reason"`
		}
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Msg == "Blocked request" {
			reasons = append(reasons, entry.AdminReason)
		}
	}
	return reasons
}

func (h *harness) waitForBlockLog(want string) {
	h.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range h.blockReasons() {
			if strings.Contains(r, want) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("no block log containing %q; got %v", want, h.blockReasons())
}

type upstream struct {
	*httptest.Server
	hits atomic.Int32
}

func newUpstream(t *testing.T, handler http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(u.Close)
	return u
}

// asLocalhost rewrites an upstream URL to use the hostname "localhost".
func asLocalhost(u *upstream) string { return strings.Replace(u.URL, "127.0.0.1", "localhost", 1) }

func writeChunks(w http.ResponseWriter, chunks ...string) {
	flusher := w.(http.Flusher)
	for _, c := range chunks {
		io.WriteString(w, c)
		flusher.Flush()
		time.Sleep(5 * time.Millisecond)
	}
}

func assertBlockPage(t *testing.T, resp *http.Response, body string) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "BLOCKED host=") {
		t.Fatalf("body is not the block page: %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
}

// --- request-time blocks ---

func TestE2EDomainBlockServesBlockPageWithoutContactingUpstream(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") })

	resp, body := h.get(asLocalhost(up) + "/page")
	assertBlockPage(t, resp, body)
	if !strings.Contains(body, "host=localhost") || !strings.Contains(body, "reason=This site is blocked.") {
		t.Fatalf("block page lacks host/reason: %q", body)
	}
	if up.hits.Load() != 0 {
		t.Fatal("blocked request reached upstream")
	}
	h.waitForBlockLog("domain rule matched: localhost")

	// The same server under another hostname is unaffected.
	resp, body = h.get(up.URL + "/page")
	if resp.StatusCode != http.StatusOK || body != "secret" {
		t.Fatalf("unblocked host: %d %q", resp.StatusCode, body)
	}
}

func TestE2EPathRuleBlocks(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })

	resp, body := h.get(up.URL + "/blocked/anything")
	assertBlockPage(t, resp, body)
	if up.hits.Load() != 0 {
		t.Fatal("path-blocked request reached upstream")
	}
	h.waitForBlockLog("path rule matched")

	if resp, body := h.get(up.URL + "/fine"); resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("clean path: %d %q", resp.StatusCode, body)
	}
}

func TestE2EStripsHeadersThatHideContent(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	var seen http.Header
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() })

	h.do(http.MethodGet, up.URL, nil, map[string]string{
		"Accept-Encoding":          "gzip, br",
		"Sec-WebSocket-Extensions": "permessage-deflate",
	})
	// The client's value is dropped. goproxy's own transport then asks for
	// plain gzip and decompresses it transparently, so "gzip" is expected.
	if v := seen.Get("Accept-Encoding"); strings.Contains(v, "br") {
		t.Errorf("client Accept-Encoding forwarded upstream: %q", v)
	}
	if v := seen.Get("Sec-WebSocket-Extensions"); v != "" {
		t.Errorf("upstream saw Sec-WebSocket-Extensions %q", v)
	}
}

// --- response body blocks ---

func TestE2EKeywordInFiniteResponseServesBlockPage(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	body := "hello there, this has a " + keyword + " in it"
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		io.WriteString(w, body)
	})

	resp, got := h.get(up.URL)
	assertBlockPage(t, resp, got)
	if strings.Contains(got, keyword) {
		t.Fatal("blocked content leaked into the block page")
	}
	if resp.ContentLength != int64(len(got)) {
		t.Fatalf("Content-Length %d does not match body length %d", resp.ContentLength, len(got))
	}
	h.waitForBlockLog(`keyword rule matched: "bad phrase"`)
}

// Regression: chunked HTML used to be truncated mid-stream, leaving a blank page.
func TestE2EKeywordInChunkedHTMLServesBlockPage(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		writeChunks(w, "<html><body>intro ", "some text with a "+keyword, " and a footer</body></html>")
	})

	resp, got := h.get(up.URL)
	assertBlockPage(t, resp, got)
	if strings.Contains(got, "intro") {
		t.Fatalf("partial upstream HTML leaked: %q", got)
	}
	h.waitForBlockLog("keyword rule matched")
}

func TestE2EKeywordInChunkedPlainTextTruncatesAndLogs(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		writeChunks(w, strings.Repeat("a", 500), "now a "+keyword+" appears", " and more")
	})

	resp, got := h.get(up.URL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; streaming blocks cannot change the status", resp.StatusCode)
	}
	if strings.Contains(got, keyword) || strings.Contains(got, "and more") {
		t.Fatalf("content after the match leaked: %q", got)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 500)) {
		t.Fatalf("text before the match was lost: %d bytes", len(got))
	}
	h.waitForBlockLog(`keyword rule matched: "bad phrase"`)
}

func TestE2EKeywordSplitAcrossChunksIsCaught(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeChunks(w, strings.Repeat("x ", 150)+"bad ", "phra", "se tail")
	})

	_, got := h.get(up.URL)
	if strings.Contains(got, "phrase") || strings.Contains(got, "tail") {
		t.Fatalf("split keyword slipped through: %q", got)
	}
	h.waitForBlockLog("keyword rule matched")
}

func TestE2ECleanChunkedBodiesArriveIntact(t *testing.T) {
	for _, contentType := range []string{"text/html", "text/plain", "application/json"} {
		t.Run(contentType, func(t *testing.T) {
			h := newHarness(t, defaultE2ERules())
			var want strings.Builder
			var chunks []string
			for i := 0; i < 40; i++ {
				chunk := fmt.Sprintf("<p>line %d %s</p>", i, strings.Repeat("z", 200))
				chunks = append(chunks, chunk)
				want.WriteString(chunk)
			}
			chunks = append(chunks, "THE END")
			want.WriteString("THE END")

			up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				writeChunks(w, chunks...)
			})

			resp, got := h.get(up.URL)
			if resp.StatusCode != 200 || got != want.String() {
				t.Fatalf("status %d, got %d bytes, want %d (tail %q)", resp.StatusCode, len(got), want.Len(), got[max(0, len(got)-20):])
			}
		})
	}
}

func TestE2EServerSentEventsAreBlockedMidStream(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeChunks(w,
			"data: "+strings.Repeat("one ", 100)+"\n\n",
			"data: "+strings.Repeat("two ", 100)+"\n\n",
			"data: the model said a "+keyword+" here\n\n",
			"data: after\n\n",
		)
	})

	resp, got := h.get(up.URL)
	if resp.StatusCode != http.StatusOK || !strings.Contains(got, "one one") {
		t.Fatalf("early events lost: status %d, %q", resp.StatusCode, got)
	}
	if strings.Contains(got, keyword) || strings.Contains(got, "after") {
		t.Fatalf("blocked event leaked: %q", got)
	}
	h.waitForBlockLog("keyword rule matched")
}

func TestE2ENonTextContentIsNotInspected(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	payload := "binary " + keyword + " data"
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		io.WriteString(w, payload)
	})
	resp, got := h.get(up.URL)
	if resp.StatusCode != 200 || got != payload {
		t.Fatalf("%d %q", resp.StatusCode, got)
	}
	if len(h.blockReasons()) != 0 {
		t.Fatalf("unexpected block logs: %v", h.blockReasons())
	}
}

func TestE2EUpstreamStatusAndHeadersPreservedWhenClean(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom", "kept")
		w.Header().Set("Content-Length", "6")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "teapot")
	})
	resp, got := h.get(up.URL)
	if resp.StatusCode != http.StatusTeapot || got != "teapot" || resp.Header.Get("X-Custom") != "kept" {
		t.Fatalf("%d %q %v", resp.StatusCode, got, resp.Header)
	}
}

func TestE2EGzipResponses(t *testing.T) {
	h := newHarness(t, defaultE2ERules())

	serve := func(text string) *upstream {
		compressed := gzipped(t, text)
		return newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(len(compressed)))
			w.Write(compressed)
		})
	}

	t.Run("blocked keyword inside gzip", func(t *testing.T) {
		resp, got := h.get(serve("<p>a " + keyword + " b</p>").URL)
		assertBlockPage(t, resp, got)
		if resp.Header.Get("Content-Encoding") != "" {
			t.Fatal("block page must not claim to be compressed")
		}
	})

	// goproxy's transport negotiates gzip itself and decompresses before the
	// response hooks run, so the client receives the plain content.
	t.Run("clean gzip is delivered decoded", func(t *testing.T) {
		resp, got := h.get(serve("<p>all good</p>").URL)
		if resp.StatusCode != 200 || got != "<p>all good</p>" {
			t.Fatalf("%d %q %v", resp.StatusCode, got, resp.Header)
		}
	})
}

// --- CORS ---

func TestE2EReplacedResponseKeepsUpstreamCORS(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Type", "application/json")
		hd.Set("Access-Control-Allow-Origin", "https://app.example")
		hd.Set("Access-Control-Allow-Credentials", "true")
		hd.Set("Access-Control-Expose-Headers", "X-Request-Id")
		hd.Set("Vary", "Origin")
		hd.Set("X-Secret", "must not survive")
		body := `{"text":"a ` + keyword + `"}`
		hd.Set("Content-Length", fmt.Sprint(len(body)))
		io.WriteString(w, body)
	})

	resp, got := h.do(http.MethodGet, up.URL, nil, map[string]string{"Origin": "https://app.example"})
	assertBlockPage(t, resp, got)
	hd := resp.Header
	if hd.Get("Access-Control-Allow-Origin") != "https://app.example" ||
		hd.Get("Access-Control-Allow-Credentials") != "true" ||
		hd.Get("Access-Control-Expose-Headers") != "X-Request-Id" {
		t.Fatalf("upstream CORS headers lost: %v", hd)
	}
	if !strings.Contains(hd.Get("Vary"), "Origin") {
		t.Fatalf("Vary lost: %v", hd)
	}
	if hd.Get("X-Secret") != "" {
		t.Fatal("unrelated upstream header survived the replacement")
	}
}

func TestE2EProxyBlockResponsesMirrorOrigin(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {})

	resp, body := h.do(http.MethodGet, asLocalhost(up), nil, map[string]string{"Origin": "https://app.example"})
	assertBlockPage(t, resp, body)
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" ||
		resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("CORS headers missing: %v", resp.Header)
	}
}

func TestE2EBlockedPreflightIsApprovedAndNeverReachesUpstream(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {})

	resp, _ := h.do(http.MethodOptions, asLocalhost(up)+"/chat", nil, map[string]string{
		"Origin":                         "https://app.example",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "content-type",
	})
	if resp.StatusCode != http.StatusNoContent ||
		resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" ||
		resp.Header.Get("Access-Control-Allow-Methods") != "POST" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	if up.hits.Load() != 0 {
		t.Fatal("preflight for a blocked domain reached upstream")
	}
}

func TestE2EPreflightForAllowedSiteGoesUpstream(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example")
		w.WriteHeader(http.StatusNoContent)
	})
	resp, _ := h.do(http.MethodOptions, up.URL, nil, map[string]string{
		"Origin": "https://app.example", "Access-Control-Request-Method": "POST",
	})
	if resp.StatusCode != http.StatusNoContent || up.hits.Load() != 1 {
		t.Fatalf("status %d, upstream hits %d", resp.StatusCode, up.hits.Load())
	}
}

// --- request payload blocks ---

func TestE2ERequestBodies(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	var received atomic.Value
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		received.Store(data)
		io.WriteString(w, "accepted")
	})

	tests := []struct {
		name        string
		contentType string
		encoding    string
		body        []byte
		blocked     bool
	}{
		{"clean json", "application/json", "", []byte(`{"q":"hello"}`), false},
		{"json with keyword", "application/json", "", []byte(`{"q":"a ` + keyword + `"}`), true},
		{"form with plus-encoded keyword", "application/x-www-form-urlencoded", "", []byte("q=a+bad+phrase"), true},
		{"form with percent-encoded keyword", "application/x-www-form-urlencoded", "", []byte("q=a%20bad%20phrase"), true},
		{"plain text keyword", "text/plain", "", []byte("say " + keyword), true},
		{"multipart keyword", "multipart/form-data; boundary=xyz", "", []byte("--xyz\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n" + keyword + "\r\n--xyz--\r\n"), true},
		{"gzip keyword", "application/json", "gzip", gzipped(t, `{"q":"`+keyword+`"}`), true},
		{"gzip clean", "application/json", "gzip", gzipped(t, `{"q":"fine"}`), false},
		{"binary type skipped", "application/octet-stream", "", []byte(keyword), false},
		{"escaped keyword", "application/json", "", []byte(js(`{"q":"bad~u0020phrase"}`)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received.Store([]byte(nil))
			before := up.hits.Load()
			headers := map[string]string{"Content-Type": tt.contentType}
			if tt.encoding != "" {
				headers["Content-Encoding"] = tt.encoding
			}

			resp, got := h.do(http.MethodPost, up.URL, bytes.NewReader(tt.body), headers)
			if tt.blocked {
				assertBlockPage(t, resp, got)
				if !strings.Contains(got, "reason=This request contains blocked content.") {
					t.Fatalf("wrong reason: %q", got)
				}
				if up.hits.Load() != before {
					t.Fatal("blocked request body reached upstream")
				}
				return
			}
			if resp.StatusCode != 200 || got != "accepted" {
				t.Fatalf("clean request failed: %d %q", resp.StatusCode, got)
			}
			if !bytes.Equal(received.Load().([]byte), tt.body) {
				t.Fatalf("upstream received altered body: %q", received.Load())
			}
		})
	}
	h.waitForBlockLog("request body")
}

func TestE2EOversizedRequestBodyIsForwardedIntact(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	var size atomic.Int64
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		size.Store(n)
	})
	body := bytes.Repeat([]byte("a"), maxRequestBodyInspect+1024)

	resp, _ := h.do(http.MethodPost, up.URL, bytes.NewReader(body), map[string]string{"Content-Type": "text/plain"})
	if resp.StatusCode != 200 || size.Load() != int64(len(body)) {
		t.Fatalf("status %d, upstream received %d of %d bytes", resp.StatusCode, size.Load(), len(body))
	}
}

// --- CONNECT / TLS ---

func TestE2EAcceptedDomainTunnelsWithoutInspection(t *testing.T) {
	rules := map[int64][]fakedb.Rule{filter.DefaultGroupID: {
		{Type: "domain", Pattern: "localhost", Action: "accept"},
		{Type: "keyword", Pattern: keyword, Action: "block"},
	}}
	h := newHarness(t, rules)

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "tunnelled "+keyword)
	}))
	t.Cleanup(secure.Close)

	pool := x509.NewCertPool()
	pool.AddCert(secure.Certificate())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(h.proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, // httptest cert SANs
		},
	}

	target := strings.Replace(secure.URL, "127.0.0.1", "localhost", 1)
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// The client verified the upstream's own certificate, proving no MITM,
	// and the keyword passed because the traffic was never decrypted.
	if resp.StatusCode != 200 || string(body) != "tunnelled "+keyword {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if len(h.blockReasons()) != 0 {
		t.Fatalf("unexpected blocks: %v", h.blockReasons())
	}
}

func TestE2EBlockedDomainOverHTTPSServesBlockPage(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	secure := newUpstream(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret") })

	// https://localhost:<port> via CONNECT: the proxy terminates TLS with its
	// own CA (which the harness client trusts) and serves the block page.
	target := "https://localhost:" + strings.Split(secure.URL, ":")[2]
	resp, body := h.get(target)
	assertBlockPage(t, resp, body)
	if !strings.Contains(body, "host=localhost") {
		t.Fatalf("body %q", body)
	}
	if secure.hits.Load() != 0 {
		t.Fatal("blocked HTTPS request reached upstream")
	}
	h.waitForBlockLog("domain rule matched")
}

// --- WebSocket ---

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type wsUpstream struct {
	*upstream
	handshakeHeaders chan http.Header
	fromClient       chan string // text messages the upstream received
}

// newWSUpstream accepts a WebSocket upgrade, sends the given server frames,
// then records text messages from the client until the connection closes.
func newWSUpstream(t *testing.T, serverFrames ...[]byte) *wsUpstream {
	t.Helper()
	ws := &wsUpstream{handshakeHeaders: make(chan http.Header, 1), fromClient: make(chan string, 16)}
	ws.upstream = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		ws.handshakeHeaders <- r.Header.Clone()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID))
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
		for _, frame := range serverFrames {
			rw.Write(frame)
		}
		rw.Flush()

		for {
			opcode, payload, err := readFrame(rw.Reader)
			if err != nil || opcode == 8 {
				return
			}
			if opcode == 1 {
				ws.fromClient <- string(payload)
			}
		}
	})
	return ws
}

func readFrame(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	head := make([]byte, 2)
	if _, err = io.ReadFull(r, head); err != nil {
		return
	}
	opcode = head[0] & 0x0f
	n := int(head[1] & 0x7f)
	if n == 126 {
		ext := make([]byte, 2)
		if _, err = io.ReadFull(r, ext); err != nil {
			return
		}
		n = int(ext[0])<<8 | int(ext[1])
	}
	var key []byte
	if head[1]&0x80 != 0 {
		key = make([]byte, 4)
		if _, err = io.ReadFull(r, key); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	for i := range payload {
		if key != nil {
			payload[i] ^= key[i%4]
		}
	}
	return
}

// dialWS opens a WebSocket to target through the proxy and returns the
// connection positioned after the 101 response.
func dialWS(t *testing.T, h *harness, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, _ := url.Parse(target)
	conn, err := net.DialTimeout("tcp", h.proxyURL.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(8 * time.Second))

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n", target, u.Host)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake status = %d", resp.StatusCode)
	}
	return conn, br
}

func TestE2EWebSocketServerMessages(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	ws := newWSUpstream(t,
		serverFrame(1, true, "welcome"),
		serverFrame(1, true, "the bot said a "+keyword),
		serverFrame(1, true, "never delivered"),
	)

	conn, br := dialWS(t, h, ws.URL)

	if hd := <-ws.handshakeHeaders; hd.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("upstream was offered extensions: %q", hd.Get("Sec-WebSocket-Extensions"))
	}

	opcode, payload, err := readFrame(br)
	if err != nil || opcode != 1 || string(payload) != "welcome" {
		t.Fatalf("first message: opcode %d %q err %v", opcode, payload, err)
	}
	// The blocked message is never delivered. Over plain ws:// goproxy leaves
	// the client socket open after the stream ends, so the read ends with a
	// timeout rather than a close; what matters is that no frame arrives.
	conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if opcode, payload, err := readFrame(br); err == nil {
		t.Fatalf("blocked message delivered: opcode %d %q", opcode, payload)
	}
	h.waitForBlockLog("keyword rule matched")
}

func TestE2EWebSocketClientMessages(t *testing.T) {
	h := newHarness(t, defaultE2ERules())
	ws := newWSUpstream(t)
	conn, _ := dialWS(t, h, ws.URL)

	if _, err := conn.Write(maskedFrame(1, true, "hello upstream")); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-ws.fromClient:
		if msg != "hello upstream" {
			t.Fatalf("upstream got %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("clean client message never reached upstream")
	}

	conn.Write(maskedFrame(1, true, "tell me a "+keyword))
	select {
	case msg := <-ws.fromClient:
		t.Fatalf("blocked message reached upstream: %q", msg)
	case <-time.After(500 * time.Millisecond):
	}
	h.waitForBlockLog("request body")
}
