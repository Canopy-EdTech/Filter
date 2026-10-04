package proxy

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
)

func TestCheckVariantsDecodesJSONEscapes(t *testing.T) {
	check := func(b []byte) (filter.Decision, filter.BlockReason) {
		if bytes.Contains(b, []byte("bad phrase")) {
			return filter.Block, filter.BlockReason{}
		}
		return filter.Accept, filter.BlockReason{}
	}
	tests := map[string]struct {
		in   string
		want filter.Decision
	}{
		"plain":            {`{"q":"bad phrase"}`, filter.Block},
		"unicode escape":   {`{"q":"bad phrase"}`, filter.Block},
		"letter escapes":   {`{"q":"bad phrase"}`, filter.Block},
		"nested json":      {`{"q":"{\"x\":\"bad\\u0020phrase\"}"}`, filter.Block},
		"surrogate pair":   {`{"q":"bad phrase 😀"}`, filter.Block},
		"clean escaped":    {`{"q":"hello world"}`, filter.Accept},
		"malformed escape": {`{"q":"\u00zz bad"}`, filter.Accept},
		"trailing slash":   {`abc\`, filter.Accept},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got, _ := checkVariants([]byte(tt.in), check); got != tt.want {
				t.Fatalf("decision = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnescapeJSONStrings(t *testing.T) {
	got, changed := unescapeJSONStrings([]byte(`aé\n\"b😀`))
	if !changed || string(got) != "aé\n\"b\U0001F600" {
		t.Fatalf("got %q changed=%v", got, changed)
	}
}

func TestBlockResponseKeepsCORS(t *testing.T) {
	page := template.Must(template.New("p").Parse("blocked {{.Host}}"))

	req := httptest.NewRequest(http.MethodPost, "https://example.org/chat", nil)
	req.Header.Set("Origin", "https://app.example")
	resp := renderBlockResponse(req, page, filter.BlockReason{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("Allow-Origin = %q", got)
	}
	if resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("missing Allow-Credentials")
	}

	plain := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
	if renderBlockResponse(plain, page, filter.BlockReason{}).Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("CORS headers added without an Origin")
	}
}

func TestBlockedPreflightIsApproved(t *testing.T) {
	page := template.Must(template.New("p").Parse("blocked"))
	req := httptest.NewRequest(http.MethodOptions, "https://example.org/chat", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-foo")

	resp := renderBlockResponse(req, page, filter.BlockReason{})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	h := resp.Header
	if h.Get("Access-Control-Allow-Origin") != "https://app.example" ||
		h.Get("Access-Control-Allow-Methods") != "POST" ||
		h.Get("Access-Control-Allow-Headers") != "content-type,x-foo" {
		t.Fatalf("bad preflight headers: %v", h)
	}
}

// --- WebSocket client-to-server ---

type wsFakeChecker struct{ keyword string }

func (c wsFakeChecker) CheckResponseWithReason(_ *http.Response, body []byte) (filter.Decision, filter.BlockReason) {
	return c.check(body)
}

func (c wsFakeChecker) CheckRequestBodyWithReason(_ *http.Request, body []byte) (filter.Decision, filter.BlockReason) {
	return c.check(body)
}

func (c wsFakeChecker) check(body []byte) (filter.Decision, filter.BlockReason) {
	if bytes.Contains(body, []byte(c.keyword)) {
		return filter.Block, filter.BlockReason{AdminReason: "ws"}
	}
	return filter.Accept, filter.BlockReason{}
}

type rw struct{ bytes.Buffer }

func maskedFrame(opcode byte, fin bool, payload string) []byte {
	key := []byte{0x12, 0x34, 0x56, 0x78}
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first}
	n := len(payload)
	switch {
	case n < 126:
		frame = append(frame, 0x80|byte(n))
	case n <= 65535:
		frame = append(frame, 0x80|126, byte(n>>8), byte(n))
	}
	frame = append(frame, key...)
	for i := 0; i < n; i++ {
		frame = append(frame, payload[i]^key[i%4])
	}
	return frame
}

func newOutFilter(upstream *rw, reported *int) *webSocketFilter {
	return &webSocketFilter{
		ReadWriter: upstream,
		engine:     wsFakeChecker{keyword: "bad phrase"},
		resp:       &http.Response{Request: httptest.NewRequest(http.MethodGet, "https://example.org/ws", nil)},
		onBlock:    func(filter.BlockReason) { *reported++ },
	}
}

func writeInChunks(f *webSocketFilter, data []byte, size int) error {
	for len(data) > 0 {
		n := min(size, len(data))
		if _, err := f.Write(data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func TestWebSocketClientMessagesForwardedWhenClean(t *testing.T) {
	long := strings.Repeat("hello ", 100) // forces the 16-bit length form
	stream := bytes.Join([][]byte{
		maskedFrame(1, true, "hi there"),
		maskedFrame(1, true, long),
		maskedFrame(2, true, "bad phrase in binary is ignored"),
		maskedFrame(9, true, "ping"),
	}, nil)

	for _, size := range []int{1, 3, 7, len(stream)} {
		upstream := &rw{}
		var reported int
		f := newOutFilter(upstream, &reported)
		if err := writeInChunks(f, stream, size); err != nil {
			t.Fatalf("chunk %d: %v", size, err)
		}
		if !bytes.Equal(upstream.Bytes(), stream) || reported != 0 {
			t.Fatalf("chunk %d: forwarded %d of %d bytes, reported=%d", size, upstream.Len(), len(stream), reported)
		}
	}
}

func TestWebSocketClientBlocksKeyword(t *testing.T) {
	upstream := &rw{}
	var reported int
	f := newOutFilter(upstream, &reported)

	clean := maskedFrame(1, true, "hello")
	if err := writeInChunks(f, clean, 4); err != nil {
		t.Fatal(err)
	}
	err := writeInChunks(f, maskedFrame(1, true, "say bad phrase now"), 5)
	if !errors.Is(err, errWebSocketBlocked) {
		t.Fatalf("err = %v, want blocked", err)
	}
	if !bytes.Equal(upstream.Bytes(), clean) {
		t.Fatal("blocked message leaked upstream")
	}
	if reported != 1 {
		t.Fatalf("reported %d times, want 1", reported)
	}
	if _, err := f.Write([]byte{0x81}); !errors.Is(err, errWebSocketBlocked) {
		t.Fatal("writes after a block must keep failing")
	}
}

func TestWebSocketClientBlocksFragmentedAndEscaped(t *testing.T) {
	upstream := &rw{}
	var reported int
	f := newOutFilter(upstream, &reported)

	stream := bytes.Join([][]byte{
		maskedFrame(1, false, `{"q":"bad`),
		maskedFrame(9, true, "ping"), // control frame interleaved
		maskedFrame(0, true, ` phrase"}`),
	}, nil)
	err := writeInChunks(f, stream, 6)
	if !errors.Is(err, errWebSocketBlocked) {
		t.Fatalf("err = %v, want blocked", err)
	}
	if bytes.Contains(upstream.Bytes(), maskedFrame(1, false, `{"q":"bad`)) {
		t.Fatal("fragment of a blocked message leaked upstream")
	}
}
