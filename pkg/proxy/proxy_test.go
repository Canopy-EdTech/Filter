package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
)

type fakeMatcher struct{ keyword string }

func (m fakeMatcher) KeywordMatch(_ *http.Response, data []byte) ([]int, bool) {
	if m.keyword == "" {
		return nil, false
	}
	i := bytes.Index(data, []byte(m.keyword))
	if i < 0 {
		return nil, false
	}
	return []int{i, i + len(m.keyword)}, true
}

// eofSeparateReader returns each chunk with a nil error and only reports
// io.EOF on a later zero-byte read, as chunked HTTP bodies commonly do.
type eofSeparateReader struct{ chunks [][]byte }

func (r *eofSeparateReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func (r *eofSeparateReader) Close() error { return nil }

func TestStreamingFilterPassesBodyThrough(t *testing.T) {
	long := strings.Repeat("x", 1000)
	tests := map[string][][]byte{
		"tiny body, EOF on separate read":   {[]byte("[[1,2,3]]")},
		"long body, EOF on separate read":   {[]byte(long)},
		"many chunks, EOF on separate read": {[]byte("abc"), []byte(long), []byte("end")},
	}
	for name, chunks := range tests {
		t.Run(name, func(t *testing.T) {
			want := string(bytes.Join(chunks, nil))
			f := &streamingFilter{reader: &eofSeparateReader{chunks: chunks}, engine: fakeMatcher{}}
			got, err := io.ReadAll(iotest.OneByteReader(f))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != want {
				t.Fatalf("body altered: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

func TestStreamingFilterBlocksAndReports(t *testing.T) {
	var reported []filter.BlockReason
	f := &streamingFilter{
		reader:  &eofSeparateReader{chunks: [][]byte{[]byte("hello bad phrase world")}},
		engine:  fakeMatcher{keyword: "bad phrase"},
		onBlock: func(r filter.BlockReason) { reported = append(reported, r) },
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello " {
		t.Fatalf("got %q, want body truncated at match", got)
	}
	if len(reported) != 1 {
		t.Fatalf("onBlock called %d times, want 1", len(reported))
	}
}

type fakeChecker struct{ keyword string }

func (c fakeChecker) CheckRequestBodyWithReason(_ *http.Request, body []byte) (filter.Decision, filter.BlockReason) {
	if c.keyword != "" && bytes.Contains(body, []byte(c.keyword)) {
		return filter.Block, filter.BlockReason{Reason: "blocked"}
	}
	return filter.Accept, filter.BlockReason{}
}

func newPost(contentType, body string) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://example.org/chat", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return req
}

func TestInspectRequestBody(t *testing.T) {
	checker := fakeChecker{keyword: "bad phrase"}
	tests := []struct {
		name        string
		contentType string
		body        string
		want        filter.Decision
	}{
		{"json match", "application/json", `{"q":"a bad phrase here"}`, filter.Block},
		{"json clean", "application/json", `{"q":"hello"}`, filter.Accept},
		{"form-encoded plus", "application/x-www-form-urlencoded", "q=a+bad+phrase", filter.Block},
		{"form-encoded %20", "application/x-www-form-urlencoded; charset=UTF-8", "q=a%20bad%20phrase", filter.Block},
		{"no content type", "", "bad phrase", filter.Block},
		{"binary skipped", "application/octet-stream", "bad phrase", filter.Accept},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newPost(tt.contentType, tt.body)
			got, _ := inspectRequestBody(req, checker)
			if got != tt.want {
				t.Fatalf("decision = %v, want %v", got, tt.want)
			}
			restored, err := io.ReadAll(req.Body)
			if err != nil || string(restored) != tt.body {
				t.Fatalf("body not restored: %q, %v", restored, err)
			}
		})
	}
}

func TestInspectRequestBodyTooLargeIsForwardedIntact(t *testing.T) {
	body := strings.Repeat("a", maxRequestBodyInspect+10) + "bad phrase"
	req := newPost("text/plain", body)
	if got, _ := inspectRequestBody(req, fakeChecker{keyword: "bad phrase"}); got != filter.Accept {
		t.Fatalf("oversized body should not be inspected, got %v", got)
	}
	restored, _ := io.ReadAll(req.Body)
	if len(restored) != len(body) {
		t.Fatalf("restored %d bytes, want %d", len(restored), len(body))
	}
}
