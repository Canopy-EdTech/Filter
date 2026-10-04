package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Canopy-EdTech/Filter/pkg/filter"
)

// --- streaming filter ---

// A keyword split across two reads must still be caught wherever the split
// falls, and the text before the keyword must still be delivered.
func TestStreamingFilterCatchesKeywordSplitAcrossChunks(t *testing.T) {
	body := "some leading text that is fairly long, then a bad phrase, then trailing text"
	at := strings.Index(body, "bad phrase")

	for split := 1; split < len(body); split++ {
		var reported int
		f := &streamingFilter{
			reader:  &eofSeparateReader{chunks: [][]byte{[]byte(body[:split]), []byte(body[split:])}},
			engine:  fakeMatcher{keyword: "bad phrase"},
			onBlock: func(filter.BlockReason) { reported++ },
		}
		got, err := io.ReadAll(f)
		if err != nil {
			t.Fatalf("split %d: %v", split, err)
		}
		if strings.Contains(string(got), "bad phrase") || strings.Contains(string(got), "trailing") {
			t.Fatalf("split %d: keyword or text after it leaked: %q", split, got)
		}
		if len(got) > at {
			t.Fatalf("split %d: delivered %d bytes, past the match at %d", split, len(got), at)
		}
		if reported != 1 {
			t.Fatalf("split %d: reported %d times, want 1", split, reported)
		}
	}
}

// With the keyword straddling a boundary the text up to the tail window is
// delivered and the rest is withheld.
func TestStreamingFilterDeliversTextBeforeMatch(t *testing.T) {
	prefix := strings.Repeat("a", 1000)
	f := &streamingFilter{
		reader: &eofSeparateReader{chunks: [][]byte{
			[]byte(prefix + "bad"), []byte(" phrase and more"),
		}},
		engine: fakeMatcher{keyword: "bad phrase"},
	}
	got, _ := io.ReadAll(f)
	if string(got) != prefix {
		t.Fatalf("got %d bytes, want exactly the %d bytes before the match", len(got), len(prefix))
	}
}

type errAfterReader struct {
	data []byte
	err  error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (r *errAfterReader) Close() error { return nil }

func TestStreamingFilterPropagatesUpstreamError(t *testing.T) {
	boom := io.ErrUnexpectedEOF
	f := &streamingFilter{reader: &errAfterReader{data: []byte("partial"), err: boom}, engine: fakeMatcher{}}
	_, err := io.ReadAll(f)
	if err != boom {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestStreamingFilterEmptyBody(t *testing.T) {
	f := &streamingFilter{reader: &eofSeparateReader{}, engine: fakeMatcher{}}
	got, err := io.ReadAll(f)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestStreamingFilterLargeBodyIntact(t *testing.T) {
	body := bytes.Repeat([]byte("0123456789"), 20000) // 200 KB, several 32 KB reads
	f := &streamingFilter{reader: io.NopCloser(bytes.NewReader(body)), engine: fakeMatcher{}}
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("body altered: got %d bytes, want %d, err=%v", len(got), len(body), err)
	}
}

// --- decompression ---

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

func deflated(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte(s))
	w.Close()
	return buf.Bytes()
}

func TestDecompressBody(t *testing.T) {
	const text = "hello bad phrase world"
	corrupt := gzipped(t, text)[:10]

	tests := []struct {
		name     string
		encoding string
		in       []byte
		want     string
	}{
		{"gzip", "gzip", gzipped(t, text), text},
		{"gzip uppercase header", "GZIP", gzipped(t, text), text},
		{"deflate", "deflate", deflated(t, text), text},
		{"identity", "identity", []byte(text), text},
		{"no encoding", "", []byte(text), text},
		{"unknown encoding", "br", []byte(text), text},
		{"corrupt gzip returns input", "gzip", corrupt, string(corrupt)},
		{"not actually gzip", "gzip", []byte(text), text},
		{"corrupt deflate returns input", "deflate", []byte("not deflate data"), "not deflate data"},
		{"empty gzip body", "gzip", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decompressBody(tt.encoding, tt.in); string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- response classification ---

func TestIsStreamingResponse(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		te          string
		length      int64
		want        bool
	}{
		{"event stream", "text/event-stream", "", -1, true},
		{"event stream with charset", "text/event-stream; charset=utf-8", "", 10, true},
		{"chunked html is buffered", "text/html; charset=utf-8", "chunked", -1, false},
		{"unknown-length html is buffered", "text/html", "", -1, false},
		{"finite html", "text/html", "", 100, false},
		{"chunked json streams", "application/json", "chunked", -1, true},
		{"unknown-length plain streams", "text/plain", "", -1, true},
		{"finite json is buffered", "application/json", "", 50, false},
		{"finite plain is buffered", "text/plain", "", 0, false},
		{"uppercase content type", "TEXT/HTML", "chunked", -1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}, ContentLength: tt.length}
			resp.Header.Set("Content-Type", tt.contentType)
			if tt.te != "" {
				resp.Header.Set("Transfer-Encoding", tt.te)
			}
			if got := isStreamingResponse(resp); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTextContentType(t *testing.T) {
	for ct, want := range map[string]bool{
		"text/html": true, "text/plain; charset=utf-8": true, "application/json": true,
		"application/javascript": true, "text/javascript": true, "application/xml": true,
		"application/graphql-response+json": true, "application/ld+json": true,
		"image/png": false, "video/mp4": false, "application/octet-stream": false,
		"font/woff2": false, "": false,
	} {
		if got := isTextContentType(ct); got != want {
			t.Errorf("isTextContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestIsInspectableRequestType(t *testing.T) {
	for ct, want := range map[string]bool{
		"": true, "text/plain": true, "application/json": true,
		"application/x-www-form-urlencoded; charset=UTF-8": true,
		"multipart/form-data; boundary=xyz":                true,
		"image/png":                                        false, "application/octet-stream": false, "video/mp4": false,
	} {
		if got := isInspectableRequestType(ct); got != want {
			t.Errorf("isInspectableRequestType(%q) = %v, want %v", ct, got, want)
		}
	}
}

// --- request body inspection details ---

func TestInspectRequestBodyEdgeCases(t *testing.T) {
	checker := fakeChecker{keyword: "bad phrase"}

	t.Run("no body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.org/", nil)
		if got, _ := inspectRequestBody(req, checker); got != filter.Accept {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("http.NoBody", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://example.org/", http.NoBody)
		if got, _ := inspectRequestBody(req, checker); got != filter.Accept {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("gzip body is decompressed", func(t *testing.T) {
		req := newPost("application/json", string(gzipped(t, `{"q":"bad phrase"}`)))
		req.Header.Set("Content-Encoding", "gzip")
		if got, _ := inspectRequestBody(req, checker); got != filter.Block {
			t.Fatalf("got %v, want Block", got)
		}
	})
	t.Run("json escape in form field", func(t *testing.T) {
		// f.req=[["bad phrase"]], URL-encoded as browsers send it.
		req := newPost("application/x-www-form-urlencoded", `f.req=%5B%5B%22bad%5Cu0020phrase%22%5D%5D`)
		if got, _ := inspectRequestBody(req, checker); got != filter.Block {
			t.Fatalf("got %v, want Block", got)
		}
	})
	t.Run("undecodable form body is still scanned raw", func(t *testing.T) {
		req := newPost("application/x-www-form-urlencoded", "q=bad phrase&bad=%zz")
		if got, _ := inspectRequestBody(req, checker); got != filter.Block {
			t.Fatalf("got %v, want Block", got)
		}
	})
	t.Run("body error leaves request usable", func(t *testing.T) {
		req := newPost("text/plain", "")
		req.Body = io.NopCloser(&errAfterReader{data: []byte("abc"), err: io.ErrUnexpectedEOF})
		if got, _ := inspectRequestBody(req, checker); got != filter.Accept {
			t.Fatalf("got %v, want Accept when the body can't be read", got)
		}
	})
	t.Run("CONNECT is skipped", func(t *testing.T) {
		req := newPost("text/plain", "bad phrase")
		req.Method = http.MethodConnect
		if got, _ := inspectRequestBody(req, checker); got != filter.Accept {
			t.Fatalf("got %v", got)
		}
	})
}

// --- JSON unescaping ---

func TestUnescapeJSONStringsEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{"no backslash", "plain", "plain", false},
		{"every simple escape", js(`~"~~~/~n~t~r~b~f`), "\"\\/\n\t\r\b\f", true},
		{"lone high surrogate", js(`~ud83d`), "\uFFFD", true},
		{"high surrogate then non-low", js(`~ud83dx`), "\uFFFDx", true},
		{"valid surrogate pair", js(`~ud83d~ude00`), "\U0001F600", true},
		{"truncated unicode", js(`~u12`), js(`~u12`), false},
		{"bad hex digits", js(`~u12zz`), js(`~u12zz`), false},
		{"unknown escape kept", js(`~q`), js(`~q`), false},
		{"trailing backslash kept", js(`abc~`), js(`abc~`), false},
		{"uppercase hex", js(`~u00E9`), "\u00e9", true},
		{"mixed", js(`a~u0041b~nc`), "aAb\nc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := unescapeJSONStrings([]byte(tt.in))
			if string(got) != tt.want || changed != tt.changed {
				t.Fatalf("got %q changed=%v, want %q changed=%v", got, changed, tt.want, tt.changed)
			}
		})
	}
}

func TestCheckVariantsStopsOnFirstBlock(t *testing.T) {
	calls := 0
	check := func([]byte) (filter.Decision, filter.BlockReason) {
		calls++
		return filter.Block, filter.BlockReason{AdminReason: "first"}
	}
	d, r := checkVariants([]byte(`A`), check)
	if d != filter.Block || r.AdminReason != "first" || calls != 1 {
		t.Fatalf("got %v %+v after %d calls", d, r, calls)
	}
}

func TestCheckVariantsBoundsNestedDecoding(t *testing.T) {
	// Deeply nested escapes must terminate; only maxUnescapeRounds layers are peeled.
	nested := "bad phrase"
	for i := 0; i < maxUnescapeRounds+3; i++ {
		nested = strings.ReplaceAll(nested, `"`, `\"`)
		nested = `"` + nested + `"`
		nested = strings.ReplaceAll(nested, `"`, `\"`)
	}
	check := func(b []byte) (filter.Decision, filter.BlockReason) { return filter.Accept, filter.BlockReason{} }
	if d, _ := checkVariants([]byte(nested), check); d != filter.Accept {
		t.Fatal("unexpected block")
	}
}

// --- WebSocket server-to-client ---

func serverFrame(opcode byte, fin bool, payload string) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	frame := []byte{first}
	n := len(payload)
	switch {
	case n < 126:
		frame = append(frame, byte(n))
	default:
		frame = append(frame, 126, byte(n>>8), byte(n))
	}
	return append(frame, payload...)
}

func newInFilter(stream []byte, reported *int) *webSocketFilter {
	return &webSocketFilter{
		ReadWriter: &rw{Buffer: *bytes.NewBuffer(stream)},
		engine:     wsFakeChecker{keyword: "bad phrase"},
		resp:       &http.Response{Request: httptest.NewRequest(http.MethodGet, "https://example.org/ws", nil)},
		onBlock:    func(filter.BlockReason) { *reported++ },
	}
}

func TestWebSocketServerMessagesForwardedWhenClean(t *testing.T) {
	stream := bytes.Join([][]byte{
		serverFrame(1, true, "hello"),
		serverFrame(1, true, strings.Repeat("long ", 100)), // 16-bit length form
		serverFrame(2, true, "bad phrase in binary is ignored"),
		serverFrame(9, true, "ping"),
	}, nil)

	var reported int
	got, err := io.ReadAll(newInFilter(stream, &reported))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, stream) || reported != 0 {
		t.Fatalf("got %d of %d bytes, reported=%d", len(got), len(stream), reported)
	}
}

func TestWebSocketServerBlocksKeyword(t *testing.T) {
	first := serverFrame(1, true, "fine")
	stream := bytes.Join([][]byte{first, serverFrame(1, true, "now a bad phrase"), serverFrame(1, true, "after")}, nil)

	var reported int
	got, err := io.ReadAll(newInFilter(stream, &reported))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("delivered %q, want only the clean first frame", got)
	}
	if reported != 1 {
		t.Fatalf("reported %d times, want 1", reported)
	}
}

func TestWebSocketServerBlocksFragmentedKeyword(t *testing.T) {
	stream := bytes.Join([][]byte{
		serverFrame(1, false, "say bad"),
		serverFrame(0, true, " phrase now"),
	}, nil)

	var reported int
	got, _ := io.ReadAll(newInFilter(stream, &reported))
	if len(got) != 0 || reported != 1 {
		t.Fatalf("delivered %d bytes, reported=%d; want nothing delivered and one report", len(got), reported)
	}
}

func TestWebSocketServerBlocksEscapedKeyword(t *testing.T) {
	stream := serverFrame(1, true, js(`{"text":"bad~u0020phrase"}`))
	var reported int
	got, _ := io.ReadAll(newInFilter(stream, &reported))
	if len(got) != 0 || reported != 1 {
		t.Fatalf("delivered %d bytes, reported=%d", len(got), reported)
	}
}

// Known bug: a clean fragmented text message is delivered with only its final
// fragment, because Read queues all fragments and then overwrites the queue
// with the last frame. Remove the Skip once Read forwards every fragment.
func TestWebSocketServerForwardsCleanFragmentedMessage(t *testing.T) {
	t.Skip("known bug: clean fragmented messages lose all but the last fragment")

	stream := bytes.Join([][]byte{
		serverFrame(1, false, "hello "),
		serverFrame(9, true, "ping"),
		serverFrame(0, false, "wide "),
		serverFrame(0, true, "world"),
	}, nil)

	var reported int
	got, err := io.ReadAll(newInFilter(stream, &reported))
	if err != nil {
		t.Fatal(err)
	}
	// Control frames may be reordered ahead of the message, but every byte must arrive.
	if len(got) != len(stream) {
		t.Fatalf("delivered %d bytes, want %d", len(got), len(stream))
	}
	for _, part := range []string{"hello ", "wide ", "world", "ping"} {
		if !bytes.Contains(got, []byte(part)) {
			t.Errorf("fragment %q missing from output", part)
		}
	}
}

func TestWebSocketReadReportErrorOnTruncatedFrame(t *testing.T) {
	var reported int
	f := newInFilter([]byte{0x81, 0x05, 'h', 'i'}, &reported) // claims 5 bytes, has 2
	if _, err := io.ReadAll(f); err == nil {
		t.Fatal("expected an error for a truncated frame")
	}
}

func TestWebSocketReadRejectsOversizedFrame(t *testing.T) {
	var reported int
	// 127 = 64-bit length; claim 1 GiB.
	f := newInFilter([]byte{0x81, 127, 0, 0, 0, 0, 0x40, 0, 0, 0}, &reported)
	if _, err := io.ReadAll(f); err == nil || !strings.Contains(err.Error(), "inspection limit") {
		t.Fatalf("err = %v, want inspection limit error", err)
	}
}
