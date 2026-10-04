package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Canopy-EdTech/Filter/internal/fakedb"
)

type ruleRow = fakedb.Rule

func rule(ruleType, pattern, action string) ruleRow {
	return ruleRow{Type: ruleType, Pattern: pattern, Action: action}
}

func newTestEngine(t *testing.T, rules map[int64][]ruleRow) (*Engine, *fakedb.DB) {
	t.Helper()
	db, fake := fakedb.New(t, rules)
	return NewEngine(db), fake
}

func get(url string) *http.Request { return httptest.NewRequest(http.MethodGet, url, nil) }

func responseFor(req *http.Request) *http.Response { return &http.Response{Request: req} }

var defaultRules = map[int64][]ruleRow{
	DefaultGroupID: {
		rule("domain", "Blocked.Example", "block"),
		rule("domain", "accepted.example", "accept"),
		rule("keyword", "bad phrase", "block"),
		rule("keyword", "c++", "block"),
		rule("keyword", "ignored keyword", "accept"),
		rule("domain", "odd.example", "something-else"),
	},
}

// --- domain rules ---

func TestDecideWithReasonDomainRules(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	tests := []struct {
		name string
		url  string
		want Decision
	}{
		{"blocked", "https://blocked.example/page", Block},
		{"blocked case-insensitive", "https://BLOCKED.EXAMPLE/", Block},
		{"blocked with port", "https://blocked.example:8443/", Block},
		{"blocked trailing dot", "https://blocked.example./", Block},
		{"accepted", "https://accepted.example/", Accept},
		{"unknown action falls through to inspect", "https://odd.example/", Inspect},
		{"unlisted domain", "https://other.example/", Inspect},
		{"subdomain of blocked", "https://www.blocked.example/", Block},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := e.DecideWithReason(get(tt.url))
			if got != tt.want {
				t.Fatalf("decision = %v, want %v", got, tt.want)
			}
			if got == Block && (reason.Reason == "" || !strings.Contains(reason.AdminReason, "domain rule matched")) {
				t.Fatalf("incomplete block reason: %+v", reason)
			}
		})
	}
}

func TestDecideWithReasonUsesHostWhenURLHasNoHost(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "blocked.example:80"
	req.URL.Host = ""
	if got, _ := e.DecideWithReason(req); got != Block {
		t.Fatalf("decision = %v, want Block", got)
	}
}

func TestDomainRulesCoverSubdomains(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {
		rule("domain", "blocked.example", "block"),
		rule("domain", "allowed.example", "accept"),
		// Exceptions: the most specific rule wins.
		rule("domain", "ok.blocked.example", "accept"),
		rule("domain", "bad.allowed.example", "block"),
		rule("domain", "10.0.0.1", "block"),
	}})
	tests := []struct {
		host string
		want Decision
	}{
		{"blocked.example", Block},
		{"www.blocked.example", Block},
		{"a.b.c.blocked.example", Block},
		{"WWW.Blocked.Example", Block},
		{"www.blocked.example.", Block},
		{"notblocked.example", Inspect},       // shares a suffix, but not a label boundary
		{"blocked.example.evil.com", Inspect}, // rule domain must be the suffix, not a prefix
		{"example", Inspect},
		{"ok.blocked.example", Accept}, // accept exception under a blocked parent
		{"deep.ok.blocked.example", Accept},
		{"allowed.example", Accept},
		{"www.allowed.example", Accept},
		{"bad.allowed.example", Block}, // block exception under an accepted parent
		{"x.bad.allowed.example", Block},
		{"10.0.0.1", Block},
		{"10.0.0.2", Inspect},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got, _ := e.DecideWithReason(get("https://" + tt.host + "/")); got != tt.want {
				t.Fatalf("decision = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainRulesDoNotSuffixMatchIPs(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {rule("domain", "0.1", "block")}})
	if got, _ := e.DecideWithReason(get("https://10.0.0.1/")); got != Inspect {
		t.Fatalf("IP address matched a domain-suffix rule: %v", got)
	}
}

func TestSubdomainBlockReasonNamesTheRule(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {rule("domain", "blocked.example", "block")}})
	_, reason := e.DecideWithReason(get("https://www.blocked.example/"))
	if !strings.Contains(reason.AdminReason, "blocked.example") || reason.Reason == "" {
		t.Fatalf("reason = %+v", reason)
	}
}

func TestDomainPatternsAreNormalized(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {
		rule("domain", "*.Wild.Example", "block"),
		rule("domain", ".dotted.example", "block"),
		rule("domain", "trailing.example.", "block"),
		rule("domain", "  spaced.example  ", "block"),
		rule("domain", "", "block"),
		rule("domain", "*.", "block"),
	}})
	for _, host := range []string{"wild.example", "x.wild.example", "dotted.example", "trailing.example", "spaced.example"} {
		if !blockedDomain(e, host, "") {
			t.Errorf("%s should be blocked", host)
		}
	}
	// Empty patterns must not turn into a rule that blocks everything.
	if blockedDomain(e, "unrelated.example", "") || blockedDomain(e, "localhost", "") {
		t.Error("empty domain pattern blocked unrelated hosts")
	}
}

func TestDecideInspectsWhenDatabaseFails(t *testing.T) {
	e, fake := newTestEngine(t, defaultRules)
	fake.SetError(errors.New("db down"))
	if got, _ := e.DecideWithReason(get("https://blocked.example/")); got != Inspect {
		t.Fatalf("decision = %v, want Inspect on DB error", got)
	}
	if _, found := e.KeywordMatchRequest(get("https://x.example/"), []byte("bad phrase")); found {
		t.Fatal("keyword matched despite DB error")
	}
}

// --- keyword rules ---

func TestKeywordMatch(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	req := get("https://x.example/")
	tests := []struct {
		name string
		body string
		want string // matched text, "" for no match
	}{
		{"match", "hello bad phrase world", "bad phrase"},
		{"case-insensitive", "hello BAD Phrase world", "BAD Phrase"},
		{"word boundary prefix", "xbad phrase", ""},
		{"word boundary suffix", "bad phrases", ""},
		{"accept-action keywords are not blocked", "ignored keyword", ""},
		{"clean", "nothing to see", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.body)
			loc, found := e.KeywordMatch(responseFor(req), data)
			if found != (tt.want != "") {
				t.Fatalf("found = %v, want match %q", found, tt.want)
			}
			if found && string(data[loc[0]:loc[1]]) != tt.want {
				t.Fatalf("matched %q, want %q", data[loc[0]:loc[1]], tt.want)
			}
		})
	}
}

func TestKeywordPatternsAreQuoted(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{
		DefaultGroupID: {rule("keyword", "a.b", "block"), rule("keyword", "(x", "block")},
	})
	req := get("https://x.example/")
	if _, found := e.KeywordMatchRequest(req, []byte("a.b")); !found {
		t.Fatal("literal pattern should match")
	}
	if _, found := e.KeywordMatchRequest(req, []byte("axb")); found {
		t.Fatal("'.' must not act as a regex wildcard")
	}
}

// Word boundaries apply only to edges that are ASCII word characters, so
// keywords that start or end with punctuation (c++, #tag, (x) match naturally.
func TestKeywordsWithPunctuationEdges(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{
		DefaultGroupID: {
			rule("keyword", "c++", "block"),
			rule("keyword", "#tag", "block"),
			rule("keyword", "(x)", "block"),
			rule("keyword", "caf\u00e9", "block"),
			rule("keyword", "_id_", "block"),
		},
	})
	req := get("https://x.example/")
	matches := func(body string) bool {
		_, found := e.KeywordMatchRequest(req, []byte(body))
		return found
	}

	for _, body := range []string{
		"learn c++ today", "c++", "I love C++.", "(c++)",
		"#tag here", "so #tag", "a#tag", // a leading-punctuation keyword matches anywhere
		"call (x) now", "(x)",
		"un caf\u00e9 noir", "caf\u00e9", "des caf\u00e9s",
		"the _id_ field",
	} {
		if !matches(body) {
			t.Errorf("%q should match", body)
		}
	}
	for _, body := range []string{
		"xc++", "abc++", // the word-character edge still needs a boundary
		"c+", "tag", "x",
	} {
		if matches(body) {
			t.Errorf("%q should not match", body)
		}
	}
}

func TestKeywordMatchSpan(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {rule("keyword", "c++", "block"), rule("keyword", "bad phrase", "block")}})
	req := get("https://x.example/")

	data := []byte("I like C++ and a Bad Phrase too")
	loc, found := e.KeywordMatchRequest(req, data)
	if !found || string(data[loc[0]:loc[1]]) != "C++" {
		t.Fatalf("span = %v, found %v", loc, found)
	}

	data = []byte("only a Bad Phrase here")
	loc, found = e.KeywordMatchRequest(req, data)
	if !found || string(data[loc[0]:loc[1]]) != "Bad Phrase" {
		t.Fatalf("span = %v, found %v", loc, found)
	}
}

func TestEmptyKeywordRuleDoesNotMatchEverything(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {rule("keyword", "", "block")}})
	if _, found := e.KeywordMatchRequest(get("https://x.example/"), []byte("anything at all")); found {
		t.Fatal("empty keyword rule matched ordinary text")
	}
}

func TestKeywordAlternative(t *testing.T) {
	for in, want := range map[string]string{
		"bad":       `\bbad\b`,
		"c++":       `\bc\+\+`,
		"#tag":      `#tag\b`,
		"(x)":       `\(x\)`,
		"a.b":       `\ba\.b\b`,
		"_x_":       `\b_x_\b`,
		"caf\u00e9": "\\bcaf\u00e9",
	} {
		if got := keywordAlternative(in); got != want {
			t.Errorf("keywordAlternative(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoKeywordRulesNeverMatch(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{DefaultGroupID: {rule("domain", "blocked.example", "block")}})
	if _, found := e.KeywordMatchRequest(get("https://x.example/"), []byte("anything")); found {
		t.Fatal("matched with no keyword rules")
	}
}

func TestKeywordMatchNilResponse(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	if _, found := e.KeywordMatch(nil, []byte("bad phrase")); found {
		t.Fatal("nil response must not match")
	}
	// A response with no Request falls back to the default group.
	if _, found := e.KeywordMatch(&http.Response{}, []byte("bad phrase")); !found {
		t.Fatal("nil Request should use the default group")
	}
}

func TestCheckResponseWithReason(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	resp := responseFor(get("https://x.example/"))

	decision, reason := e.CheckResponseWithReason(resp, []byte("this has a Bad Phrase in it"))
	if decision != Block || reason.Reason == "" || !strings.Contains(reason.AdminReason, `"bad phrase"`) {
		t.Fatalf("got %v %+v", decision, reason)
	}
	if decision, _ := e.CheckResponseWithReason(resp, []byte("clean")); decision != Accept {
		t.Fatalf("clean body decision = %v", decision)
	}
	if e.CheckResponse(resp, []byte("bad phrase")) != Block {
		t.Fatal("CheckResponse should block")
	}
}

func TestCheckRequestBodyWithReason(t *testing.T) {
	e, _ := newTestEngine(t, defaultRules)
	req := get("https://x.example/")

	decision, reason := e.CheckRequestBodyWithReason(req, []byte("send bad phrase"))
	if decision != Block || !strings.Contains(reason.AdminReason, "request body") {
		t.Fatalf("got %v %+v", decision, reason)
	}
	if decision, _ := e.CheckRequestBodyWithReason(req, []byte("hello")); decision != Accept {
		t.Fatalf("clean body decision = %v", decision)
	}
	if decision, _ := e.CheckRequestBodyWithReason(nil, []byte("bad phrase")); decision != Block {
		t.Fatal("nil request should use the default group")
	}
}

func TestKeywordBlockReason(t *testing.T) {
	data := []byte("xx Bad Phrase yy")
	reason := KeywordBlockReason(data, []int{3, 13})
	if reason.Reason == "" || !strings.Contains(reason.AdminReason, `"bad phrase"`) {
		t.Fatalf("got %+v", reason)
	}
}

// --- path rule ---

func TestCheckWithReasonPathRule(t *testing.T) {
	e, _ := newTestEngine(t, nil)
	if decision, reason := e.CheckWithReason(get("https://x.example/Blocked/thing")); decision != Block || reason.Reason == "" {
		t.Fatalf("got %v %+v", decision, reason)
	}
	if e.Check(get("https://x.example/fine")) != Accept {
		t.Fatal("unlisted path should be accepted")
	}
	if !e.IsBlocked(get("https://x.example/blocked")) {
		t.Fatal("IsBlocked should report the path rule")
	}
}

// --- groups and caching ---

func TestRulesAreScopedPerGroup(t *testing.T) {
	e, _ := newTestEngine(t, map[int64][]ruleRow{
		1: {rule("domain", "one.example", "block")},
		2: {rule("domain", "two.example", "block")},
	})
	for _, tt := range []struct {
		group, host string
		want        Decision
	}{
		{"", "one.example", Block},
		{"", "two.example", Inspect},
		{"2", "two.example", Block},
		{"2", "one.example", Inspect},
		{"not-a-number", "one.example", Block}, // invalid header falls back to default group
		{"99", "one.example", Inspect},         // unknown group has no rules
	} {
		req := get("https://" + tt.host + "/")
		if tt.group != "" {
			req.Header.Set("X-Group-ID", tt.group)
		}
		if got, _ := e.DecideWithReason(req); got != tt.want {
			t.Errorf("group %q host %s: decision = %v, want %v", tt.group, tt.host, got, tt.want)
		}
	}
}

func TestSlotsAreCachedPerGroup(t *testing.T) {
	e, fake := newTestEngine(t, defaultRules)
	for i := 0; i < 5; i++ {
		e.DecideWithReason(get("https://blocked.example/"))
		e.KeywordMatchRequest(get("https://x.example/"), []byte("bad phrase"))
	}
	if got := fake.Queries(); got != 1 {
		t.Fatalf("queries = %d, want 1 (cache hit after first load)", got)
	}

	other := get("https://blocked.example/")
	other.Header.Set("X-Group-ID", "2")
	e.DecideWithReason(other)
	if got := fake.Queries(); got != 2 {
		t.Fatalf("queries = %d, want 2 after a different group", got)
	}
}

func TestFailedLoadsAreNotCached(t *testing.T) {
	e, fake := newTestEngine(t, defaultRules)
	fake.SetError(errors.New("db down"))
	e.DecideWithReason(get("https://blocked.example/"))

	fake.SetError(nil)
	if got, _ := e.DecideWithReason(get("https://blocked.example/")); got != Block {
		t.Fatalf("decision = %v, want Block once the DB recovers", got)
	}
}

func TestConcurrentSlotLoadHitsDatabaseOnce(t *testing.T) {
	e, fake := newTestEngine(t, defaultRules)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.DecideWithReason(get("https://blocked.example/"))
		}()
	}
	wg.Wait()
	if got := fake.Queries(); got != 1 {
		t.Fatalf("queries = %d, want 1", got)
	}
}

func TestActionToDecision(t *testing.T) {
	for in, want := range map[string]Decision{
		"block": Block, "BLOCK": Block, "accept": Accept, "Accept": Accept, "": Inspect, "nope": Inspect,
	} {
		if got := actionToDecision(in); got != want {
			t.Errorf("actionToDecision(%q) = %v, want %v", in, got, want)
		}
	}
}
