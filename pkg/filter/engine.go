package filter

import (
	"bytes"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	db *sql.DB

	mu    sync.RWMutex
	cache map[string]CompiledSlot
}

// RuleAction is the compiled, ready-to-return outcome for a single rule.
type RuleAction struct {
	Action      Decision
	Reason      string
	AdminReason string
}

// CompiledSlot is the cached, pre-compiled rule set for one group during one
// time slot (day-of-week + hour block). Postgres has already resolved which
// rules are in effect; nothing here is re-evaluated against the clock.
type CompiledSlot struct {
	Domains  map[string]RuleAction
	Keywords *regexp.Regexp
}

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

// DefaultGroupID is used when a request carries no group identity.
const DefaultGroupID = 1

const rulesQuery = `
SELECT r.type, r.pattern, r.action
FROM rules r
JOIN rule_groups rg ON rg.rule_id = r.id
JOIN rule_schedules rs ON rs.rule_id = r.id
WHERE rg.group_id = $1
  AND CURRENT_TIME BETWEEN rs.start_time AND rs.end_time
  AND (rs.days_mask & (1 << (EXTRACT(ISODOW FROM CURRENT_TIMESTAMP)::int - 1))) > 0
`

func NewEngine(db *sql.DB) *Engine {
	return &Engine{
		db:    db,
		cache: make(map[string]CompiledSlot),
	}
}

func (e *Engine) Decide(req *http.Request) Decision {
	decision, _ := e.DecideWithReason(req)
	return decision
}

// DecideWithReason performs the pre-flight domain check: it loads (or
// reuses) the compiled slot for the request's group and current time slot,
// and looks the host up in the cached domain map.
func (e *Engine) DecideWithReason(req *http.Request) (Decision, BlockReason) {
	host := extractCleanHost(req)
	groupID := resolveGroupID(req)

	slot, err := e.getSlot(groupID)
	if err != nil {
		return Inspect, BlockReason{}
	}

	if rule, ok := lookupDomain(slot.Domains, host); ok && rule.Action == Block {
		return Block, BlockReason{Reason: rule.Reason, AdminReason: rule.AdminReason}
	} else if ok && rule.Action == Accept {
		return Accept, BlockReason{}
	}

	return Inspect, BlockReason{}
}

// lookupDomain finds the domain rule for host, trying the host itself and then
// each parent domain, so a rule for example.com also covers www.example.com.
// The most specific rule wins, which lets an accept rule for a subdomain carve
// an exception out of a block rule on its parent (and vice versa). IP
// addresses only ever match exactly.
func lookupDomain(domains map[string]RuleAction, host string) (RuleAction, bool) {
	if rule, ok := domains[host]; ok {
		return rule, true
	}
	if net.ParseIP(host) != nil {
		return RuleAction{}, false
	}
	for rest := host; ; {
		_, parent, found := strings.Cut(rest, ".")
		if !found || parent == "" {
			return RuleAction{}, false
		}
		if rule, ok := domains[parent]; ok {
			return rule, true
		}
		rest = parent
	}
}

// normalizeDomainPattern lowercases a stored domain rule and strips the
// decorations admins commonly type: a leading "*." or ".", and a trailing dot.
func normalizeDomainPattern(pattern string) string {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimPrefix(pattern, "*.")
	return strings.Trim(pattern, ".")
}

// keywordAlternative quotes a keyword for use in the combined regex and adds
// \b word boundaries on the edges that are ASCII word characters. An edge
// that is punctuation (c++, #tag) or non-ASCII gets no boundary: \b next to a
// non-word character would demand a word character on the other side, which
// made such keywords match only in unnatural places like "c++x".
func keywordAlternative(keyword string) string {
	quoted := regexp.QuoteMeta(keyword)
	if isASCIIWordByte(keyword[0]) {
		quoted = `\b` + quoted
	}
	if isASCIIWordByte(keyword[len(keyword)-1]) {
		quoted += `\b`
	}
	return quoted
}

func isASCIIWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func (e *Engine) Check(req *http.Request) Decision {
	decision, _ := e.CheckWithReason(req)
	return decision
}

// CheckWithReason performs a lightweight, non-DB-backed path check. It is
// kept separate from the rule schema (which only covers domain/keyword
// rules) so the proxy's pre-flight pipeline keeps working unchanged.
func (e *Engine) CheckWithReason(req *http.Request) (Decision, BlockReason) {
	path := strings.ToLower(req.URL.Path)

	if strings.HasPrefix(path, "/blocked") {
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

// CheckResponseWithReason performs the post-flight keyword scan using the
// compiled regex matcher cached for the response's group and current time
// slot.
func (e *Engine) CheckResponseWithReason(resp *http.Response, body []byte) (Decision, BlockReason) {
	loc, ok := e.KeywordMatch(resp, body)
	if !ok {
		return Accept, BlockReason{}
	}

	return Block, KeywordBlockReason(body, loc)
}

// KeywordBlockReason builds the BlockReason for a keyword match at loc in
// data, as returned by KeywordMatch.
func KeywordBlockReason(data []byte, loc []int) BlockReason {
	return BlockReason{
		Reason:      "This page contains blocked content.",
		AdminReason: fmt.Sprintf("keyword rule matched: %q", bytes.ToLower(data[loc[0]:loc[1]])),
	}
}

// KeywordMatch scans data against the compiled keyword regex cached for the
// response's group and current time slot, returning the matched byte span
// (suitable for passing to regexp.Regexp.Find-style indexing) if any. It is
// also used by streaming/chunked response filters that need the match
// position rather than just a yes/no decision.
func (e *Engine) KeywordMatch(resp *http.Response, data []byte) (loc []int, found bool) {
	if resp == nil {
		return nil, false
	}
	return e.keywordMatch(resp.Request, data)
}

// KeywordMatchRequest is KeywordMatch for an outgoing request payload.
func (e *Engine) KeywordMatchRequest(req *http.Request, data []byte) (loc []int, found bool) {
	return e.keywordMatch(req, data)
}

func (e *Engine) keywordMatch(req *http.Request, data []byte) (loc []int, found bool) {
	slot, err := e.getSlot(resolveGroupID(req))
	if err != nil || slot.Keywords == nil {
		return nil, false
	}

	loc = slot.Keywords.FindIndex(data)
	return loc, loc != nil
}

// CheckRequestBodyWithReason scans an outgoing request payload for blocked
// keywords using the same compiled matcher as response bodies.
func (e *Engine) CheckRequestBodyWithReason(req *http.Request, body []byte) (Decision, BlockReason) {
	loc, ok := e.KeywordMatchRequest(req, body)
	if !ok {
		return Accept, BlockReason{}
	}

	return Block, BlockReason{
		Reason:      "This request contains blocked content.",
		AdminReason: fmt.Sprintf("keyword rule matched in request body: %q", bytes.ToLower(body[loc[0]:loc[1]])),
	}
}

func (e *Engine) IsBlocked(req *http.Request) bool {
	return e.Check(req) == Block
}

// getSlot returns the compiled slot for groupID at the current time slot,
// loading and caching it from Postgres on a miss.
func (e *Engine) getSlot(groupID int) (CompiledSlot, error) {
	key := cacheKey(groupID)

	e.mu.RLock()
	slot, ok := e.cache[key]
	e.mu.RUnlock()
	if ok {
		return slot, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Another goroutine may have populated this slot while we waited for
	// the write lock.
	if slot, ok := e.cache[key]; ok {
		return slot, nil
	}

	slot, err := e.loadSlot(groupID)
	if err != nil {
		return CompiledSlot{}, err
	}

	e.cache[key] = slot
	return slot, nil
}

// loadSlot runs the raw SQL join against Postgres, letting the database
// evaluate the time/day window statically, then compiles the resulting rows
// into a CompiledSlot: a domain lookup map plus one combined keyword regex.
func (e *Engine) loadSlot(groupID int) (CompiledSlot, error) {
	rows, err := e.db.Query(rulesQuery, groupID)
	if err != nil {
		return CompiledSlot{}, fmt.Errorf("query rules for group %d: %w", groupID, err)
	}
	defer rows.Close()

	domains := make(map[string]RuleAction)
	var keywordPatterns []string

	for rows.Next() {
		var ruleType, pattern, action string
		if err := rows.Scan(&ruleType, &pattern, &action); err != nil {
			return CompiledSlot{}, fmt.Errorf("scan rule row: %w", err)
		}

		decision := actionToDecision(action)

		switch ruleType {
		case "domain":
			domain := normalizeDomainPattern(pattern)
			if domain == "" {
				continue
			}
			domains[domain] = RuleAction{
				Action:      decision,
				Reason:      "This site is blocked.",
				AdminReason: fmt.Sprintf("domain rule matched: %s", pattern),
			}
		case "keyword":
			if decision == Block && pattern != "" {
				keywordPatterns = append(keywordPatterns, keywordAlternative(pattern))
			}
		}
	}
	if err := rows.Err(); err != nil {
		return CompiledSlot{}, fmt.Errorf("iterate rule rows: %w", err)
	}

	var keywords *regexp.Regexp
	if len(keywordPatterns) > 0 {
		pattern := `(?i)(` + strings.Join(keywordPatterns, "|") + `)`
		keywords, err = regexp.Compile(pattern)
		if err != nil {
			return CompiledSlot{}, fmt.Errorf("compile keyword regex: %w", err)
		}
	}

	return CompiledSlot{Domains: domains, Keywords: keywords}, nil
}

func actionToDecision(action string) Decision {
	switch strings.ToLower(action) {
	case "block":
		return Block
	case "accept":
		return Accept
	default:
		return Inspect
	}
}

// cacheKey combines the group with a time slot derived from the current
// day-of-week and hour block, matching the granularity Postgres evaluates
// rule_schedules at.
func cacheKey(groupID int) string {
	now := time.Now()
	return fmt.Sprintf("%d:%d-%d", groupID, int(now.Weekday()), now.Hour())
}

// resolveGroupID maps a request to its filtering group. There is no
// authentication layer yet, so callers may supply X-Group-ID; otherwise
// requests fall back to DefaultGroupID.
func resolveGroupID(req *http.Request) int {
	if req == nil {
		return DefaultGroupID
	}
	if v := req.Header.Get("X-Group-ID"); v != "" {
		if id, err := strconv.Atoi(v); err == nil {
			return id
		}
	}
	return DefaultGroupID
}

// Helper: Extracts host without port numbers or trailing dots
func extractCleanHost(req *http.Request) string {
	host := req.URL.Hostname()
	if host == "" {
		host = req.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
