package filter

import (
	"database/sql"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Rules are loaded from Postgres together with their schedules and cached per
// group. The schedule is evaluated in Go against a clock in a configured
// timezone, so a rule switches on and off at its exact start and end time
// rather than at the granularity the cache was loaded at. The compiled
// matchers are rebuilt from the cached rules only when a schedule boundary
// passes, and the rules themselves are re-read from the database every
// refresh interval so edits show up without a restart.

const (
	// DefaultRefreshInterval is how long loaded rules are used before being
	// re-read from the database.
	DefaultRefreshInterval = 30 * time.Second

	// maxRetryDelay bounds how soon a failed refresh is retried, so a database
	// outage is not hit by every request.
	maxRetryDelay = 5 * time.Second

	// maxSlotLifetime caps how long a compiled slot is reused, as a safety net
	// against clock or daylight-saving jumps.
	maxSlotLifetime = time.Hour
)

const rulesQuery = `
SELECT r.id, r.type, r.pattern, r.action,
       EXTRACT(EPOCH FROM rs.start_time)::float8,
       EXTRACT(EPOCH FROM rs.end_time)::float8,
       rs.days_mask
FROM rules r
JOIN rule_groups rg ON rg.rule_id = r.id
JOIN rule_schedules rs ON rs.rule_id = r.id
WHERE rg.group_id = $1
ORDER BY r.id
`

// Option configures an Engine.
type Option func(*Engine)

// WithLocation sets the timezone rule schedules are evaluated in. Schedule
// times are stored without a zone, so this decides what "09:00" means.
func WithLocation(loc *time.Location) Option {
	return func(e *Engine) {
		if loc != nil {
			e.loc = loc
		}
	}
}

// WithRefreshInterval sets how often a group's rules are re-read from the
// database. Zero or negative values keep the default.
func WithRefreshInterval(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.refresh = d
		}
	}
}

// WithClock replaces the time source; used by tests.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// WithLogger reports rule refresh failures.
func WithLogger(logger *slog.Logger) Option {
	return func(e *Engine) { e.logger = logger }
}

type Engine struct {
	db      *sql.DB
	loc     *time.Location
	refresh time.Duration
	now     func() time.Time
	logger  *slog.Logger

	mu     sync.RWMutex
	groups map[int]*groupState
}

func NewEngine(db *sql.DB, opts ...Option) *Engine {
	e := &Engine{
		db:      db,
		loc:     time.Local,
		refresh: DefaultRefreshInterval,
		now:     time.Now,
		groups:  make(map[int]*groupState),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// window is one schedule row: active on the days in daysMask (bit 0 =
// Monday ... bit 6 = Sunday) from start to end of day, both inclusive.
//
// A window whose start is after its end crosses midnight, e.g. 22:00-06:00.
// Its daysMask names the day the window starts, so Monday 22:00-06:00 runs
// from Monday 22:00 until Tuesday 06:00.
type window struct {
	start, end time.Duration
	daysMask   int
}

func (w window) overnight() bool { return w.start > w.end }

func (w window) activeAt(t time.Time) bool {
	tod := timeOfDay(t)
	today := w.daysMask&weekdayBit(t.Weekday()) != 0
	if !w.overnight() {
		return today && tod >= w.start && tod <= w.end
	}
	// The evening part belongs to today's window, the early-morning part to
	// the window that started yesterday.
	yesterday := w.daysMask&weekdayBit((t.Weekday()+6)%7) != 0
	return (today && tod >= w.start) || (yesterday && tod <= w.end)
}

func weekdayBit(d time.Weekday) int { return 1 << ((int(d) + 6) % 7) }

func timeOfDay(t time.Time) time.Duration {
	return time.Duration(t.Hour())*time.Hour +
		time.Duration(t.Minute())*time.Minute +
		time.Duration(t.Second())*time.Second +
		time.Duration(t.Nanosecond())
}

// atWallClock returns the instant at the given time of day on day's date,
// using wall-clock fields so daylight-saving days are handled correctly.
func atWallClock(day time.Time, d time.Duration) time.Time {
	return time.Date(day.Year(), day.Month(), day.Day(),
		int(d/time.Hour), int(d%time.Hour/time.Minute), int(d%time.Minute/time.Second), int(d%time.Second), day.Location())
}

type scheduledRule struct {
	ruleType, pattern, action string
	windows                   []window
}

func (r *scheduledRule) activeAt(t time.Time) bool {
	for _, w := range r.windows {
		if w.activeAt(t) {
			return true
		}
	}
	return false
}

type ruleSet struct {
	rules   []*scheduledRule
	expires time.Time // when to re-read from the database
}

// groupState is the cached state for one group.
type groupState struct {
	reloadMu sync.Mutex // held while talking to the database

	mu         sync.RWMutex
	rules      *ruleSet // nil until the first successful load
	slot       CompiledSlot
	compiledAt time.Time
	validUntil time.Time
	retryAt    time.Time // earliest next attempt after a failed refresh
}

func (e *Engine) group(id int) *groupState {
	e.mu.RLock()
	g, ok := e.groups[id]
	e.mu.RUnlock()
	if ok {
		return g
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if g, ok := e.groups[id]; ok {
		return g
	}
	g = &groupState{}
	e.groups[id] = g
	return g
}

// getSlot returns the compiled rules in effect for groupID right now.
func (e *Engine) getSlot(groupID int) (CompiledSlot, error) {
	g := e.group(groupID)
	now := e.now().In(e.loc)

	if err := e.ensureLoaded(g, groupID, now); err != nil {
		return CompiledSlot{}, err
	}

	g.mu.RLock()
	slot, usable := g.slot, !now.Before(g.compiledAt) && now.Before(g.validUntil)
	g.mu.RUnlock()
	if usable {
		return slot, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if !now.Before(g.compiledAt) && now.Before(g.validUntil) {
		return g.slot, nil // another goroutine recompiled while we waited
	}
	slot, validUntil, err := compile(g.rules.rules, now)
	if err != nil {
		return CompiledSlot{}, err
	}
	g.slot, g.compiledAt, g.validUntil = slot, now, validUntil
	return slot, nil
}

// ensureLoaded makes sure the group has rules, refreshing them when they are
// older than the refresh interval. A failed refresh keeps the previous rules
// in force and is retried shortly; only a failed first load is an error.
func (e *Engine) ensureLoaded(g *groupState, groupID int, now time.Time) error {
	g.mu.RLock()
	rs, retryAt := g.rules, g.retryAt
	g.mu.RUnlock()

	switch {
	case rs == nil:
		// First load: every caller needs the result, so they queue up.
		g.reloadMu.Lock()
		defer g.reloadMu.Unlock()
		g.mu.RLock()
		loaded := g.rules != nil
		g.mu.RUnlock()
		if loaded {
			return nil
		}
		return e.reload(g, groupID, now)

	case now.After(rs.expires) && !now.Before(retryAt):
		// Stale: one caller refreshes while the rest keep using current rules.
		if !g.reloadMu.TryLock() {
			return nil
		}
		defer g.reloadMu.Unlock()
		_ = e.reload(g, groupID, now)
	}
	return nil
}

func (e *Engine) reload(g *groupState, groupID int, now time.Time) error {
	rules, err := e.loadRules(groupID)

	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		g.retryAt = now.Add(min(maxRetryDelay, e.refresh))
		if e.logger != nil {
			e.logger.Warn("Failed to load filter rules", "group", groupID, "error", err, "keeping_previous_rules", g.rules != nil)
		}
		return err
	}
	g.rules = &ruleSet{rules: rules, expires: now.Add(e.refresh)}
	g.validUntil = time.Time{} // force a recompile against the new rules
	g.retryAt = time.Time{}
	return nil
}

// loadRules reads a group's rules and their schedules from the database.
func (e *Engine) loadRules(groupID int) ([]*scheduledRule, error) {
	rows, err := e.db.Query(rulesQuery, groupID)
	if err != nil {
		return nil, fmt.Errorf("query rules for group %d: %w", groupID, err)
	}
	defer rows.Close()

	var ordered []*scheduledRule
	byID := make(map[int64]*scheduledRule)
	for rows.Next() {
		var (
			id                        int64
			ruleType, pattern, action string
			startSecs, endSecs        float64
			daysMask                  int
		)
		if err := rows.Scan(&id, &ruleType, &pattern, &action, &startSecs, &endSecs, &daysMask); err != nil {
			return nil, fmt.Errorf("scan rule row: %w", err)
		}

		r, ok := byID[id]
		if !ok {
			r = &scheduledRule{ruleType: ruleType, pattern: pattern, action: action}
			byID[id] = r
			ordered = append(ordered, r)
		}
		r.windows = append(r.windows, window{
			start:    secondsToDuration(startSecs),
			end:      secondsToDuration(endSecs),
			daysMask: daysMask,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rule rows: %w", err)
	}
	return ordered, nil
}

// secondsToDuration converts the database's seconds-since-midnight to a
// Duration, rounded to the microsecond precision of the TIME type.
func secondsToDuration(secs float64) time.Duration {
	return time.Duration(math.Round(secs*1e6)) * time.Microsecond
}

// compile builds the domain map and keyword regex from the rules in effect at
// t, and reports until when that result stays correct.
func compile(rules []*scheduledRule, t time.Time) (CompiledSlot, time.Time, error) {
	domains := make(map[string]RuleAction)
	var keywordPatterns []string

	for _, r := range rules {
		if !r.activeAt(t) {
			continue
		}
		decision := actionToDecision(r.action)

		switch r.ruleType {
		case "domain":
			domain := normalizeDomainPattern(r.pattern)
			if domain == "" {
				continue
			}
			// If rules disagree about a domain, blocking wins over accepting.
			if existing, ok := domains[domain]; ok && priority(existing.Action) > priority(decision) {
				continue
			}
			domains[domain] = RuleAction{
				Action:      decision,
				Reason:      "This site is blocked.",
				AdminReason: fmt.Sprintf("domain rule matched: %s", r.pattern),
			}
		case "keyword":
			if decision == Block && r.pattern != "" {
				keywordPatterns = append(keywordPatterns, keywordAlternative(r.pattern))
			}
		}
	}

	var keywords *regexp.Regexp
	if len(keywordPatterns) > 0 {
		var err error
		keywords, err = regexp.Compile(`(?i)(` + strings.Join(keywordPatterns, "|") + `)`)
		if err != nil {
			return CompiledSlot{}, time.Time{}, fmt.Errorf("compile keyword regex: %w", err)
		}
	}
	return CompiledSlot{Domains: domains, Keywords: keywords}, nextTransition(rules, t), nil
}

func priority(d Decision) int {
	switch d {
	case Block:
		return 2
	case Accept:
		return 1
	default:
		return 0
	}
}

// nextTransition returns the earliest moment after t at which any rule's
// schedule switches on or off, capped at maxSlotLifetime. Extra candidates are
// harmless: they only cause an early recompile.
func nextTransition(rules []*scheduledRule, t time.Time) time.Time {
	next := t.Add(maxSlotLifetime)
	for _, r := range rules {
		for _, w := range r.windows {
			// Start from yesterday: an overnight window that began then ends today.
			for offset := -1; offset <= 8; offset++ {
				day := time.Date(t.Year(), t.Month(), t.Day()+offset, 0, 0, 0, 0, t.Location())
				if w.daysMask&weekdayBit(day.Weekday()) == 0 {
					continue
				}
				endDay := day
				if w.overnight() {
					endDay = time.Date(day.Year(), day.Month(), day.Day()+1, 0, 0, 0, 0, day.Location())
				}
				// The window is inclusive, so it ends just after w.end.
				for _, boundary := range []time.Time{atWallClock(day, w.start), atWallClock(endDay, w.end+time.Microsecond)} {
					if boundary.After(t) && boundary.Before(next) {
						next = boundary
					}
				}
			}
		}
	}
	return next
}
