package filter

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/Canopy-EdTech/Filter/internal/fakedb"
)

// A fake clock lets these tests move through days and hours without sleeping.

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const (
	mon = 1 << iota
	tue
	wed
	thu
	fri
	sat
	sun
	weekdays = mon | tue | wed | thu | fri
	allDays  = weekdays | sat | sun
)

// monday returns 2026-10-05 (a Monday) at the given clock time in UTC.
func monday(hms string) time.Time { return at(5, hms) }

// at returns the given day of October 2026 (the 5th is a Monday) at hms UTC.
func at(day int, hms string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05.999999", "2026-10-"+pad(day)+" "+hms)
	if err != nil {
		panic(err)
	}
	return t
}

func pad(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func newScheduledEngine(t *testing.T, start time.Time, rules map[int64][]fakedb.Rule, opts ...Option) (*Engine, *fakedb.DB, *fakeClock) {
	t.Helper()
	if start.Weekday() != time.Monday && start.Day() == 5 {
		t.Fatal("test calendar is wrong: 2026-10-05 should be a Monday")
	}
	db, fake := fakedb.New(t, rules)
	clock := &fakeClock{t: start}
	base := []Option{WithClock(clock.Now), WithLocation(time.UTC), WithRefreshInterval(24 * time.Hour)}
	return NewEngine(db, append(base, opts...)...), fake, clock
}

func during(start, end string, days int) []fakedb.Schedule {
	return []fakedb.Schedule{{Start: start, End: end, DaysMask: days}}
}

func domainRule(pattern, action string, schedules []fakedb.Schedule) fakedb.Rule {
	return fakedb.Rule{Type: "domain", Pattern: pattern, Action: action, Schedules: schedules}
}

func keywordRule(pattern string, schedules []fakedb.Schedule) fakedb.Rule {
	return fakedb.Rule{Type: "keyword", Pattern: pattern, Action: "block", Schedules: schedules}
}

func isBlocked(e *Engine, host string) bool { return blockedDomain(e, host, "") }

func keywordMatches(e *Engine, body string) bool {
	_, found := e.KeywordMatchRequest(get("https://x.example/"), []byte(body))
	return found
}

// --- schedule evaluation ---

func TestWindowBoundariesAreInclusiveAndExact(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("09:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("window.example", "block", during("09:30", "10:30", mon))},
	})

	steps := []struct {
		at   time.Time
		want bool
	}{
		{monday("09:00:00"), false},
		{monday("09:29:59"), false},
		{monday("09:29:59.999999"), false},
		{monday("09:30:00"), true}, // start is inclusive, to the second
		{monday("10:00:00"), true},
		{monday("10:30:00"), true}, // end is inclusive
		{monday("10:30:00.000001"), false},
		{monday("10:30:01"), false},
		{monday("23:59:59"), false},
	}
	for _, step := range steps {
		clock.Set(step.at)
		if got := isBlocked(e, "window.example"); got != step.want {
			t.Errorf("at %s: blocked = %v, want %v", step.at.Format("15:04:05.000000"), got, step.want)
		}
	}
	if q := fake.Queries(); q != 1 {
		t.Errorf("queries = %d; schedule changes must not need the database", q)
	}
}

// Regression: slots used to be cached for a whole hour, so a window that began
// mid-hour was missed if the slot happened to load before it started.
func TestWindowStartingMidHourIsPickedUpWithoutReload(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("09:05:00"), map[int64][]fakedb.Rule{
		1: {
			domainRule("late.example", "block", during("09:30", "10:30", allDays)),
			keywordRule("secret", during("09:30", "09:45", allDays)),
		},
	})

	if isBlocked(e, "late.example") || keywordMatches(e, "a secret") {
		t.Fatal("rules active before their start time")
	}
	clock.Set(monday("09:31:00"))
	if !isBlocked(e, "late.example") || !keywordMatches(e, "a secret") {
		t.Fatal("rules not active after their start time, within the same hour")
	}
	clock.Set(monday("09:50:00"))
	if !isBlocked(e, "late.example") || keywordMatches(e, "a secret") {
		t.Fatal("keyword window should have closed at 09:45 while the domain window is still open")
	}
	clock.Set(monday("10:31:00"))
	if isBlocked(e, "late.example") {
		t.Fatal("rule still active after its end")
	}
	if q := fake.Queries(); q != 1 {
		t.Fatalf("queries = %d, want 1", q)
	}
}

func TestEachWeekdayUsesItsOwnBit(t *testing.T) {
	names := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	var rules []fakedb.Rule
	for i, name := range names {
		rules = append(rules, domainRule(name+".example", "block", during("00:00", "23:59:59", 1<<i)))
	}
	e, _, clock := newScheduledEngine(t, at(5, "12:00:00"), map[int64][]fakedb.Rule{1: rules})

	for i, active := range names { // Oct 5 is Monday ... Oct 11 is Sunday
		clock.Set(at(5+i, "12:00:00"))
		for _, name := range names {
			if got, want := isBlocked(e, name+".example"), name == active; got != want {
				t.Errorf("on %s: %s.example blocked = %v, want %v", active, name, got, want)
			}
		}
	}
}

func TestMidnightRollsOverToTheNextDay(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("23:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("monday.example", "block", during("00:00", "23:59:59.999999", mon))},
	}, WithRefreshInterval(30*24*time.Hour))
	if !isBlocked(e, "monday.example") {
		t.Fatal("should be active on Monday evening")
	}
	clock.Set(at(6, "00:00:00"))
	if isBlocked(e, "monday.example") {
		t.Fatal("Monday-only rule still active at Tuesday 00:00")
	}
	clock.Set(at(12, "00:00:00")) // the following Monday
	if !isBlocked(e, "monday.example") {
		t.Fatal("Monday-only rule not active again a week later")
	}
	if q := fake.Queries(); q != 1 {
		t.Fatalf("queries = %d, want 1", q)
	}
}

func TestKeywordWindowTogglesWithoutReload(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("08:00:00"), map[int64][]fakedb.Rule{
		1: {keywordRule("exam answers", during("09:00", "10:00", mon))},
	}, WithRefreshInterval(30*24*time.Hour))
	for _, step := range []struct {
		at   time.Time
		want bool
	}{
		{monday("08:00:00"), false},
		{monday("09:30:00"), true},
		{monday("10:30:00"), false},
		{at(6, "09:30:00"), false}, // Tuesday: not in the day mask
		{at(12, "09:30:00"), true}, // next Monday
	} {
		clock.Set(step.at)
		if got := keywordMatches(e, "get the exam answers here"); got != step.want {
			t.Errorf("at %s: matched = %v, want %v", step.at.Format("Mon 15:04"), got, step.want)
		}
	}
	if q := fake.Queries(); q != 1 {
		t.Fatalf("queries = %d, want 1", q)
	}
}

func TestMultipleSchedulesAreAUnion(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("08:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("split.example", "block", []fakedb.Schedule{
			{Start: "09:00", End: "10:00", DaysMask: mon},
			{Start: "13:00", End: "14:00", DaysMask: mon | tue},
		})},
	})
	for at, want := range map[string]bool{
		"08:59:59": false, "09:30:00": true, "11:00:00": false, "13:30:00": true, "14:00:01": false,
	} {
		clock.Set(monday(at))
		if got := isBlocked(e, "split.example"); got != want {
			t.Errorf("Monday %s: blocked = %v, want %v", at, got, want)
		}
	}
	clock.Set(at(6, "13:30:00"))
	if !isBlocked(e, "split.example") {
		t.Error("second window should also apply on Tuesday")
	}
	clock.Set(at(6, "09:30:00"))
	if isBlocked(e, "split.example") {
		t.Error("first window is Monday only")
	}
}

func TestRulesWithoutSchedulesNeverApply(t *testing.T) {
	e, _, _ := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {
			domainRule("unscheduled.example", "block", []fakedb.Schedule{}),
			keywordRule("unscheduled", []fakedb.Schedule{}),
		},
	})
	if isBlocked(e, "unscheduled.example") || keywordMatches(e, "unscheduled") {
		t.Fatal("a rule with no schedule rows must never be active")
	}
}

// --- overnight windows (start after end) ---

func TestOvernightWindowSpansMidnight(t *testing.T) {
	// Monday 22:00 until Tuesday 06:00.
	e, fake, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("night.example", "block", during("22:00", "06:00", mon))},
	}, WithRefreshInterval(30*24*time.Hour))

	for _, step := range []struct {
		at   time.Time
		want bool
	}{
		{monday("00:00:00"), false}, // Monday early morning belongs to Sunday's window
		{monday("05:00:00"), false},
		{monday("12:00:00"), false},
		{monday("21:59:59"), false},
		{monday("22:00:00"), true}, // start is inclusive
		{monday("23:59:59"), true},
		{at(6, "00:00:00"), true}, // Tuesday: still Monday's window
		{at(6, "03:00:00"), true},
		{at(6, "06:00:00"), true}, // end is inclusive
		{at(6, "06:00:00.000001"), false},
		{at(6, "12:00:00"), false},
		{at(6, "22:30:00"), false}, // Tuesday evening: the mask is Monday only
		{at(7, "03:00:00"), false},
		{at(12, "23:00:00"), true}, // the following Monday evening
		{at(13, "05:59:59"), true},
	} {
		clock.Set(step.at)
		if got := isBlocked(e, "night.example"); got != step.want {
			t.Errorf("at %s: blocked = %v, want %v", step.at.Format("Mon 15:04:05.000000"), got, step.want)
		}
	}
	if q := fake.Queries(); q != 1 {
		t.Errorf("queries = %d; crossing midnight must not need the database", q)
	}
}

func TestOvernightWindowUsesTheStartDayForEveryWeekday(t *testing.T) {
	// For each weekday i, an overnight rule on that day alone is active from
	// i 22:00 to i+1 06:00. Sunday's window ends on Monday, wrapping the week.
	names := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	var rules []fakedb.Rule
	for i, name := range names {
		rules = append(rules, domainRule(name+".example", "block", during("22:00", "06:00", 1<<i)))
	}
	e, _, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{1: rules},
		WithRefreshInterval(30*24*time.Hour))

	for i, name := range names {
		for _, step := range []struct {
			offset int
			hms    string
			want   bool
		}{
			{0, "23:00:00", true},  // the evening it starts
			{1, "01:00:00", true},  // the next morning
			{0, "01:00:00", false}, // the same calendar day's early morning belongs to the previous night
			{1, "07:00:00", false},
			{1, "23:00:00", false},
			{2, "01:00:00", false},
		} {
			clock.Set(at(5+i+step.offset, step.hms))
			if got := isBlocked(e, name+".example"); got != step.want {
				t.Errorf("%s rule at %s: blocked = %v, want %v", name, clock.Now().Format("Mon 15:04"), got, step.want)
			}
		}
	}
}

func TestOvernightWindowOnEveryDayIsActiveExceptDuringTheDay(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("night.example", "block", during("22:00", "06:00", allDays))},
	}, WithRefreshInterval(30*24*time.Hour))

	for hms, want := range map[string]bool{
		"00:00:00": true, "03:00:00": true, "06:00:00": true,
		"06:00:01": false, "12:00:00": false, "21:59:59": false,
		"22:00:00": true, "23:59:59": true,
	} {
		for day := 5; day <= 11; day++ {
			clock.Set(at(day, hms))
			if got := isBlocked(e, "night.example"); got != want {
				t.Errorf("Oct %d %s: blocked = %v, want %v", day, hms, got, want)
			}
		}
	}
}

func TestOvernightKeywordWindowTogglesWithoutReload(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("20:00:00"), map[int64][]fakedb.Rule{
		1: {keywordRule("night talk", during("22:00", "02:00", mon))},
	}, WithRefreshInterval(30*24*time.Hour))

	for _, step := range []struct {
		at   time.Time
		want bool
	}{
		{monday("20:00:00"), false},
		{monday("23:30:00"), true},
		{at(6, "01:30:00"), true},
		{at(6, "02:30:00"), false},
		{at(6, "23:30:00"), false},
	} {
		clock.Set(step.at)
		if got := keywordMatches(e, "some night talk here"); got != step.want {
			t.Errorf("at %s: matched = %v, want %v", step.at.Format("Mon 15:04"), got, step.want)
		}
	}
	if q := fake.Queries(); q != 1 {
		t.Fatalf("queries = %d, want 1", q)
	}
}

func TestOvernightAndDaytimeWindowsCombine(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("mixed.example", "block", []fakedb.Schedule{
			{Start: "09:00", End: "10:00", DaysMask: mon},
			{Start: "23:00", End: "01:00", DaysMask: mon},
		})},
	}, WithRefreshInterval(30*24*time.Hour))

	for _, step := range []struct {
		at   time.Time
		want bool
	}{
		{monday("09:30:00"), true},
		{monday("12:00:00"), false},
		{monday("23:30:00"), true},
		{at(6, "00:30:00"), true},
		{at(6, "01:30:00"), false},
		{at(6, "09:30:00"), false},
	} {
		clock.Set(step.at)
		if got := isBlocked(e, "mixed.example"); got != step.want {
			t.Errorf("at %s: blocked = %v, want %v", step.at.Format("Mon 15:04"), got, step.want)
		}
	}
}

func TestWindowWithEqualStartAndEndIsASingleInstant(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("08:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("instant.example", "block", during("09:00:00", "09:00:00", mon))},
	})
	for _, step := range []struct {
		at   time.Time
		want bool
	}{
		{monday("08:59:59"), false},
		{monday("09:00:00"), true},
		{monday("09:00:00.000001"), false},
		{monday("21:00:00"), false}, // not an all-day window, and not an overnight one
	} {
		clock.Set(step.at)
		if got := isBlocked(e, "instant.example"); got != step.want {
			t.Errorf("at %s: blocked = %v, want %v", step.at.Format("15:04:05.000000"), got, step.want)
		}
	}
}

func TestSlotRecompilesWhenClockMovesBackwards(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("09:45:00"), map[int64][]fakedb.Rule{
		1: {domainRule("window.example", "block", during("09:30", "10:30", mon))},
	})
	if !isBlocked(e, "window.example") {
		t.Fatal("should be active at 09:45")
	}
	clock.Set(monday("08:00:00"))
	if isBlocked(e, "window.example") {
		t.Fatal("stale slot used after the clock moved backwards")
	}
}

func TestConflictingDomainRulesBlockWins(t *testing.T) {
	for name, rules := range map[string][]fakedb.Rule{
		"block first":  {domainRule("dup.example", "block", nil), domainRule("dup.example", "accept", nil)},
		"accept first": {domainRule("dup.example", "accept", nil), domainRule("dup.example", "block", nil)},
	} {
		t.Run(name, func(t *testing.T) {
			e, _, _ := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{1: rules})
			if d, _ := e.DecideWithReason(get("https://dup.example/")); d != Block {
				t.Fatalf("decision = %v, want Block", d)
			}
		})
	}
}

func TestConflictingRulesOnlyConflictWhileBothAreActive(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("08:00:00"), map[int64][]fakedb.Rule{
		1: {
			domainRule("dup.example", "accept", nil),
			domainRule("dup.example", "block", during("09:00", "10:00", mon)),
		},
	})
	if d, _ := e.DecideWithReason(get("https://dup.example/")); d != Accept {
		t.Fatalf("outside the block window: %v, want Accept", d)
	}
	clock.Set(monday("09:30:00"))
	if d, _ := e.DecideWithReason(get("https://dup.example/")); d != Block {
		t.Fatalf("inside the block window: %v, want Block", d)
	}
}

// --- timezones ---

func TestSchedulesUseTheConfiguredTimezone(t *testing.T) {
	ams, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	rules := map[int64][]fakedb.Rule{
		1: {domainRule("school.example", "block", during("09:00", "10:00", weekdays))},
	}

	tests := []struct {
		name string
		at   time.Time // UTC instant
		want bool
	}{
		{"summer 09:30 local", time.Date(2026, 10, 5, 7, 30, 0, 0, time.UTC), true}, // CEST, UTC+2
		{"summer 10:30 local", time.Date(2026, 10, 5, 8, 30, 0, 0, time.UTC), false},
		{"summer 08:59 local", time.Date(2026, 10, 5, 6, 59, 59, 0, time.UTC), false},
		{"summer 09:30 UTC is 11:30 local", time.Date(2026, 10, 5, 9, 30, 0, 0, time.UTC), false},
		{"winter 09:30 local", time.Date(2026, 12, 7, 8, 30, 0, 0, time.UTC), true}, // CET, UTC+1
		{"winter 08:30 local", time.Date(2026, 12, 7, 7, 30, 0, 0, time.UTC), false},
		{"local date rolls before UTC", time.Date(2026, 10, 4, 22, 30, 0, 0, time.UTC), false}, // Mon 00:30 local, outside window
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _, _ := newScheduledEngine(t, tt.at, rules, WithLocation(ams))
			if got := isBlocked(e, "school.example"); got != tt.want {
				t.Fatalf("blocked = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWeekdayIsTakenInTheConfiguredTimezone(t *testing.T) {
	// 23:30 UTC on Sunday is already 01:30 Monday in Amsterdam.
	ams, _ := time.LoadLocation("Europe/Amsterdam")
	rules := map[int64][]fakedb.Rule{
		1: {domainRule("monday.example", "block", during("00:00", "23:59:59", mon))},
	}
	sundayLateUTC := time.Date(2026, 10, 4, 23, 30, 0, 0, time.UTC)

	inUTC, _, _ := newScheduledEngine(t, sundayLateUTC, rules, WithLocation(time.UTC))
	if isBlocked(inUTC, "monday.example") {
		t.Error("Sunday in UTC should not match a Monday rule")
	}
	inAms, _, _ := newScheduledEngine(t, sundayLateUTC, rules, WithLocation(ams))
	if !isBlocked(inAms, "monday.example") {
		t.Error("it is already Monday in Amsterdam")
	}
}

// --- refreshing rules from the database ---

func TestRuleEditsAppearAfterTheRefreshInterval(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("old.example", "block", nil)},
	}, WithRefreshInterval(time.Minute))

	if !isBlocked(e, "old.example") || isBlocked(e, "new.example") {
		t.Fatal("initial rules wrong")
	}
	fake.SetRules(1, []fakedb.Rule{domainRule("new.example", "block", nil)})

	clock.Advance(59 * time.Second)
	if !isBlocked(e, "old.example") || isBlocked(e, "new.example") {
		t.Fatal("rules changed before the refresh interval elapsed")
	}
	if q := fake.Queries(); q != 1 {
		t.Fatalf("queries = %d before the interval, want 1", q)
	}

	clock.Advance(2 * time.Second)
	if isBlocked(e, "old.example") || !isBlocked(e, "new.example") {
		t.Fatal("edited rules not picked up after the refresh interval")
	}
	if q := fake.Queries(); q != 2 {
		t.Fatalf("queries = %d after the interval, want 2", q)
	}

	// Steady state: no further queries until the next interval.
	for i := 0; i < 20; i++ {
		isBlocked(e, "new.example")
	}
	if q := fake.Queries(); q != 2 {
		t.Fatalf("queries = %d, want 2", q)
	}
}

func TestRemovedRulesStopApplying(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("gone.example", "block", nil), keywordRule("gone phrase", nil)},
	}, WithRefreshInterval(time.Minute))
	if !isBlocked(e, "gone.example") || !keywordMatches(e, "gone phrase") {
		t.Fatal("rules not active")
	}
	fake.SetRules(1, nil)
	clock.Advance(2 * time.Minute)
	if isBlocked(e, "gone.example") || keywordMatches(e, "gone phrase") {
		t.Fatal("deleted rules still apply after a refresh")
	}
}

func TestEditedRulesGetTheirNewSchedule(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("09:30:00"), map[int64][]fakedb.Rule{
		1: {domainRule("a.example", "block", during("09:00", "10:00", mon))},
	}, WithRefreshInterval(time.Minute))
	if !isBlocked(e, "a.example") {
		t.Fatal("rule should be active")
	}
	fake.SetRules(1, []fakedb.Rule{domainRule("a.example", "block", during("11:00", "12:00", mon))})
	clock.Advance(2 * time.Minute) // 09:32, past the refresh
	if isBlocked(e, "a.example") {
		t.Fatal("rule still active under its old schedule")
	}
	clock.Set(monday("11:30:00"))
	if !isBlocked(e, "a.example") {
		t.Fatal("rule not active under its new schedule")
	}
}

func TestFailedRefreshKeepsServingPreviousRules(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	e, fake, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("old.example", "block", nil), keywordRule("old phrase", nil)},
	}, WithRefreshInterval(time.Minute), WithLogger(logger))

	if !isBlocked(e, "old.example") {
		t.Fatal("initial load failed")
	}
	fake.SetError(errors.New("db down"))
	clock.Advance(2 * time.Minute)

	// One request tries to refresh and fails; everyone keeps the old rules.
	if !isBlocked(e, "old.example") || !keywordMatches(e, "old phrase") {
		t.Fatal("rules dropped when the refresh failed")
	}
	afterFirstFailure := fake.Queries()
	if afterFirstFailure != 2 {
		t.Fatalf("queries = %d, want 2 (initial load + one failed refresh)", afterFirstFailure)
	}

	// The database is not hammered while it is down.
	for i := 0; i < 50; i++ {
		isBlocked(e, "old.example")
	}
	if q := fake.Queries(); q != afterFirstFailure {
		t.Fatalf("queries rose to %d during the retry delay", q)
	}
	if !strings.Contains(logs.String(), `"keeping_previous_rules":true`) || !strings.Contains(logs.String(), "db down") {
		t.Fatalf("refresh failure not logged: %s", logs.String())
	}

	// After the retry delay it tries again, and recovers once the database is back.
	clock.Advance(maxRetryDelay + time.Second)
	isBlocked(e, "old.example")
	if q := fake.Queries(); q != afterFirstFailure+1 {
		t.Fatalf("queries = %d, want one retry", q)
	}
	fake.SetError(nil)
	fake.SetRules(1, []fakedb.Rule{domainRule("new.example", "block", nil)})
	clock.Advance(maxRetryDelay + time.Second)
	if isBlocked(e, "old.example") || !isBlocked(e, "new.example") {
		t.Fatal("did not recover to the new rules once the database returned")
	}
}

func TestFirstLoadFailureIsAnErrorAndRetried(t *testing.T) {
	var logs bytes.Buffer
	e, fake, clock := newScheduledEngine(t, monday("12:00:00"), map[int64][]fakedb.Rule{
		1: {domainRule("blocked.example", "block", nil)},
	}, WithLogger(slog.New(slog.NewJSONHandler(&logs, nil))))

	fake.SetError(errors.New("db down"))
	if _, err := e.getSlot(1); err == nil {
		t.Fatal("expected an error when no rules have ever loaded")
	}
	if !strings.Contains(logs.String(), `"keeping_previous_rules":false`) {
		t.Fatalf("first-load failure not logged: %s", logs.String())
	}

	fake.SetError(nil)
	if !isBlocked(e, "blocked.example") {
		t.Fatal("did not load once the database recovered")
	}
	_ = clock
}

func TestEachGroupHasItsOwnSchedulesAndRefresh(t *testing.T) {
	e, _, clock := newScheduledEngine(t, monday("09:30:00"), map[int64][]fakedb.Rule{
		1: {domainRule("one.example", "block", during("09:00", "10:00", mon))},
		2: {domainRule("one.example", "block", during("11:00", "12:00", mon))},
	})
	if !blockedDomain(e, "one.example", "1") || blockedDomain(e, "one.example", "2") {
		t.Fatal("group schedules mixed up at 09:30")
	}
	clock.Set(monday("11:30:00"))
	if blockedDomain(e, "one.example", "1") || !blockedDomain(e, "one.example", "2") {
		t.Fatal("group schedules mixed up at 11:30")
	}
}

func TestOptionsIgnoreInvalidValues(t *testing.T) {
	db, _ := fakedb.New(t, nil)
	e := NewEngine(db, WithLocation(nil), WithRefreshInterval(0), WithRefreshInterval(-time.Second), WithClock(nil))
	if e.loc != time.Local || e.refresh != DefaultRefreshInterval || e.now == nil {
		t.Fatalf("defaults overridden by invalid options: %+v", e)
	}
}

// Run with -race: requests, clock movement and refreshes all overlap.
func TestConcurrentRequestsWhileTimeAndRulesChange(t *testing.T) {
	e, fake, clock := newScheduledEngine(t, monday("08:00:00"), map[int64][]fakedb.Rule{
		1: {
			domainRule("a.example", "block", during("09:00", "10:00", allDays)),
			keywordRule("phrase", during("09:30", "11:00", allDays)),
		},
	}, WithRefreshInterval(10*time.Minute))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					isBlocked(e, "a.example")
					keywordMatches(e, "a phrase")
				}
			}
		}()
	}
	for i := 0; i < 400; i++ {
		clock.Advance(7 * time.Minute)
		if i%25 == 0 {
			fake.SetRules(1, []fakedb.Rule{domainRule("a.example", "block", during("00:00", "23:59:59", allDays))})
		}
		isBlocked(e, "a.example")
	}
	close(stop)
	wg.Wait()
}

// --- internals ---

func TestNextTransition(t *testing.T) {
	rules := []*scheduledRule{{windows: []window{
		{start: 9 * time.Hour, end: 10 * time.Hour, daysMask: mon},
	}}}
	tests := []struct {
		name string
		from time.Time
		want time.Time
	}{
		{"before the window", monday("08:00:00"), monday("09:00:00")},
		{"inside the window", monday("09:30:00"), monday("10:00:00").Add(time.Microsecond)},
		{"after the window, capped at an hour", monday("11:00:00"), monday("12:00:00")},
		{"exactly at start, capped at an hour", monday("09:00:00"), monday("10:00:00")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextTransition(rules, tt.from); !got.Equal(tt.want) {
				t.Fatalf("nextTransition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNextTransitionForOvernightWindows(t *testing.T) {
	rules := []*scheduledRule{{windows: []window{
		{start: 22 * time.Hour, end: 6 * time.Hour, daysMask: mon},
	}}}
	tests := []struct {
		name string
		from time.Time
		want time.Time
	}{
		{"evening before the start", monday("21:30:00"), monday("22:00:00")},
		{"after midnight, window began yesterday", at(6, "05:30:00"), at(6, "06:00:00").Add(time.Microsecond)},
		{"mid-window is capped", monday("22:10:00"), monday("23:10:00")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextTransition(rules, tt.from); !got.Equal(tt.want) {
				t.Fatalf("nextTransition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWindowActiveAt(t *testing.T) {
	overnight := window{start: 22 * time.Hour, end: 6 * time.Hour, daysMask: sun}
	// Sunday 22:00 -> Monday 06:00: the end of the week wraps to Monday.
	for tm, want := range map[time.Time]bool{
		at(11, "23:00:00"): true, // Sunday night
		at(12, "05:00:00"): true, // Monday morning, started Sunday
		at(12, "07:00:00"): false,
		at(11, "05:00:00"): false, // Sunday morning belongs to Saturday's window
		at(12, "23:00:00"): false, // Monday night: mask is Sunday only
	} {
		if got := overnight.activeAt(tm); got != want {
			t.Errorf("activeAt(%s) = %v, want %v", tm.Format("Mon 15:04"), got, want)
		}
	}
}

func TestNextTransitionWithNoRulesIsCapped(t *testing.T) {
	from := monday("12:00:00")
	if got := nextTransition(nil, from); !got.Equal(from.Add(maxSlotLifetime)) {
		t.Fatalf("got %v", got)
	}
}

func TestSecondsToDuration(t *testing.T) {
	for in, want := range map[float64]time.Duration{
		0:             0,
		34200:         9*time.Hour + 30*time.Minute,
		86399.999999:  24*time.Hour - time.Microsecond,
		32400.1234567: 9*time.Hour + 123457*time.Microsecond,
	} {
		if got := secondsToDuration(in); got != want {
			t.Errorf("secondsToDuration(%v) = %v, want %v", in, got, want)
		}
	}
}
