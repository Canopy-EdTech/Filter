package filter

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// These tests run the real rules query and db/schema.sql against Postgres.
// They are skipped unless TEST_DATABASE_URL points at a database the tests may
// create temporary schemas in, e.g.
//
//	docker run --rm -d -e POSTGRES_PASSWORD=test -e POSTGRES_DB=canopy_test -p 54329:5432 postgres:17
//	TEST_DATABASE_URL='postgres://postgres:test@localhost:54329/canopy_test?sslmode=disable' go test ./pkg/filter/
//
// Each test works in its own throwaway schema, so existing data is untouched.

func readSQL(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("../../db/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// newSchemaDB creates an isolated schema, applies db/schema.sql to it, and
// returns a connection pool whose search_path points at that schema.
func newSchemaDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres tests")
	}

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if err := admin.Ping(); err != nil {
		t.Fatalf("cannot reach TEST_DATABASE_URL: %v", err)
	}

	suffix := make([]byte, 6)
	rand.Read(suffix)
	schema := "filter_test_" + hex.EncodeToString(suffix)
	if _, err := admin.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec("DROP SCHEMA " + schema + " CASCADE") })

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	var path string
	if err := db.QueryRow("SHOW search_path").Scan(&path); err != nil || !strings.Contains(path, schema) {
		t.Fatalf("search_path = %q (err %v), want %s", path, err, schema)
	}
	if _, err := db.Exec(readSQL(t, "schema.sql")); err != nil {
		t.Fatalf("apply schema.sql: %v", err)
	}
	return db
}

// pgEngine builds an engine that evaluates schedules in UTC, so the tests do
// not depend on the machine's timezone.
func pgEngine(db *sql.DB, opts ...Option) *Engine {
	return NewEngine(db, append([]Option{WithLocation(time.UTC)}, opts...)...)
}

// testClock describes schedules relative to the current moment (UTC): windows
// and day masks that do, or do not, contain it.
type testClock struct {
	todayBit     int
	otherDays    int
	activeStart  string
	activeEnd    string
	inactiveFrom string
	inactiveTo   string
}

func newDBClock(t *testing.T, _ *sql.DB) testClock {
	t.Helper()
	now := time.Now().UTC()

	bit := weekdayBit(now.Weekday()) // Monday=bit0 ... Sunday=bit6
	c := testClock{
		todayBit:    bit,
		otherDays:   127 &^ bit,
		activeStart: "00:00:00",
		activeEnd:   "23:59:59.999999",
	}
	if now.Hour() < 12 {
		c.inactiveFrom, c.inactiveTo = "12:00:00", "23:59:59.999999"
	} else {
		c.inactiveFrom, c.inactiveTo = "00:00:00", "11:59:59"
	}
	return c
}

func addRule(t *testing.T, db *sql.DB, ruleType, pattern, action string, groups []int, schedules ...[3]any) int {
	t.Helper()
	var id int
	if err := db.QueryRow("INSERT INTO rules (type, pattern, action) VALUES ($1, $2, $3) RETURNING id",
		ruleType, pattern, action).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if _, err := db.Exec("INSERT INTO rule_groups (rule_id, group_id) VALUES ($1, $2)", id, g); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range schedules {
		if _, err := db.Exec("INSERT INTO rule_schedules (rule_id, start_time, end_time, days_mask) VALUES ($1, $2, $3, $4)",
			id, s[0], s[1], s[2]); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func (c testClock) always() [3]any     { return [3]any{c.activeStart, c.activeEnd, 127} }
func (c testClock) today() [3]any      { return [3]any{c.activeStart, c.activeEnd, c.todayBit} }
func (c testClock) otherDay() [3]any   { return [3]any{c.activeStart, c.activeEnd, c.otherDays} }
func (c testClock) wrongTime() [3]any  { return [3]any{c.inactiveFrom, c.inactiveTo, 127} }
func (c testClock) activeTime() [3]any { return [3]any{c.activeStart, c.activeEnd, c.todayBit} }

func blockedDomain(e *Engine, host string, group string) bool {
	req := get("https://" + host + "/")
	if group != "" {
		req.Header.Set("X-Group-ID", group)
	}
	decision, _ := e.DecideWithReason(req)
	return decision == Block
}

func TestPostgresSchemaAndSeed(t *testing.T) {
	db := newSchemaDB(t)
	if _, err := db.Exec(readSQL(t, "seed.sql")); err != nil {
		t.Fatalf("apply seed.sql: %v", err)
	}

	noon := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) // a Monday
	e := pgEngine(db, WithClock(func() time.Time { return noon }))
	if d, _ := e.DecideWithReason(get("https://blocked.example/")); d != Block {
		t.Errorf("seeded blocked domain: %v", d)
	}
	if d, _ := e.DecideWithReason(get("https://accepted.example/")); d != Accept {
		t.Errorf("seeded accepted domain: %v", d)
	}
	if d, _ := e.DecideWithReason(get("https://other.example/")); d != Inspect {
		t.Errorf("unlisted domain: %v", d)
	}
	if _, found := e.KeywordMatchRequest(get("https://x.example/"), []byte("this has a blocked phrase in it")); !found {
		t.Error("seeded keyword did not match")
	}
	// Seed rules belong to group 1 only.
	if blockedDomain(e, "blocked.example", "2") {
		t.Error("group 2 should not inherit group 1's seeded rules")
	}
}

func TestPostgresScheduling(t *testing.T) {
	db := newSchemaDB(t)
	c := newDBClock(t, db)

	addRule(t, db, "domain", "always.example", "block", []int{1}, c.always())
	addRule(t, db, "domain", "today.example", "block", []int{1}, c.today())
	addRule(t, db, "domain", "otherday.example", "block", []int{1}, c.otherDay())
	addRule(t, db, "domain", "wrongtime.example", "block", []int{1}, c.wrongTime())
	addRule(t, db, "domain", "mixed.example", "block", []int{1}, c.wrongTime(), c.activeTime())
	addRule(t, db, "domain", "unscheduled.example", "block", []int{1})
	addRule(t, db, "domain", "ungrouped.example", "block", nil, c.always())
	addRule(t, db, "domain", "shared.example", "block", []int{1, 2}, c.always())
	addRule(t, db, "domain", "group2.example", "block", []int{2}, c.always())

	e := pgEngine(db)
	tests := []struct {
		host, group string
		want        bool
	}{
		{"always.example", "", true},
		{"today.example", "", true},        // days_mask bit for today (bit 0 = Monday)
		{"otherday.example", "", false},    // mask covers every day but today
		{"wrongtime.example", "", false},   // window does not contain now
		{"mixed.example", "", true},        // one of two schedules is active
		{"unscheduled.example", "", false}, // no schedule row means never active
		{"ungrouped.example", "", false},   // no group row means applies to nobody
		{"shared.example", "", true},       // rule in two groups, no duplicates problem
		{"shared.example", "2", true},
		{"group2.example", "", false},
		{"group2.example", "2", true},
		{"always.example", "2", false},
	}
	for _, tt := range tests {
		if got := blockedDomain(e, tt.host, tt.group); got != tt.want {
			t.Errorf("%s (group %q): blocked = %v, want %v", tt.host, tt.group, got, tt.want)
		}
	}
}

func TestPostgresKeywordRulesAndActions(t *testing.T) {
	db := newSchemaDB(t)
	c := newDBClock(t, db)

	addRule(t, db, "keyword", "secret sauce", "block", []int{1}, c.always())
	addRule(t, db, "keyword", "scheduled out", "block", []int{1}, c.wrongTime())
	addRule(t, db, "keyword", "allowed words", "accept", []int{1}, c.always())
	addRule(t, db, "domain", "dup.example", "block", []int{1}, c.always())
	addRule(t, db, "domain", "dup.example", "accept", []int{1}, c.always())

	e := pgEngine(db)
	req := get("https://x.example/")
	for body, want := range map[string]bool{
		"mind the Secret Sauce":   true,
		"scheduled out":           false,
		"allowed words":           false,
		"something else entirely": false,
	} {
		if _, found := e.KeywordMatchRequest(req, []byte(body)); found != want {
			t.Errorf("%q: matched = %v, want %v", body, found, want)
		}
	}
	// When rules disagree about a domain, blocking wins.
	if d, _ := e.DecideWithReason(get("https://dup.example/")); d != Block {
		t.Errorf("conflicting domain rules gave %v, want Block", d)
	}
}

func TestPostgresConstraints(t *testing.T) {
	db := newSchemaDB(t)

	bad := []struct{ name, stmt string }{
		{"unknown rule type", "INSERT INTO rules (type, pattern, action) VALUES ('regex', 'x', 'block')"},
		{"unknown action", "INSERT INTO rules (type, pattern, action) VALUES ('domain', 'x', 'allow')"},
		{"null pattern", "INSERT INTO rules (type, pattern, action) VALUES ('domain', NULL, 'block')"},
		{"orphan group row", "INSERT INTO rule_groups (rule_id, group_id) VALUES (9999, 1)"},
		{"orphan schedule row", "INSERT INTO rule_schedules (rule_id, start_time, end_time, days_mask) VALUES (9999, '00:00', '01:00', 1)"},
	}
	for _, tt := range bad {
		if _, err := db.Exec(tt.stmt); err == nil {
			t.Errorf("%s: insert succeeded, want a constraint error", tt.name)
		}
	}
}

func TestPostgresDeletingRuleCascades(t *testing.T) {
	db := newSchemaDB(t)
	c := newDBClock(t, db)
	id := addRule(t, db, "domain", "gone.example", "block", []int{1, 2}, c.always(), c.today())

	if _, err := db.Exec("DELETE FROM rules WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"rule_groups", "rule_schedules"} {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s has %d rows after deleting the rule (err %v)", table, n, err)
		}
	}
	if blockedDomain(pgEngine(db), "gone.example", "") {
		t.Error("deleted rule still applies")
	}
}

func TestPostgresSchemaCannotBeAppliedTwice(t *testing.T) {
	db := newSchemaDB(t)
	if _, err := db.Exec(readSQL(t, "schema.sql")); err == nil {
		t.Fatal("re-applying schema.sql should fail on existing tables")
	}
}

// The schedule is evaluated in Go from values stored in Postgres, so check the
// stored times round-trip exactly, including the boundaries.
func TestPostgresScheduleBoundariesRoundTrip(t *testing.T) {
	db := newSchemaDB(t)
	addRule(t, db, "domain", "window.example", "block", []int{1},
		[3]any{"09:30:00", "10:30:00", 1}, // Mondays only
	)
	addRule(t, db, "domain", "fractional.example", "block", []int{1},
		[3]any{"00:00:00", "23:59:59.999999", 127},
	)

	var now time.Time
	clock := func() time.Time { return now }
	e := pgEngine(db, WithClock(clock), WithRefreshInterval(24*time.Hour))

	monday := func(h, m, s, us int) time.Time { return time.Date(2026, 10, 5, h, m, s, us*1000, time.UTC) }
	for _, tt := range []struct {
		at   time.Time
		want bool
	}{
		{monday(9, 29, 59, 999999), false},
		{monday(9, 30, 0, 0), true},
		{monday(10, 30, 0, 0), true},
		{monday(10, 30, 0, 1), false},
		{monday(10, 30, 1, 0), false},
		{time.Date(2026, 10, 6, 9, 45, 0, 0, time.UTC), false}, // Tuesday
		{time.Date(2026, 10, 12, 9, 45, 0, 0, time.UTC), true}, // next Monday
	} {
		now = tt.at
		if got := blockedDomain(e, "window.example", ""); got != tt.want {
			t.Errorf("at %s: blocked = %v, want %v", tt.at.Format("Mon 15:04:05.000000"), got, tt.want)
		}
	}

	now = monday(23, 59, 59, 999999)
	if !blockedDomain(e, "fractional.example", "") {
		t.Error("23:59:59.999999 should be inside an all-day window")
	}
}

func TestPostgresEachWeekdayUsesItsOwnBit(t *testing.T) {
	db := newSchemaDB(t)
	names := []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
	for i, name := range names {
		addRule(t, db, "domain", name+".example", "block", []int{1}, [3]any{"00:00:00", "23:59:59.999999", 1 << i})
	}

	var now time.Time
	e := pgEngine(db, WithClock(func() time.Time { return now }), WithRefreshInterval(24*time.Hour))
	for i, active := range names { // Oct 5 2026 is a Monday
		now = time.Date(2026, 10, 5+i, 12, 0, 0, 0, time.UTC)
		for _, name := range names {
			if got, want := blockedDomain(e, name+".example", ""), name == active; got != want {
				t.Errorf("on %s: %s.example blocked = %v, want %v", active, name, got, want)
			}
		}
	}
}

// Regression: a window that starts partway through the hour must be picked up
// without waiting for the next hour or a reload.
func TestPostgresWindowStartingMidHourIsNotMissed(t *testing.T) {
	db := newSchemaDB(t)
	addRule(t, db, "domain", "late.example", "block", []int{1}, [3]any{"09:30:00", "10:30:00", 127})

	now := time.Date(2026, 10, 5, 9, 5, 0, 0, time.UTC)
	e := pgEngine(db, WithClock(func() time.Time { return now }), WithRefreshInterval(24*time.Hour))

	if blockedDomain(e, "late.example", "") {
		t.Fatal("blocked before the window starts")
	}
	now = time.Date(2026, 10, 5, 9, 31, 0, 0, time.UTC)
	if !blockedDomain(e, "late.example", "") {
		t.Fatal("window that started mid-hour was missed")
	}
}

func TestPostgresRuleEditsAreRefreshed(t *testing.T) {
	db := newSchemaDB(t)
	addRule(t, db, "domain", "first.example", "block", []int{1}, [3]any{"00:00:00", "23:59:59.999999", 127})

	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	e := pgEngine(db, WithClock(func() time.Time { return now }), WithRefreshInterval(time.Minute))
	if !blockedDomain(e, "first.example", "") || blockedDomain(e, "second.example", "") {
		t.Fatal("initial rules wrong")
	}

	addRule(t, db, "domain", "second.example", "block", []int{1}, [3]any{"00:00:00", "23:59:59.999999", 127})
	if _, err := db.Exec("DELETE FROM rules WHERE pattern = 'first.example'"); err != nil {
		t.Fatal(err)
	}

	if !blockedDomain(e, "first.example", "") {
		t.Fatal("edit visible before the refresh interval")
	}
	now = now.Add(2 * time.Minute)
	if blockedDomain(e, "first.example", "") || !blockedDomain(e, "second.example", "") {
		t.Fatal("edits not visible after the refresh interval")
	}
}

func TestPostgresOvernightWindowRoundTrip(t *testing.T) {
	db := newSchemaDB(t)
	// Monday 22:00 until Tuesday 06:00; the schema must accept start > end.
	addRule(t, db, "domain", "night.example", "block", []int{1}, [3]any{"22:00:00", "06:00:00", 1})

	var now time.Time
	e := pgEngine(db, WithClock(func() time.Time { return now }), WithRefreshInterval(24*time.Hour))
	for _, tt := range []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 10, 5, 21, 59, 59, 0, time.UTC), false}, // Monday
		{time.Date(2026, 10, 5, 22, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 10, 6, 5, 59, 59, 0, time.UTC), true}, // Tuesday morning
		{time.Date(2026, 10, 6, 6, 0, 0, 0, time.UTC), true},
		{time.Date(2026, 10, 6, 6, 0, 1, 0, time.UTC), false},
		{time.Date(2026, 10, 6, 23, 0, 0, 0, time.UTC), false}, // Tuesday night: Monday-only mask
	} {
		now = tt.at
		if got := blockedDomain(e, "night.example", ""); got != tt.want {
			t.Errorf("at %s: blocked = %v, want %v", tt.at.Format("Mon 15:04:05"), got, tt.want)
		}
	}
}
