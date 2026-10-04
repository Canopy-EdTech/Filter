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

// dbClock reports the database's idea of "now": the weekday bit used by
// days_mask (bit 0 = Monday) and windows that do / don't contain this moment.
type dbClock struct {
	todayBit     int
	otherDays    int
	activeStart  string
	activeEnd    string
	inactiveFrom string
	inactiveTo   string
}

func newDBClock(t *testing.T, db *sql.DB) dbClock {
	t.Helper()
	var now time.Time
	var tod string
	if err := db.QueryRow("SELECT CURRENT_TIMESTAMP, CURRENT_TIME::time::text").Scan(&now, &tod); err != nil {
		t.Fatal(err)
	}

	bit := 1 << ((int(now.Weekday()) + 6) % 7) // Monday=bit0 ... Sunday=bit6
	c := dbClock{
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

func (c dbClock) always() [3]any     { return [3]any{c.activeStart, c.activeEnd, 127} }
func (c dbClock) today() [3]any      { return [3]any{c.activeStart, c.activeEnd, c.todayBit} }
func (c dbClock) otherDay() [3]any   { return [3]any{c.activeStart, c.activeEnd, c.otherDays} }
func (c dbClock) wrongTime() [3]any  { return [3]any{c.inactiveFrom, c.inactiveTo, 127} }
func (c dbClock) activeTime() [3]any { return [3]any{c.activeStart, c.activeEnd, c.todayBit} }

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

	e := NewEngine(db)
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

	e := NewEngine(db)
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

	e := NewEngine(db)
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
	// With conflicting rules for one domain, a decision is still made (the
	// later row wins); the point is that loading doesn't fail.
	if d, _ := e.DecideWithReason(get("https://dup.example/")); d != Block && d != Accept {
		t.Errorf("conflicting domain rules gave %v", d)
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
	if blockedDomain(NewEngine(db), "gone.example", "") {
		t.Error("deleted rule still applies")
	}
}

func TestPostgresSchemaCannotBeAppliedTwice(t *testing.T) {
	db := newSchemaDB(t)
	if _, err := db.Exec(readSQL(t, "schema.sql")); err == nil {
		t.Fatal("re-applying schema.sql should fail on existing tables")
	}
}
