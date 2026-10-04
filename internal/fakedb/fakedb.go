// Package fakedb is a tiny database/sql driver that serves canned rule rows,
// so the filter engine can be exercised without a Postgres server.
package fakedb

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Schedule is one rule_schedules row: active between Start and End ("15:04"
// or "15:04:05", inclusive) on the days in DaysMask (bit 0 = Monday).
type Schedule struct {
	Start, End string
	DaysMask   int
}

// Always is a schedule covering every moment of every day.
var Always = Schedule{Start: "00:00:00", End: "23:59:59.999999", DaysMask: 127}

// Rule is one rule with its group membership implied by the map key it is
// stored under. A nil Schedules means Always, as a convenience; use an empty
// non-nil slice for a rule with no schedule rows (which is never active).
type Rule struct {
	Type, Pattern, Action string
	Schedules             []Schedule
}

// DB holds the canned rules, keyed by group id, and records query activity.
type DB struct {
	mu      sync.Mutex
	rules   map[int64][]Rule
	err     error
	queries atomic.Int32
}

// SetError makes every subsequent query fail with err (nil to recover).
func (d *DB) SetError(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

// SetRules replaces the rules served for one group, as if edited in the DB.
func (d *DB) SetRules(group int64, rules []Rule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rules == nil {
		d.rules = make(map[int64][]Rule)
	}
	d.rules[group] = rules
}

// Queries reports how many rule queries have been run.
func (d *DB) Queries() int { return int(d.queries.Load()) }

var (
	registerOnce sync.Once
	instances    sync.Map // dsn -> *DB
	counter      atomic.Int64
)

// New returns a *sql.DB backed by the given rules, plus a handle for
// inspecting and controlling it.
func New(t testing.TB, rules map[int64][]Rule) (*sql.DB, *DB) {
	t.Helper()
	registerOnce.Do(func() { sql.Register("fakedb", driverImpl{}) })

	fake := &DB{rules: rules}
	dsn := t.Name() + "#" + strconv.FormatInt(counter.Add(1), 10)
	instances.Store(dsn, fake)
	t.Cleanup(func() { instances.Delete(dsn) })

	db, err := sql.Open("fakedb", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, fake
}

type driverImpl struct{}

func (driverImpl) Open(dsn string) (driver.Conn, error) {
	fake, ok := instances.Load(dsn)
	if !ok {
		return nil, errors.New("fakedb: unknown instance")
	}
	return &conn{db: fake.(*DB)}, nil
}

type conn struct{ db *DB }

func (c *conn) Prepare(string) (driver.Stmt, error) { return &stmt{db: c.db}, nil }
func (c *conn) Close() error                        { return nil }
func (c *conn) Begin() (driver.Tx, error)           { return nil, errors.New("fakedb: transactions unsupported") }

type stmt struct{ db *DB }

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return 1 }
func (s *stmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("fakedb: exec unsupported")
}

// Query returns one row per (rule, schedule), mirroring the real rules query:
// id, type, pattern, action, start seconds, end seconds, days mask.
func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	s.db.queries.Add(1)
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if s.db.err != nil {
		return nil, s.db.err
	}

	var out [][]driver.Value
	for i, rule := range s.db.rules[args[0].(int64)] {
		schedules := rule.Schedules
		if schedules == nil {
			schedules = []Schedule{Always}
		}
		for _, sc := range schedules {
			start, err := parseClock(sc.Start)
			if err != nil {
				return nil, err
			}
			end, err := parseClock(sc.End)
			if err != nil {
				return nil, err
			}
			out = append(out, []driver.Value{int64(i + 1), rule.Type, rule.Pattern, rule.Action, start, end, int64(sc.DaysMask)})
		}
	}
	return &rows{data: out}, nil
}

// parseClock converts "HH:MM[:SS[.ffffff]]" to seconds since midnight.
func parseClock(s string) (float64, error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("fakedb: bad time %q", s)
	}
	var secs float64
	for _, part := range parts {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, fmt.Errorf("fakedb: bad time %q", s)
		}
		secs = secs*60 + v
	}
	if len(parts) == 2 {
		secs *= 60
	}
	return secs, nil
}

type rows struct {
	data [][]driver.Value
	i    int
}

func (r *rows) Columns() []string {
	return []string{"id", "type", "pattern", "action", "start", "end", "days_mask"}
}
func (r *rows) Close() error { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.i >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.i])
	r.i++
	return nil
}
