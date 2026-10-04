// Package fakedb is a tiny database/sql driver that serves canned rule rows,
// so the filter engine can be exercised without a Postgres server.
package fakedb

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// Rule is one (type, pattern, action) row as returned by the rules query.
type Rule struct{ Type, Pattern, Action string }

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

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	s.db.queries.Add(1)
	s.db.mu.Lock()
	defer s.db.mu.Unlock()
	if s.db.err != nil {
		return nil, s.db.err
	}
	return &rows{rules: s.db.rules[args[0].(int64)]}, nil
}

type rows struct {
	rules []Rule
	i     int
}

func (r *rows) Columns() []string { return []string{"type", "pattern", "action"} }
func (r *rows) Close() error      { return nil }
func (r *rows) Next(dest []driver.Value) error {
	if r.i >= len(r.rules) {
		return io.EOF
	}
	rule := r.rules[r.i]
	r.i++
	dest[0], dest[1], dest[2] = rule.Type, rule.Pattern, rule.Action
	return nil
}
