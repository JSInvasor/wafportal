// Package store is the persistence layer: protected sites, custom rules, and
// WAF events. It uses a pure-Go SQLite driver so the whole portal ships as a
// single cgo-free binary.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite writers are serialized; a single connection avoids "database is
	// locked" churn under the proxy's concurrent event inserts.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS sites (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	domain       TEXT NOT NULL UNIQUE,
	upstream_url TEXT NOT NULL,
	waf_mode     TEXT NOT NULL DEFAULT 'on',
	tls_mode     TEXT NOT NULL DEFAULT 'auto',
	cert_file    TEXT NOT NULL DEFAULT '',
	key_file     TEXT NOT NULL DEFAULT '',
	enabled      INTEGER NOT NULL DEFAULT 1,
	created_at   DATETIME NOT NULL,
	updated_at   DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	directive   TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	enabled     INTEGER NOT NULL DEFAULT 1,
	created_at  DATETIME NOT NULL,
	updated_at  DATETIME NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp     DATETIME NOT NULL,
	tx_id         TEXT NOT NULL,
	domain        TEXT NOT NULL,
	client_ip     TEXT NOT NULL,
	method        TEXT NOT NULL,
	uri           TEXT NOT NULL,
	blocked       INTEGER NOT NULL,
	status_code   INTEGER NOT NULL,
	rule_id       INTEGER NOT NULL,
	message       TEXT NOT NULL,
	severity      INTEGER NOT NULL,
	anomaly_score INTEGER NOT NULL,
	matched_rules TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(blocked);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`
	_, err := s.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// ---- Settings (key/value) ----

// GetSetting returns the stored value and whether the key exists.
func (s *Store) GetSetting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ---- Sites ----

func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.db.Query(`SELECT id, domain, upstream_url, waf_mode, tls_mode, cert_file, key_file, enabled, created_at, updated_at FROM sites ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		var st Site
		if err := rows.Scan(&st.ID, &st.Domain, &st.UpstreamURL, &st.WAFMode, &st.TLSMode, &st.CertFile, &st.KeyFile, &st.Enabled, &st.CreatedAt, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) GetSite(id int64) (Site, error) {
	var st Site
	err := s.db.QueryRow(`SELECT id, domain, upstream_url, waf_mode, tls_mode, cert_file, key_file, enabled, created_at, updated_at FROM sites WHERE id = ?`, id).
		Scan(&st.ID, &st.Domain, &st.UpstreamURL, &st.WAFMode, &st.TLSMode, &st.CertFile, &st.KeyFile, &st.Enabled, &st.CreatedAt, &st.UpdatedAt)
	return st, err
}

func (s *Store) CreateSite(st *Site) error {
	now := time.Now().UTC()
	st.CreatedAt, st.UpdatedAt = now, now
	res, err := s.db.Exec(`INSERT INTO sites (domain, upstream_url, waf_mode, tls_mode, cert_file, key_file, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		st.Domain, st.UpstreamURL, st.WAFMode, st.TLSMode, st.CertFile, st.KeyFile, st.Enabled, st.CreatedAt, st.UpdatedAt)
	if err != nil {
		return err
	}
	st.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateSite(st *Site) error {
	st.UpdatedAt = time.Now().UTC()
	_, err := s.db.Exec(`UPDATE sites SET domain=?, upstream_url=?, waf_mode=?, tls_mode=?, cert_file=?, key_file=?, enabled=?, updated_at=? WHERE id=?`,
		st.Domain, st.UpstreamURL, st.WAFMode, st.TLSMode, st.CertFile, st.KeyFile, st.Enabled, st.UpdatedAt, st.ID)
	return err
}

func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

// ---- Custom rules ----

func (s *Store) ListRules() ([]CustomRule, error) {
	rows, err := s.db.Query(`SELECT id, name, directive, description, enabled, created_at, updated_at FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CustomRule
	for rows.Next() {
		var r CustomRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Directive, &r.Description, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EnabledRuleDirectives returns the directive text of every enabled custom
// rule, in declaration order, for compiling into the WAF engine.
func (s *Store) EnabledRuleDirectives() ([]string, error) {
	rows, err := s.db.Query(`SELECT directive FROM rules WHERE enabled = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) GetRule(id int64) (CustomRule, error) {
	var r CustomRule
	err := s.db.QueryRow(`SELECT id, name, directive, description, enabled, created_at, updated_at FROM rules WHERE id = ?`, id).
		Scan(&r.ID, &r.Name, &r.Directive, &r.Description, &r.Enabled, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (s *Store) CreateRule(r *CustomRule) error {
	now := time.Now().UTC()
	r.CreatedAt, r.UpdatedAt = now, now
	res, err := s.db.Exec(`INSERT INTO rules (name, directive, description, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		r.Name, r.Directive, r.Description, r.Enabled, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return err
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

func (s *Store) UpdateRule(r *CustomRule) error {
	r.UpdatedAt = time.Now().UTC()
	_, err := s.db.Exec(`UPDATE rules SET name=?, directive=?, description=?, enabled=?, updated_at=? WHERE id=?`,
		r.Name, r.Directive, r.Description, r.Enabled, r.UpdatedAt, r.ID)
	return err
}

func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM rules WHERE id = ?`, id)
	return err
}

// ---- Events ----

func (s *Store) InsertEvent(e *Event) error {
	matched, _ := json.Marshal(e.MatchedRules)
	res, err := s.db.Exec(`INSERT INTO events (timestamp, tx_id, domain, client_ip, method, uri, blocked, status_code, rule_id, message, severity, anomaly_score, matched_rules) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Timestamp, e.TxID, e.Domain, e.ClientIP, e.Method, e.URI, e.Blocked, e.StatusCode, e.RuleID, e.Message, e.Severity, e.AnomalyScore, string(matched))
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// EventFilter narrows an event query for the monitoring views.
type EventFilter struct {
	Domain     string
	BlockedOnly bool
	Limit      int
	Offset     int
}

func (s *Store) ListEvents(f EventFilter) ([]Event, error) {
	var where []string
	var args []any
	if f.Domain != "" {
		where = append(where, "domain = ?")
		args = append(args, f.Domain)
	}
	if f.BlockedOnly {
		where = append(where, "blocked = 1")
	}
	q := `SELECT id, timestamp, tx_id, domain, client_ip, method, uri, blocked, status_code, rule_id, message, severity, anomaly_score, matched_rules FROM events`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	args = append(args, f.Limit, f.Offset)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var matched string
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.TxID, &e.Domain, &e.ClientIP, &e.Method, &e.URI, &e.Blocked, &e.StatusCode, &e.RuleID, &e.Message, &e.Severity, &e.AnomalyScore, &matched); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(matched), &e.MatchedRules)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Stats aggregates events from the last `since` window for the dashboard.
func (s *Store) Stats(since time.Duration) (Stats, error) {
	var st Stats
	from := time.Now().UTC().Add(-since)

	if err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(blocked),0) FROM events WHERE timestamp >= ?`, from).
		Scan(&st.TotalEvents, &st.BlockedEvents); err != nil {
		return st, err
	}

	rules, err := s.db.Query(`SELECT rule_id, message, COUNT(*) c FROM events WHERE timestamp >= ? AND rule_id != 0 GROUP BY rule_id ORDER BY c DESC LIMIT 10`, from)
	if err != nil {
		return st, err
	}
	defer rules.Close()
	for rules.Next() {
		var rc RuleCount
		if err := rules.Scan(&rc.RuleID, &rc.Message, &rc.Count); err != nil {
			return st, err
		}
		st.TopRules = append(st.TopRules, rc)
	}

	clients, err := s.db.Query(`SELECT client_ip, COUNT(*) c FROM events WHERE timestamp >= ? GROUP BY client_ip ORDER BY c DESC LIMIT 10`, from)
	if err != nil {
		return st, err
	}
	defer clients.Close()
	for clients.Next() {
		var cc ClientCount
		if err := clients.Scan(&cc.ClientIP, &cc.Count); err != nil {
			return st, err
		}
		st.TopClients = append(st.TopClients, cc)
	}

	// The driver stores time.Time in Go's String() layout with nanoseconds,
	// which SQLite's date functions cannot parse; substr trims it to a
	// "YYYY-MM-DD HH:MM:SS" prefix that strftime understands.
	buckets, err := s.db.Query(`SELECT strftime('%Y-%m-%dT%H:00:00Z', substr(timestamp,1,19)) b, COUNT(*), COALESCE(SUM(blocked),0) FROM events WHERE timestamp >= ? GROUP BY b ORDER BY b`, from)
	if err != nil {
		return st, err
	}
	defer buckets.Close()
	for buckets.Next() {
		var tp TimelinePoint
		var bucket string
		if err := buckets.Scan(&bucket, &tp.Total, &tp.Blocked); err != nil {
			return st, err
		}
		tp.Bucket, _ = time.Parse(time.RFC3339, bucket)
		st.Timeline = append(st.Timeline, tp)
	}

	return st, nil
}
