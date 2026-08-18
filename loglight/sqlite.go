package loglight

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// SQLiteStore persists Loglight sources and active detections. It shares the
// same *sql.DB as the findings store.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore migrates the tables and returns the store.
func NewSQLiteStore(db *sql.DB) (*SQLiteStore, error) {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS loglight_sources (
    name       TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    params     TEXT NOT NULL DEFAULT '{}',
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS loglight_detections (
    source_id  TEXT NOT NULL,
    key        TEXT NOT NULL,
    check_id   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    target     TEXT NOT NULL DEFAULT '',
    title      TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    evidence   TEXT NOT NULL DEFAULT '[]',
    fix        TEXT NOT NULL DEFAULT '',
    count      INTEGER NOT NULL DEFAULT 1,
    first_at   TIMESTAMP NOT NULL,
    last_at    TIMESTAMP NOT NULL,
    PRIMARY KEY (source_id, key)
);
CREATE INDEX IF NOT EXISTS idx_loglight_det_lastat ON loglight_detections(last_at);`); err != nil {
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) PutSource(c SourceConfig) error {
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	params, _ := json.Marshal(c.Params)
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
INSERT INTO loglight_sources (name, type, params, enabled, created_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
    type = excluded.type, params = excluded.params, enabled = excluded.enabled`,
		c.Name, c.Type, string(params), enabled, c.CreatedAt.UTC())
	return err
}

func (s *SQLiteStore) GetSource(name string) (SourceConfig, bool, error) {
	row := s.db.QueryRow(`SELECT name, type, params, enabled, created_at FROM loglight_sources WHERE name = ?`, name)
	c, err := scanSource(row)
	if err == sql.ErrNoRows {
		return SourceConfig{}, false, nil
	}
	if err != nil {
		return SourceConfig{}, false, err
	}
	return c, true, nil
}

func (s *SQLiteStore) ListSources() ([]SourceConfig, error) {
	rows, err := s.db.Query(`SELECT name, type, params, enabled, created_at FROM loglight_sources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceConfig
	for rows.Next() {
		c, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteSource(name string) error {
	if _, err := s.db.Exec(`DELETE FROM loglight_sources WHERE name = ?`, name); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM loglight_detections WHERE source_id = ?`, name)
	return err
}

func (s *SQLiteStore) UpsertDetection(d DetectionRecord) error {
	ev, _ := json.Marshal(d.Evidence)
	_, err := s.db.Exec(`
INSERT INTO loglight_detections (source_id, key, check_id, severity, actor, target, title, detail, evidence, fix, count, first_at, last_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(source_id, key) DO UPDATE SET
    severity = excluded.severity, title = excluded.title, detail = excluded.detail,
    evidence = excluded.evidence, count = excluded.count, last_at = excluded.last_at,
    first_at = MIN(loglight_detections.first_at, excluded.first_at)`,
		d.SourceID, d.Key, d.Check, d.Severity, d.Actor, d.Target, d.Title, d.Detail,
		string(ev), d.Fix, d.Count, d.FirstAt.UTC(), d.LastAt.UTC())
	return err
}

func (s *SQLiteStore) ListDetections(sourceID string) ([]DetectionRecord, error) {
	rows, err := s.db.Query(`
SELECT source_id, key, check_id, severity, actor, target, title, detail, evidence, fix, count, first_at, last_at
FROM loglight_detections WHERE source_id = ? ORDER BY last_at DESC`, sourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetectionRecord
	for rows.Next() {
		d, err := scanDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) PruneDetections(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM loglight_detections WHERE last_at < ?`, before.UTC())
	return err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSource(sc rowScanner) (SourceConfig, error) {
	var c SourceConfig
	var params string
	var enabled int
	var created time.Time
	if err := sc.Scan(&c.Name, &c.Type, &params, &enabled, &created); err != nil {
		return SourceConfig{}, err
	}
	c.Enabled = enabled != 0
	c.CreatedAt = created
	if strings.TrimSpace(params) != "" {
		_ = json.Unmarshal([]byte(params), &c.Params)
	}
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	return c, nil
}

func scanDetection(sc rowScanner) (DetectionRecord, error) {
	var d DetectionRecord
	var ev string
	var first, last time.Time
	if err := sc.Scan(&d.SourceID, &d.Key, &d.Check, &d.Severity, &d.Actor, &d.Target,
		&d.Title, &d.Detail, &ev, &d.Fix, &d.Count, &first, &last); err != nil {
		return DetectionRecord{}, err
	}
	d.FirstAt, d.LastAt = first, last
	if strings.TrimSpace(ev) != "" {
		_ = json.Unmarshal([]byte(ev), &d.Evidence)
	}
	return d, nil
}
