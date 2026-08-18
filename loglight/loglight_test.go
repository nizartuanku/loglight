package loglight

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nizartuanku/loglight/core"
	"github.com/nizartuanku/loglight/correlate"
	"github.com/nizartuanku/loglight/detect"
	"github.com/nizartuanku/loglight/logingest"
	"github.com/nizartuanku/loglight/store"
)

var t0 = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func newPipeline(ls Store, fs store.Store) *Pipeline {
	return &Pipeline{
		Detect: detect.NewEngine(detect.Config{BruteFailures: 5, BruteWindow: time.Minute}),
		Corr:   correlate.New(10*time.Minute, 15*time.Minute),
		Log:    ls, Store: fs,
	}
}

func failLine(ip string, at time.Time) logingest.Event {
	return logingest.Event{Timestamp: at, SourceID: "auth", Auth: logingest.AuthFailure,
		SrcIP: ip, Host: "web01", App: "sshd", Raw: "Failed password from " + ip}
}

func TestPipelineBruteForceWritesFinding(t *testing.T) {
	ls, fs := NewMemStore(), store.NewMemStore()
	ls.PutSource(SourceConfig{Name: "auth", Type: "file", Enabled: true})
	p := newPipeline(ls, fs)

	for i := 0; i < 5; i++ {
		p.Handle(failLine("203.0.113.9", t0.Add(time.Duration(i)*time.Second)))
	}
	dets, _ := ls.ListDetections("auth")
	if len(dets) != 1 || dets[0].Check != "detect.brute_force" {
		t.Fatalf("expected one brute_force detection, got %+v", dets)
	}
	open, _ := fs.ListOpen(ModuleID)
	if len(open) != 1 {
		t.Fatalf("expected one open finding, got %d", len(open))
	}
	if open[0].Target != "auth" {
		t.Errorf("finding target must equal source name for reconcile, got %q", open[0].Target)
	}
}

func TestPipelineKillChainIncident(t *testing.T) {
	ls, fs := NewMemStore(), store.NewMemStore()
	ls.PutSource(SourceConfig{Name: "fw", Type: "syslog", Enabled: true})
	p := &Pipeline{
		Detect: detect.NewEngine(detect.Config{BruteFailures: 3, BruteWindow: time.Minute, ScanPorts: 3, ScanWindow: time.Minute}),
		Corr:   correlate.New(10*time.Minute, 15*time.Minute),
		Log:    ls, Store: fs,
	}
	// scan
	for port := 20; port < 23; port++ {
		p.Handle(logingest.Event{Timestamp: t0, SourceID: "fw", SrcIP: "203.0.113.9", DstPort: port, Host: "web01", Raw: "deny"})
	}
	// brute
	for i := 0; i < 3; i++ {
		p.Handle(logingest.Event{Timestamp: t0.Add(time.Duration(30+i) * time.Second), SourceID: "fw",
			Auth: logingest.AuthFailure, SrcIP: "203.0.113.9", Host: "web01", App: "sshd", Raw: "Failed password"})
	}
	// success → kill chain
	p.Handle(logingest.Event{Timestamp: t0.Add(90 * time.Second), SourceID: "fw",
		Auth: logingest.AuthSuccess, SrcIP: "203.0.113.9", User: "deploy", Host: "web01", Raw: "Accepted password"})

	dets, _ := ls.ListDetections("fw")
	var inc *DetectionRecord
	for i := range dets {
		if dets[i].Check == "incident.killchain" {
			inc = &dets[i]
		}
	}
	if inc == nil {
		t.Fatalf("expected a kill-chain incident, got %+v", dets)
	}
	if inc.Severity != "critical" {
		t.Errorf("full kill chain should be critical, got %s", inc.Severity)
	}
}

func TestCollectorAutoResolvesQuietDetections(t *testing.T) {
	ls := NewMemStore()
	ls.PutSource(SourceConfig{Name: "auth", Type: "file", Enabled: true})
	// A stale detection (older than ActiveWindow) must NOT be re-emitted.
	ls.UpsertDetection(DetectionRecord{Key: "brute|x", SourceID: "auth", Check: "detect.brute_force",
		Severity: "high", Title: "old", FirstAt: t0.Add(-2 * time.Hour), LastAt: t0.Add(-2 * time.Hour)})
	// A fresh one must be.
	ls.UpsertDetection(DetectionRecord{Key: "brute|y", SourceID: "auth", Check: "detect.brute_force",
		Severity: "high", Title: "fresh", FirstAt: t0.Add(-1 * time.Minute), LastAt: t0.Add(-1 * time.Minute)})

	c := New(ls, nil)
	c.now = func() time.Time { return t0 }
	fs, err := c.Collect(context.Background(), toTarget("auth"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Title != "fresh" {
		t.Fatalf("only the fresh detection should re-emit, got %+v", fs)
	}
}

func TestCollectorDeletedSourceResolves(t *testing.T) {
	c := New(NewMemStore(), nil)
	fs, err := c.Collect(context.Background(), toTarget("gone"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a missing source should emit nothing (auto-resolve), got %d", len(fs))
	}
}

func TestParseRateFindingSurfaced(t *testing.T) {
	ls := NewMemStore()
	ls.PutSource(SourceConfig{Name: "noisy", Type: "syslog", Enabled: true})
	c := New(ls, func(string) float64 { return 0.2 }) // poor parse rate
	c.now = func() time.Time { return t0 }
	fs, _ := c.Collect(context.Background(), toTarget("noisy"))
	found := false
	for _, f := range fs {
		if f.Check == "ingest.parse_rate" {
			found = true
		}
	}
	if !found {
		t.Errorf("a low parse rate should surface a finding")
	}
}

func TestSQLiteRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLiteStore(db)
	if err != nil {
		t.Fatal(err)
	}
	s.PutSource(SourceConfig{Name: "auth", Type: "file", Params: map[string]string{"path": "/var/log/auth.log"}, Enabled: true})
	got, ok, err := s.GetSource("auth")
	if err != nil || !ok {
		t.Fatalf("get source: ok=%v err=%v", ok, err)
	}
	if got.Params["path"] != "/var/log/auth.log" || !got.Enabled {
		t.Errorf("source round-trip lost data: %+v", got)
	}
	s.UpsertDetection(DetectionRecord{Key: "brute|z", SourceID: "auth", Check: "detect.brute_force",
		Severity: "high", Title: "t", Count: 9, FirstAt: t0, LastAt: t0})
	dets, _ := s.ListDetections("auth")
	if len(dets) != 1 || dets[0].Count != 9 {
		t.Errorf("detection round-trip: %+v", dets)
	}
	// delete source cascades to its detections
	s.DeleteSource("auth")
	if d, _ := s.ListDetections("auth"); len(d) != 0 {
		t.Errorf("deleting a source should remove its detections")
	}
}

func toTarget(name string) core.Target { return core.Target{Raw: name, Canonical: name} }
