// Package loglight is the sixth Sentinel product: self-hosted threat detection
// from logs. It wires logingest (normalize) → detect (windowed detectors) →
// correlate (kill-chain) into the event-driven two-write-path shape Decoy
// pioneered on Sentinel Core:
//
//   - Path A (real-time): the pipeline writes a detection/incident finding the
//     instant it fires and notifies immediately. See Sink.
//   - Path B (poll backstop): the Collector re-emits currently-active detections
//     per source so the reconcile engine auto-resolves quiet ones and recovers
//     state on restart.
//
// A target = one configured ingest source (capped by tier, restored on restart,
// exactly like RuleHawk's configs). Everything else — store, reconcile, notify,
// dashboard shell, licensing — is reused unchanged.
package loglight

import (
	"context"
	"strings"
	"time"

	"github.com/nizartuanku/loglight/core"
)

// ModuleID is the module id used across findings and the scheduler.
const ModuleID = "loglight"

// ActiveWindow is how long after its last occurrence a detection keeps being
// re-emitted by the backstop. Quiet past this, it stops emitting and the
// reconcile engine auto-resolves it.
const ActiveWindow = 30 * time.Minute

// SourceConfig is one configured ingest source. Params holds type-specific
// settings: syslog → {udp,tcp}; file → {path,host,app}; journald → {unit};
// docker → {container}; windows → {udp,tcp} (a syslog listener for a forwarder).
type SourceConfig struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"` // syslog|file|journald|docker|windows
	Params    map[string]string `json:"params"`
	Enabled   bool              `json:"enabled"`
	CreatedAt time.Time         `json:"created_at"`
}

// DetectionRecord is a persisted, currently-active detection/incident. The
// pipeline upserts one per Key (updating LastAt/Count on recurrence); the
// Collector re-emits those still inside ActiveWindow.
type DetectionRecord struct {
	Key      string
	SourceID string
	Check    string // "detect.<kind>" | "incident.killchain"
	Severity string
	Actor    string
	Target   string
	Title    string
	Detail   string
	Evidence []string
	Fix      string
	Count    int
	FirstAt  time.Time
	LastAt   time.Time
}

// Store persists source configs and active detections. SQLite in production, an
// in-memory version for tests.
type Store interface {
	PutSource(s SourceConfig) error
	GetSource(name string) (SourceConfig, bool, error)
	ListSources() ([]SourceConfig, error)
	DeleteSource(name string) error

	UpsertDetection(d DetectionRecord) error
	ListDetections(sourceID string) ([]DetectionRecord, error)
	PruneDetections(before time.Time) error
}

// Collector is Path B: the poll-driven backstop. Collect(sourceName) re-emits
// the source's active detections plus a low-severity parse-rate finding when
// ingest coverage is poor. A deleted source is never scanned, so its detections
// auto-resolve by absence.
type Collector struct {
	store    Store
	now      func() time.Time
	parseFor func(sourceID string) float64 // live parse-rate probe (nil → skip)
}

// New builds the collector. parseRate may be nil (no live pipeline, e.g. tests).
func New(s Store, parseRate func(string) float64) *Collector {
	return &Collector{store: s, now: time.Now, parseFor: parseRate}
}

// Describe returns module metadata. The real-time path carries urgency; the poll
// only reconciles health and auto-resolve, so the interval is generous.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "Loglight",
		Version:         "0.1.0",
		TargetKind:      "source",
		DefaultInterval: 5 * time.Minute,
		ResolveAfter:    1,
	}
}

// ValidateTarget canonicalises a source name. Sources are created via the
// console (which stores type + params); this registers a source with the
// scheduler for tier-cap enforcement and restart restore.
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return core.Target{}, &core.IngestError{Field: "target", Reason: "empty source name"}
	}
	return core.Target{Raw: raw, Canonical: name}, nil
}

// Collect re-emits the source's active detections and a parse-rate finding.
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	src, ok, err := c.store.GetSource(t.Canonical)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // deleted → auto-resolve everything under it
	}

	dets, err := c.store.ListDetections(t.Canonical)
	if err != nil {
		return nil, err
	}
	cutoff := c.now().Add(-ActiveWindow)
	out := make([]core.Finding, 0, len(dets)+1)
	for _, d := range dets {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if d.LastAt.Before(cutoff) {
			continue // quiet → let reconcile auto-resolve it
		}
		out = append(out, detectionFinding(d))
	}

	// Ingest-coverage honesty: a source parsing poorly is surfaced, like
	// RuleHawk's unparsed-lines finding.
	if c.parseFor != nil {
		if rate := c.parseFor(t.Canonical); rate < 0.5 {
			out = append(out, parseRateFinding(src, rate))
		}
	}
	return out, nil
}

// Diff defers to the core's fingerprint-based diff.
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }

// detectionFinding maps a persisted detection to a core.Finding. Target MUST be
// the source name (the scanned canonical) so reconcile groups it correctly.
func detectionFinding(d DetectionRecord) core.Finding {
	sev := core.Severity(d.Severity)
	if !sev.Valid() {
		sev = core.SeverityMedium
	}
	fix := d.Fix
	if strings.TrimSpace(fix) == "" {
		fix = "Investigate the actor and affected host."
	}
	ev := map[string]any{
		"actor": d.Actor, "count": d.Count,
		"first_seen": d.FirstAt.Format(time.RFC3339), "last_seen": d.LastAt.Format(time.RFC3339),
	}
	if d.Target != "" {
		ev["target"] = d.Target
	}
	if len(d.Evidence) > 0 {
		ev["evidence"] = d.Evidence
	}
	if d.Detail != "" {
		ev["detail"] = d.Detail
	}
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, d.SourceID, d.Check, d.Key),
		Target:      d.SourceID,
		Check:       d.Check,
		Title:       d.Title,
		Severity:    sev,
		Remediation: fix,
		Evidence:    ev,
	}
}

func parseRateFinding(s SourceConfig, rate float64) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, s.Name, "ingest.parse_rate", ""),
		Target:      s.Name,
		Check:       "ingest.parse_rate",
		Title:       "Low parse rate on source " + s.Name,
		Severity:    core.SeverityLow,
		Remediation: "Many lines from this source aren't being parsed — check the source type and format. Unparsed lines are stored but not analysed.",
		Evidence:    map[string]any{"parse_rate": rate, "type": s.Type},
	}
}
