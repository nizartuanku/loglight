// Package detect runs curated, windowed detectors over the normalized Event
// stream from logingest. Each detector encodes what an analyst watches for —
// brute force, scanning, exfiltration, a new admin account, an auth-failure
// spike — with tunable thresholds and bounded per-actor state (no "hold all
// logs in RAM"). Detectors are pure over their state: feed an Event, get zero or
// more Detections. The correlator and the loglight Collector consume Detections.
package detect

import (
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

// Kind identifies a detector's output.
type Kind string

const (
	KindBruteForce Kind = "brute_force"
	KindScan       Kind = "scan"
	KindExfil      Kind = "exfil"
	KindNewAdmin   Kind = "new_admin"
	KindAuthSpike  Kind = "auth_spike"
	// KindSentinel is a finding another Sentinel product sent us over syslog.
	KindSentinel Kind = "sentinel_finding"
)

// Severity mirrors core severities as plain strings (loglight maps to core).
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

// Detection is one fired detector result. Key is an index/time-free stable
// discriminator (actor+kind+target) so the same ongoing condition keeps its
// identity across re-fires and restarts — loglight fingerprints on it.
type Detection struct {
	Kind     Kind
	Severity Severity
	Actor    string // src IP or user:<name> or host
	Target   string // affected host/service, if any
	User     string
	Title    string
	Detail   string
	Count    int
	FirstAt  time.Time
	LastAt   time.Time
	Evidence []string // sample raw lines
	Key      string
}

// Config holds tunable thresholds. Zero values fall back to sane defaults via
// withDefaults, so callers can set only what they care about.
type Config struct {
	BruteFailures int           // failures within BruteWindow to fire (default 8)
	BruteWindow   time.Duration // default 60s
	ScanPorts     int           // distinct dst ports within ScanWindow to fire (default 10)
	ScanWindow    time.Duration // default 30s
	ExfilBytes    int64         // absolute egress floor within ExfilWindow (default 50MB)
	ExfilFactor   float64       // multiple over rolling baseline to fire (default 4x)
	ExfilWindow   time.Duration // default 60s
	SpikeMin      int           // service-wide failures (from ≥3 sources) to fire (default 20)
	SpikeWindow   time.Duration // default 60s
	Cooldown      time.Duration // per-key silence after firing (default 5m)
	EvidenceMax   int           // sample lines kept per detection (default 5)
}

func (c Config) withDefaults() Config {
	if c.BruteFailures == 0 {
		c.BruteFailures = 8
	}
	if c.BruteWindow == 0 {
		c.BruteWindow = 60 * time.Second
	}
	if c.ScanPorts == 0 {
		c.ScanPorts = 10
	}
	if c.ScanWindow == 0 {
		c.ScanWindow = 30 * time.Second
	}
	if c.ExfilBytes == 0 {
		c.ExfilBytes = 50 << 20
	}
	if c.ExfilFactor == 0 {
		c.ExfilFactor = 4
	}
	if c.ExfilWindow == 0 {
		c.ExfilWindow = 60 * time.Second
	}
	if c.SpikeMin == 0 {
		c.SpikeMin = 20
	}
	if c.SpikeWindow == 0 {
		c.SpikeWindow = 60 * time.Second
	}
	if c.Cooldown == 0 {
		c.Cooldown = 5 * time.Minute
	}
	if c.EvidenceMax == 0 {
		c.EvidenceMax = 5
	}
	return c
}

// Engine holds all detectors and feeds each Event to them. Observe returns any
// detections the event triggered. Not safe for concurrent Observe calls — the
// ingest pipeline serialises events through a single goroutine.
type Engine struct {
	cfg       Config
	brute     *bruteForce
	scan      *scan
	exfil     *exfil
	newAdmin  *newAdmin
	authSpike *authSpike
	sentinel  *sentinelFinding
}

// NewEngine builds the detector engine with the given (defaulted) config.
func NewEngine(cfg Config) *Engine {
	c := cfg.withDefaults()
	return &Engine{
		cfg:       c,
		brute:     newBruteForce(c),
		scan:      newScan(c),
		exfil:     newExfil(c),
		newAdmin:  newNewAdmin(c),
		authSpike: newAuthSpike(c),
		sentinel:  newSentinelFinding(c),
	}
}

// Observe feeds one event to every detector and returns fired detections.
func (e *Engine) Observe(ev logingest.Event) []Detection {
	var out []Detection
	for _, d := range []interface {
		observe(logingest.Event) *Detection
	}{
		e.brute, e.scan, e.exfil, e.newAdmin, e.authSpike, e.sentinel,
	} {
		if det := d.observe(ev); det != nil {
			out = append(out, *det)
		}
	}
	return out
}
