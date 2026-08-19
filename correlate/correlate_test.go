package correlate

import (
	"fmt"
	"testing"
	"time"

	"github.com/nizartuanku/loglight/detect"
	"github.com/nizartuanku/loglight/logingest"
)

var t0 = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func scanDet(actor string, at time.Time) detect.Detection {
	return detect.Detection{Kind: detect.KindScan, Actor: actor, Target: "web01", LastAt: at, Title: "Port scan"}
}
func bruteDet(actor string, at time.Time) detect.Detection {
	return detect.Detection{Kind: detect.KindBruteForce, Actor: actor, Target: "web01", LastAt: at, Title: "Brute force"}
}

func TestFullKillChainIsCritical(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	c.ObserveDetection(scanDet("203.0.113.9", t0))
	c.ObserveDetection(bruteDet("203.0.113.9", t0.Add(1*time.Minute)))
	inc := c.ObserveSuccess("203.0.113.9", "web01", "deploy", t0.Add(2*time.Minute), "Accepted password")
	if inc == nil {
		t.Fatal("scan→brute→success should produce an incident")
	}
	if inc.Severity != "critical" {
		t.Errorf("full chain should be critical, got %s", inc.Severity)
	}
	if len(inc.Stages) != 3 || inc.Stages[0] != "scan" {
		t.Errorf("stages wrong: %v", inc.Stages)
	}
	if len(inc.Members) != 3 {
		t.Errorf("want 3 members, got %d", len(inc.Members))
	}
}

func TestBruteThenSuccessIsHigh(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	c.ObserveDetection(bruteDet("198.51.100.7", t0))
	inc := c.ObserveSuccess("198.51.100.7", "web01", "root", t0.Add(30*time.Second), "Accepted")
	if inc == nil || inc.Severity != "high" {
		t.Fatalf("brute→success should be a high incident, got %+v", inc)
	}
	if len(inc.Stages) != 2 {
		t.Errorf("want 2 stages, got %v", inc.Stages)
	}
}

func TestSuccessWithoutBruteIsNoIncident(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	if inc := c.ObserveSuccess("10.0.0.5", "web01", "alice", t0, "Accepted"); inc != nil {
		t.Fatal("a normal login must not create an incident")
	}
}

func TestBruteTooLongAgoDoesNotLink(t *testing.T) {
	c := New(5*time.Minute, 15*time.Minute)
	c.ObserveDetection(bruteDet("203.0.113.9", t0))
	if inc := c.ObserveSuccess("203.0.113.9", "web01", "deploy", t0.Add(10*time.Minute), "Accepted"); inc != nil {
		t.Fatal("success outside the window should not link to the old brute force")
	}
}

func TestCooldownSuppressesRepeat(t *testing.T) {
	c := New(10*time.Minute, 30*time.Minute)
	c.ObserveDetection(bruteDet("203.0.113.9", t0))
	if inc := c.ObserveSuccess("203.0.113.9", "web01", "deploy", t0.Add(1*time.Minute), "Accepted"); inc == nil {
		t.Fatal("first chain should fire")
	}
	// New brute + success shortly after; cooldown should suppress.
	c.ObserveDetection(bruteDet("203.0.113.9", t0.Add(2*time.Minute)))
	if inc := c.ObserveSuccess("203.0.113.9", "web01", "deploy", t0.Add(3*time.Minute), "Accepted"); inc != nil {
		t.Fatal("second chain within cooldown should be suppressed")
	}
}

func TestScanTooEarlyStillHighNotCritical(t *testing.T) {
	// Scan far before the brute (outside window) → not part of the chain; the
	// brute→success still escalates, but only to high.
	c := New(5*time.Minute, 15*time.Minute)
	c.ObserveDetection(scanDet("203.0.113.9", t0))
	c.ObserveDetection(bruteDet("203.0.113.9", t0.Add(20*time.Minute)))
	inc := c.ObserveSuccess("203.0.113.9", "web01", "deploy", t0.Add(21*time.Minute), "Accepted")
	if inc == nil || inc.Severity != "high" {
		t.Fatalf("stale scan should not make it critical, got %+v", inc)
	}
}

// Regression: the whole chain, driven from raw log lines through ParseLine the
// way a tailed file actually feeds it — not from hand-built Detections with
// hand-set timestamps.
//
// This is the shape the original bug hid in: ParseLine left Event.Timestamp at
// the zero value, so Detection.LastAt was zero, so the correlator's
// `!scanAt.IsZero()` gate never opened and the incident silently degraded from
// CRITICAL "scan → brute force → successful login" to a HIGH two-stage one. The
// unit tests above all passed throughout, because they never went through
// ParseLine.
func TestFullKillChainFromRawFileLines(t *testing.T) {
	const ip = "198.51.100.66"
	eng := detect.NewEngine(detect.Config{})
	c := New(10*time.Minute, 15*time.Minute)

	feed := func(line string, at time.Time) *Incident {
		e := logingest.ParseLine(logingest.SourceFile, "auth-file", "web01", "sshd", line, at)
		if e.Timestamp.IsZero() {
			t.Fatalf("ParseLine produced a zero timestamp for %q", line)
		}
		for _, d := range eng.Observe(e) {
			c.ObserveDetection(d)
		}
		if e.Auth == logingest.AuthSuccess {
			return c.ObserveSuccess(e.Actor(), e.Host, e.User, e.Timestamp, e.Raw)
		}
		return nil
	}

	// Stage 1 — port scan: 10 distinct ports inside the scan window.
	for i, port := range []int{21, 22, 23, 25, 80, 110, 143, 443, 445, 3306} {
		feed(fmt.Sprintf("web01 kernel: [UFW BLOCK] SRC=%s DST=10.20.4.11 SPT=51%03d DPT=%d", ip, i, port),
			t0.Add(time.Duration(i)*time.Second))
	}
	// Stage 2 — brute force: 8 failures inside the brute window.
	for i, user := range []string{"admin", "root", "deploy", "oracle", "postgres", "jenkins", "git", "backup"} {
		feed(fmt.Sprintf("web01 sshd[%d]: Failed password for invalid user %s from %s port %d ssh2",
			2200+i, user, ip, 40000+i), t0.Add(time.Minute).Add(time.Duration(i)*time.Second))
	}
	// Stage 3 — the login that finally works.
	inc := feed(fmt.Sprintf("web01 sshd[2290]: Accepted password for deploy from %s port 40099 ssh2", ip),
		t0.Add(2*time.Minute))

	if inc == nil {
		t.Fatal("scan → brute force → success should produce an incident")
	}
	if inc.Severity != "critical" {
		t.Errorf("full three-stage chain must be critical, got %q (stages %v)", inc.Severity, inc.Stages)
	}
	if len(inc.Stages) != 3 || inc.Stages[0] != "scan" {
		t.Errorf("want scan→brute_force→success, got %v", inc.Stages)
	}
	if inc.FirstAt.IsZero() || inc.LastAt.IsZero() {
		t.Errorf("incident carries zero times: first=%v last=%v", inc.FirstAt, inc.LastAt)
	}
}

func sentinelDet(actor string, at time.Time) detect.Detection {
	return detect.Detection{
		Kind: detect.KindSentinel, Severity: detect.SevCritical, Actor: actor,
		Target: "web01", FirstAt: at, LastAt: at,
		Title: "decoy reported trap.tripped from " + actor,
	}
}

// The Suite's whole claim: a Decoy trip from an address Loglight already saw
// scanning is one story, not two blips.
func TestSentinelTripAfterScanIsOneIncident(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	c.ObserveDetection(scanDet("198.51.100.66", t0))
	inc := c.ObserveSentinelFinding(sentinelDet("198.51.100.66", t0.Add(90*time.Second)))
	if inc == nil {
		t.Fatal("scan then bait touched by the same actor must correlate")
	}
	if inc.Severity != "critical" {
		t.Errorf("want critical, got %q", inc.Severity)
	}
	if len(inc.Stages) != 2 || inc.Stages[0] != "scan" || inc.Stages[1] != "deception" {
		t.Errorf("stages wrong: %v", inc.Stages)
	}
	if !inc.FirstAt.Equal(t0) {
		t.Errorf("incident should start at the scan, got %v", inc.FirstAt)
	}
}

// A trip on its own is not correlated here: the product that raised it already
// alerted, and echoing it would recreate the duplicate-alert problem.
func TestSentinelTripAloneIsNotAnIncident(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	if inc := c.ObserveSentinelFinding(sentinelDet("203.0.113.5", t0)); inc != nil {
		t.Fatalf("a lone finding must not become an incident: %q", inc.Title)
	}
}

// Recon from long ago must not be stitched onto today's trip.
func TestSentinelTripOutsideWindowDoesNotCorrelate(t *testing.T) {
	c := New(10*time.Minute, 15*time.Minute)
	c.ObserveDetection(scanDet("198.51.100.66", t0))
	if inc := c.ObserveSentinelFinding(sentinelDet("198.51.100.66", t0.Add(2*time.Hour))); inc != nil {
		t.Fatalf("a scan two hours earlier must not correlate: %q", inc.Title)
	}
}
