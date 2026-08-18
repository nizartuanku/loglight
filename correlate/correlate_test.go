package correlate

import (
	"testing"
	"time"

	"github.com/nizartuanku/loglight/detect"
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
