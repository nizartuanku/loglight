package detect

import (
	"testing"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

func flowEvent(src, dst string, port int, at time.Time) logingest.Event {
	return logingest.Event{Timestamp: at, Source: logingest.SourceNetflow,
		SourceID: "flows", Host: src, SrcIP: src, DstIP: dst, DstPort: port,
		Raw: "netflow " + src + ">" + dst, Parsed: true}
}

func TestBeaconFiresOnRegularInterval(t *testing.T) {
	e := NewEngine(Config{})
	base := time.Now()
	var fired []Detection
	for i := 0; i < 10; i++ {
		at := base.Add(time.Duration(i) * 30 * time.Second) // metronome: every 30s
		fired = append(fired, e.Observe(flowEvent("192.168.1.50", "203.0.113.7", 443, at))...)
	}
	var beacons int
	for _, d := range fired {
		if d.Kind == KindBeacon {
			beacons++
			if d.Actor != "192.168.1.50" || d.Target != "203.0.113.7" || d.Severity != SevHigh {
				t.Fatalf("bad beacon detection: %+v", d)
			}
		}
	}
	if beacons != 1 {
		t.Fatalf("want exactly 1 beacon, got %d", beacons)
	}
}

func TestBeaconIgnoresIrregularAndInternal(t *testing.T) {
	e := NewEngine(Config{})
	base := time.Now()
	// Irregular gaps: 5s, 300s, 12s, 700s, ... — human browsing, not a beacon.
	gaps := []int{0, 5, 305, 317, 1017, 1030, 1600, 1610, 2400, 2410, 3000}
	for _, g := range gaps {
		for _, d := range e.Observe(flowEvent("192.168.1.60", "203.0.113.8", 443, base.Add(time.Duration(g)*time.Second))) {
			if d.Kind == KindBeacon {
				t.Fatalf("irregular traffic fired beacon: %+v", d)
			}
		}
	}
	// Internal→internal at a perfect interval (a cron, backups): never a beacon.
	for i := 0; i < 20; i++ {
		for _, d := range e.Observe(flowEvent("192.168.1.60", "192.168.1.9", 5432, base.Add(time.Duration(i)*30*time.Second))) {
			if d.Kind == KindBeacon {
				t.Fatalf("internal traffic fired beacon: %+v", d)
			}
		}
	}
}

func TestNewServiceLearnsThenFires(t *testing.T) {
	e := NewEngine(Config{NewServiceLearn: 10 * time.Minute})
	base := time.Now()
	// Learning window: ports 22 and 443 are this host's normal.
	for i, port := range []int{22, 443, 22, 443} {
		for _, d := range e.Observe(flowEvent("192.168.1.7", "192.168.1.100", port, base.Add(time.Duration(i)*time.Minute))) {
			if d.Kind == KindNewService {
				t.Fatalf("fired during learning: %+v", d)
			}
		}
	}
	// Known port after the window: silent.
	for _, d := range e.Observe(flowEvent("192.168.1.7", "192.168.1.100", 22, base.Add(20*time.Minute))) {
		if d.Kind == KindNewService {
			t.Fatalf("known port fired: %+v", d)
		}
	}
	// Never-seen port after the window: fires medium.
	var hits []Detection
	hits = append(hits, e.Observe(flowEvent("192.168.1.7", "192.168.1.100", 4444, base.Add(21*time.Minute)))...)
	var ok bool
	for _, d := range hits {
		if d.Kind == KindNewService {
			ok = true
			if d.Target != "192.168.1.100" || d.Severity != SevMedium {
				t.Fatalf("bad new-service detection: %+v", d)
			}
		}
	}
	if !ok {
		t.Fatal("new port after learning window did not fire")
	}
	// Ephemeral ports and external destinations never fire.
	for _, ev := range []logingest.Event{
		flowEvent("192.168.1.7", "192.168.1.100", 51000, base.Add(30*time.Minute)),
		flowEvent("192.168.1.7", "203.0.113.9", 4444, base.Add(31*time.Minute)),
	} {
		for _, d := range e.Observe(ev) {
			if d.Kind == KindNewService {
				t.Fatalf("should not fire: %+v (event %+v)", d, ev)
			}
		}
	}
}

func TestFlowFeedsExistingScanDetector(t *testing.T) {
	e := NewEngine(Config{})
	base := time.Now()
	var scans int
	for port := 1; port <= 12; port++ {
		for _, d := range e.Observe(flowEvent("203.0.113.66", "192.168.1.100", port, base.Add(time.Duration(port)*time.Second))) {
			if d.Kind == KindScan {
				scans++
			}
		}
	}
	if scans != 1 {
		t.Fatalf("flow-driven port scan not detected (got %d)", scans)
	}
}
