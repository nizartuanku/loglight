package detect

import (
	"testing"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

var base = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func failEvent(ip string, at time.Time) logingest.Event {
	return logingest.Event{Timestamp: at, Auth: logingest.AuthFailure, SrcIP: ip, Host: "web01", App: "sshd", Raw: "Failed password from " + ip}
}

func firstOf(dets []Detection, k Kind) *Detection {
	for i := range dets {
		if dets[i].Kind == k {
			return &dets[i]
		}
	}
	return nil
}

func TestBruteForceFires(t *testing.T) {
	e := NewEngine(Config{BruteFailures: 5, BruteWindow: time.Minute})
	var fired *Detection
	for i := 0; i < 5; i++ {
		for _, d := range e.Observe(failEvent("203.0.113.9", base.Add(time.Duration(i)*time.Second))) {
			if d.Kind == KindBruteForce {
				fired = &d
			}
		}
	}
	if fired == nil {
		t.Fatal("brute force should fire at 5 failures")
	}
	if fired.Actor != "203.0.113.9" || fired.Count < 5 {
		t.Errorf("bad detection: %+v", fired)
	}
}

func TestBruteForceDoesNotFireBelowThreshold(t *testing.T) {
	e := NewEngine(Config{BruteFailures: 8, BruteWindow: time.Minute})
	for i := 0; i < 7; i++ {
		if d := firstOf(e.Observe(failEvent("203.0.113.9", base.Add(time.Duration(i)*time.Second))), KindBruteForce); d != nil {
			t.Fatal("should not fire below threshold")
		}
	}
}

func TestBruteForceWindowExpiry(t *testing.T) {
	// Failures spread beyond the window must not accumulate to a fire.
	e := NewEngine(Config{BruteFailures: 5, BruteWindow: 10 * time.Second})
	for i := 0; i < 8; i++ {
		if d := firstOf(e.Observe(failEvent("1.2.3.4", base.Add(time.Duration(i)*5*time.Second))), KindBruteForce); d != nil {
			t.Fatal("spread-out failures should not fire (window expiry)")
		}
	}
}

func TestScanFires(t *testing.T) {
	e := NewEngine(Config{ScanPorts: 6, ScanWindow: 30 * time.Second})
	var fired *Detection
	for p := 20; p < 26; p++ {
		ev := logingest.Event{Timestamp: base, SrcIP: "198.51.100.7", DstPort: p, Host: "fw01", Raw: "deny"}
		if d := firstOf(e.Observe(ev), KindScan); d != nil {
			fired = d
		}
	}
	if fired == nil {
		t.Fatal("scan should fire at 6 distinct ports")
	}
}

func TestScanSamePortNoFire(t *testing.T) {
	e := NewEngine(Config{ScanPorts: 5, ScanWindow: 30 * time.Second})
	for i := 0; i < 10; i++ {
		ev := logingest.Event{Timestamp: base.Add(time.Duration(i) * time.Second), SrcIP: "198.51.100.7", DstPort: 443, Host: "fw01"}
		if d := firstOf(e.Observe(ev), KindScan); d != nil {
			t.Fatal("hitting the same port repeatedly is not a scan")
		}
	}
}

func TestNewAdminFiresImmediately(t *testing.T) {
	e := NewEngine(Config{})
	ev := logingest.Event{Timestamp: base, Action: "new_admin", User: "backdoor", Host: "web01", Raw: "new user backdoor uid=0"}
	if d := firstOf(e.Observe(ev), KindNewAdmin); d == nil {
		t.Fatal("new admin should fire on first sighting")
	}
}

func TestExfilFires(t *testing.T) {
	e := NewEngine(Config{ExfilBytes: 1 << 20, ExfilFactor: 3, ExfilWindow: time.Minute})
	// Establish a low baseline, then a big spike.
	e.Observe(logingest.Event{Timestamp: base, Host: "app01", BytesOut: 1000})
	e.Observe(logingest.Event{Timestamp: base.Add(2 * time.Minute), Host: "app01", BytesOut: 2000})
	var fired *Detection
	for i := 0; i < 3; i++ {
		ev := logingest.Event{Timestamp: base.Add(4*time.Minute + time.Duration(i)*time.Second), Host: "app01", BytesOut: 20 << 20}
		if d := firstOf(e.Observe(ev), KindExfil); d != nil {
			fired = d
		}
	}
	if fired == nil {
		t.Fatal("exfil should fire on a large egress spike over baseline")
	}
}

func TestAuthSpikeFiresOnDistributedFailures(t *testing.T) {
	e := NewEngine(Config{SpikeMin: 12, SpikeWindow: time.Minute, BruteFailures: 1000})
	// 12 failures against one service from many distinct IPs (credential
	// stuffing) — below the per-IP brute threshold, but a service-level spike.
	var fired *Detection
	for i := 0; i < 12; i++ {
		ip := "203.0.113." + itoa(i+1) // distinct source each time
		ev := logingest.Event{Timestamp: base.Add(time.Duration(i) * time.Second),
			Auth: logingest.AuthFailure, Host: "web01", App: "nginx", SrcIP: ip}
		if d := firstOf(e.Observe(ev), KindAuthSpike); d != nil {
			fired = d
		}
	}
	if fired == nil {
		t.Fatal("auth spike should fire on a distributed failure surge")
	}
}

func TestAuthSpikeIgnoresSingleSource(t *testing.T) {
	// Many failures from ONE ip is brute force, not a distributed spike.
	e := NewEngine(Config{SpikeMin: 12, SpikeWindow: time.Minute, BruteFailures: 1000})
	for i := 0; i < 20; i++ {
		ev := logingest.Event{Timestamp: base.Add(time.Duration(i) * time.Second),
			Auth: logingest.AuthFailure, Host: "web01", App: "nginx", SrcIP: "203.0.113.5"}
		if d := firstOf(e.Observe(ev), KindAuthSpike); d != nil {
			t.Fatal("single-source failures should not trigger the distributed spike")
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{512: "512 B", 1536: "1.5 KB", 5 << 20: "5.0 MB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d)=%q want %q", in, got, want)
		}
	}
}
