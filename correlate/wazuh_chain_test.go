package correlate

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/loglight/detect"
	"github.com/nizartuanku/loglight/logingest"
)

// TestWazuhBruteForceThenDecoyTripIsOneIncident is the cross-system chain the
// integration exists for: Wazuh relays sshd failures from one address, Loglight
// counts them as a brute-force stage, and a Decoy trip from the same address
// then completes a single incident instead of two unrelated alerts.
func TestWazuhBruteForceThenDecoyTripIsOneIncident(t *testing.T) {
	sample, err := os.ReadFile("../logingest/testdata/wazuh_sshd_5710.txt")
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimSpace(string(sample))
	start := time.Date(2026, 10, 28, 10, 58, 0, 0, time.UTC)

	det := detect.NewEngine(detect.Config{})
	corr := New(10*time.Minute, 15*time.Minute)

	brute := false
	for i := 0; i < 10; i++ {
		at := start.Add(time.Duration(i) * 2 * time.Second)
		line := strings.Replace(base, "Oct 28 10:58:43", at.Format(time.Stamp), 1)
		e := logingest.ParseSyslog(line, at)
		e.Timestamp = at
		for _, d := range det.Observe(e) {
			corr.ObserveDetection(d)
			if d.Kind == detect.KindBruteForce {
				brute = true
			}
		}
	}
	if !brute {
		t.Fatal("ten Wazuh-relayed sshd failures from one address did not fire Loglight's brute-force detector")
	}

	trip := start.Add(90 * time.Second)
	hfs := fmt.Sprintf(`<130>1 %s decoy-host hexward 77 finding - {"schema":"hexward.finding/1","event":"opened","ts":"%s","product":"decoy","src_ip":"203.0.113.50","finding":{"fingerprint":"f","check":"decoy.token","title":"Canary token opened","target":"hr-share","severity":"critical","severity_num":10,"status":"open"}}`,
		trip.Format("2006-01-02T15:04:05.000Z"), trip.Format(time.RFC3339))
	e := logingest.ParseSyslog(hfs, trip)
	e.Timestamp = trip
	var inc *Incident
	for _, d := range det.Observe(e) {
		corr.ObserveDetection(d)
		if got := corr.ObserveSentinelFinding(d); got != nil {
			inc = got
		}
	}
	if inc == nil {
		t.Fatal("Decoy trip after the Wazuh brute force did not raise an incident")
	}
	if inc.Actor != "203.0.113.50" {
		t.Fatalf("incident actor %q", inc.Actor)
	}
	stages := strings.Join(inc.Stages, ",")
	if !strings.Contains(stages, "brute_force") || !strings.Contains(stages, "deception") {
		t.Fatalf("stages %q, want brute_force then deception", stages)
	}
}
