package logingest

import (
	"os"
	"strings"
	"testing"
	"time"
)

var vnow = time.Date(2026, 10, 28, 11, 0, 0, 0, time.UTC)

func TestWazuhAlertFromRealCapture(t *testing.T) {
	b, err := os.ReadFile("testdata/wazuh_sshd_5710.txt")
	if err != nil {
		t.Fatal(err)
	}
	e := ParseSyslog(strings.TrimSpace(string(b)), vnow)
	if e.Vendor != "wazuh" || e.VendorRule != "5710" || e.VendorLevel != 5 {
		t.Fatalf("vendor fields: %+v", e)
	}
	if e.SrcIP != "203.0.113.50" || e.User != "admin" || e.Auth != AuthFailure {
		t.Fatalf("actor fields: src=%q user=%q auth=%v", e.SrcIP, e.User, e.Auth)
	}
	if e.Host != "web01" {
		t.Fatalf("host = %q, want the originating host, not the manager", e.Host)
	}
	if !strings.HasPrefix(e.Message, "wazuh rule 5710 (level 5): sshd: Attempt to login using a non-existent user | ") {
		t.Fatalf("message %q", e.Message)
	}
	if !e.Parsed {
		t.Fatal("not marked parsed")
	}
}

func TestWazuhAggregateIsNotAnotherFailure(t *testing.T) {
	b, err := os.ReadFile("testdata/wazuh_brute.txt")
	if err != nil {
		t.Fatal(err)
	}
	e := ParseSyslog(strings.TrimSpace(string(b)), vnow)
	if e.VendorLevel != 10 || e.SrcIP != "203.0.113.50" {
		t.Fatalf("%+v", e)
	}
	if e.Auth == AuthFailure {
		t.Fatal("the brute-force aggregate must not count as one more failed login")
	}
	if e.Severity != 3 {
		t.Fatalf("level 10 should map to syslog err (3), got %d", e.Severity)
	}
}

func TestWazuhEchoOfHexwardFindingIgnored(t *testing.T) {
	line := `<132>Oct 28 10:58:43 mgr ossec: {"rule":{"level":10,"id":"100511","description":"Hexward rulehawk: high"},"data":{"srcip":"198.51.100.4"}}`
	e := ParseSyslog(line, vnow)
	if e.Vendor != "wazuh" || e.SrcIP != "" {
		t.Fatalf("echo must parse but carry no actor: %+v", e)
	}
}

func TestNonWazuhJSONLeftAlone(t *testing.T) {
	e := ParseSyslog(`<134>Oct 28 10:58:43 app1 myapp: {"rule":{"id":"x"},"note":"from 192.0.2.1"}`, vnow)
	if e.Vendor != "" {
		t.Fatalf("a JSON line from another program is not a Wazuh alert: %+v", e)
	}
}

func TestHFSFindingRewrittenForDetectors(t *testing.T) {
	line := `<130>1 2026-10-28T10:59:00.000Z decoy-host hexward 77 finding - {"schema":"hexward.finding/1","event":"opened","ts":"2026-10-28T10:59:00Z","product":"decoy","src_ip":"203.0.113.50","finding":{"fingerprint":"f","check":"decoy.token","title":"Canary token opened","target":"hr-share","severity":"critical","severity_num":10,"status":"open"}}`
	e := ParseSyslog(line, vnow)
	if e.Vendor != "hexward" || e.SrcIP != "203.0.113.50" {
		t.Fatalf("%+v", e)
	}
	for _, want := range []string{"product=decoy", "severity=critical", "check=decoy.token", "status=open", "src=203.0.113.50"} {
		if !strings.Contains(e.Message, want) {
			t.Errorf("message lacks %q: %s", want, e.Message)
		}
	}
	resolved := strings.Replace(line, `"event":"opened"`, `"event":"resolved"`, 1)
	if r := ParseSyslog(resolved, vnow); !strings.Contains(r.Message, "status=resolved") {
		t.Fatalf("resolved: %s", r.Message)
	}
}
