package logingest

import (
	"testing"
	"time"
)

var now = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func TestSyslog3164_SSHFailure(t *testing.T) {
	line := `<38>Aug 17 11:22:33 web01 sshd[2114]: Failed password for invalid user admin from 203.0.113.9 port 55344 ssh2`
	e := ParseSyslog(line, now)
	if !e.Parsed {
		t.Fatal("should parse RFC3164 framing")
	}
	if e.Host != "web01" || e.App != "sshd" {
		t.Errorf("host/app: %q/%q", e.Host, e.App)
	}
	if e.Auth != AuthFailure {
		t.Errorf("want auth failure, got %q", e.Auth)
	}
	if e.SrcIP != "203.0.113.9" {
		t.Errorf("want srcIP 203.0.113.9, got %q", e.SrcIP)
	}
	if e.User != "admin" {
		t.Errorf("want user admin, got %q", e.User)
	}
	if e.Severity != 6 { // 38 % 8
		t.Errorf("want severity 6, got %d", e.Severity)
	}
}

func TestSyslog3164_SSHSuccess(t *testing.T) {
	line := `<38>Aug 17 11:25:01 web01 sshd[2120]: Accepted password for deploy from 203.0.113.9 port 55990 ssh2`
	e := ParseSyslog(line, now)
	if e.Auth != AuthSuccess {
		t.Errorf("want success, got %q", e.Auth)
	}
	if e.User != "deploy" || e.SrcIP != "203.0.113.9" {
		t.Errorf("user/ip: %q/%q", e.User, e.SrcIP)
	}
}

func TestSyslog5424(t *testing.T) {
	line := `<34>1 2026-08-17T11:30:00Z fw01 kernel - - - IN=eth0 SRC=198.51.100.7 DPT=22 bytes=64 deny`
	e := ParseSyslog(line, now)
	if !e.Parsed {
		t.Fatal("should parse RFC5424")
	}
	if e.Host != "fw01" || e.App != "kernel" {
		t.Errorf("host/app: %q/%q", e.Host, e.App)
	}
	if !e.Timestamp.Equal(time.Date(2026, 8, 17, 11, 30, 0, 0, time.UTC)) {
		t.Errorf("timestamp: %v", e.Timestamp)
	}
	if e.SrcIP != "198.51.100.7" {
		t.Errorf("srcIP: %q", e.SrcIP)
	}
	if e.DstPort != 22 {
		t.Errorf("dport: %d", e.DstPort)
	}
	if e.Action != "deny" {
		t.Errorf("action: %q", e.Action)
	}
}

func TestFirewallBytesEgress(t *testing.T) {
	line := `<134>Aug 17 12:00:00 fw01 filterlog: pass out OUT=eth0 SRC=10.0.0.5 DST=185.2.3.4 bytes=5242880`
	e := ParseSyslog(line, now)
	if e.BytesOut != 5242880 {
		t.Errorf("want bytes 5242880, got %d", e.BytesOut)
	}
}

func TestWindowsForwarded_4625(t *testing.T) {
	line := `<13>Aug 17 12:01:00 dc01 Security: Microsoft-Windows-Security-Auditing EventID 4625 An account failed to log on. Account Name: bob Source Network Address: 198.51.100.23`
	e := ParseSyslog(line, now)
	if e.Auth != AuthFailure {
		t.Errorf("Windows 4625 should be auth failure, got %q", e.Auth)
	}
	if e.SrcIP != "198.51.100.23" {
		t.Errorf("want srcIP from Windows event, got %q", e.SrcIP)
	}
}

func TestWindowsForwarded_4720NewAccount(t *testing.T) {
	line := `<13>Aug 17 12:02:00 dc01 Security: Microsoft-Windows-Security-Auditing EventID 4720 A user account was created. Account Name: eviladmin`
	e := ParseSyslog(line, now)
	if e.Action != "new_admin" {
		t.Errorf("4720 should tag new_admin, got %q", e.Action)
	}
}

func TestNewAdminUnix(t *testing.T) {
	line := `<38>Aug 17 12:03:00 web01 useradd[9001]: new user: name=backdoor, UID=0, GID=0, home=/root`
	e := ParseSyslog(line, now)
	if e.Action != "new_admin" {
		t.Errorf("useradd new user should tag new_admin, got %q", e.Action)
	}
}

func TestUnframedLineStillExtracts(t *testing.T) {
	// A bare message forwarded without <PRI> header must still yield fields.
	e := ParseSyslog(`Failed password for root from 203.0.113.99 port 22 ssh2`, now)
	if e.Auth != AuthFailure || e.SrcIP != "203.0.113.99" {
		t.Errorf("unframed line lost fields: auth=%q ip=%q", e.Auth, e.SrcIP)
	}
}

func TestParseLineGeneric(t *testing.T) {
	e := ParseLine(SourceDocker, "app-container", "host1", "web", `10.0.0.9 - - "POST /login" 401 accepted password? no`)
	if e.Source != SourceDocker || e.SourceID != "app-container" {
		t.Errorf("source labelling wrong: %+v", e)
	}
	if e.SrcIP != "10.0.0.9" {
		t.Errorf("want srcIP 10.0.0.9, got %q", e.SrcIP)
	}
}

func TestActor(t *testing.T) {
	if got := (Event{SrcIP: "1.2.3.4", User: "x", Host: "h"}).Actor(); got != "1.2.3.4" {
		t.Errorf("actor should prefer srcIP, got %q", got)
	}
	if got := (Event{User: "alice", Host: "h"}).Actor(); got != "user:alice" {
		t.Errorf("actor should fall back to user, got %q", got)
	}
	if got := (Event{Host: "h"}).Actor(); got != "h" {
		t.Errorf("actor should fall back to host, got %q", got)
	}
}
