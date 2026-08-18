// Package logingest turns raw log lines from many sources — syslog, tailed
// files, journald, Docker, Windows-via-syslog — into one normalized Event that
// the detectors and correlator consume. Adding a source is a parser to Event;
// every detector then works over it unchanged, the same open-core idea as
// RuleHawk's vendor-neutral rule model.
package logingest

import (
	"net"
	"strings"
	"time"
)

// SourceType enumerates the ingest source kinds (v0: all of them).
type SourceType string

const (
	SourceSyslog   SourceType = "syslog"
	SourceFile     SourceType = "file"
	SourceJournald SourceType = "journald"
	SourceDocker   SourceType = "docker"
	SourceWindows  SourceType = "windows" // forwarded to syslog by NXLog/winlogbeat
)

// AuthOutcome is the parsed result of an authentication-related line.
type AuthOutcome string

const (
	AuthNone    AuthOutcome = ""        // not an auth line
	AuthFailure AuthOutcome = "failure" // failed login / rejected credential
	AuthSuccess AuthOutcome = "success" // accepted login
)

// Event is the normalized unit every detector consumes. Parsers fill what they
// can and always keep Raw; unknown fields stay zero. Fields deliberately favour
// the entities detections key on (actor IP, user, host, ports, bytes).
type Event struct {
	Timestamp time.Time
	Source    SourceType // which ingest source produced it
	SourceID  string     // the configured source instance (e.g. "auth-file", "fw-syslog")
	Host      string     // originating host / hostname field
	App       string     // program / unit / container name
	Severity  int        // syslog severity 0..7 (0 = emerg); -1 if unknown
	Message   string     // the human message part

	// Structured, best-effort extractions used by detectors:
	Auth     AuthOutcome // failure/success/none
	User     string      // account the line concerns, if any
	SrcIP    string      // actor / source address, if any
	DstPort  int         // destination port, if any (0 = none)
	BytesOut int64       // egress bytes, if the line reports them (0 = none)
	Action   string      // "new_admin" | "accept" | "deny" | "" — coarse tag for detectors

	Raw    string // the original line (always kept)
	Parsed bool   // false → parser did not understand structure (counts toward parse-rate)
}

// Actor returns the best identity to key detections on: the source IP if known,
// else the user, else the host. Never empty for a parsed event that names any.
func (e Event) Actor() string {
	if e.SrcIP != "" {
		return e.SrcIP
	}
	if e.User != "" {
		return "user:" + e.User
	}
	return e.Host
}

// isPrivateIP is used by egress detection to distinguish internal vs outbound.
func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	if p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() {
		return true
	}
	return false
}

// looksLikeIP is a cheap guard before net.ParseIP for token scanning.
func looksLikeIP(s string) bool {
	if s == "" {
		return false
	}
	return net.ParseIP(strings.Trim(s, "[]")) != nil
}
