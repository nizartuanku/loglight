package logingest

import (
	"regexp"
	"strconv"
	"strings"
)

// extractFields fills the structured fields detectors key on, from the message
// (and app) of an already-framed Event. It recognises the common shapes a small
// environment produces: OpenSSH, sudo/PAM, generic "failed/accepted" auth,
// Windows security events (forwarded via syslog), nginx/web access, and
// firewall/flow lines carrying byte counts. It is best-effort: anything it can't
// classify leaves Auth=None and the line still flows as raw context.
func extractFields(e *Event) {
	msg := e.Message
	if msg == "" {
		msg = e.Raw
	}
	low := strings.ToLower(msg)

	// Source IP (first IP-looking token after "from"/"rhost", else any IP).
	if ip := findSrcIP(msg); ip != "" {
		e.SrcIP = ip
	}
	// User.
	if u := findUser(msg); u != "" {
		e.User = u
	}
	// Account-creation lines often name the account as "name=<user>".
	if e.User == "" {
		if m := reNameKV.FindStringSubmatch(msg); m != nil {
			e.User = m[1]
		}
	}

	// Windows security events (forwarded). Event IDs are the reliable signal.
	switch {
	case containsEventID(msg, "4625"):
		e.Auth = AuthFailure
	case containsEventID(msg, "4624"):
		e.Auth = AuthSuccess
	case containsEventID(msg, "4720") || containsEventID(msg, "4728") || containsEventID(msg, "4732"):
		e.Action = "new_admin"
	}

	// Unix auth shapes (OpenSSH, PAM, login).
	if e.Auth == AuthNone {
		switch {
		case strings.Contains(low, "failed password"),
			strings.Contains(low, "authentication failure"),
			strings.Contains(low, "invalid user"),
			strings.Contains(low, "failed publickey"),
			strings.Contains(low, "permission denied"):
			e.Auth = AuthFailure
		case strings.Contains(low, "accepted password"),
			strings.Contains(low, "accepted publickey"),
			strings.Contains(low, "session opened for user"):
			e.Auth = AuthSuccess
		}
	}

	// New privileged account / group change (Unix). The program name ("useradd")
	// is often parsed into App, so consider both App and the message.
	if e.Action == "" {
		appLow := strings.ToLower(e.App)
		if (appLow == "useradd" || strings.Contains(low, "useradd")) &&
			(strings.Contains(low, "new user") || strings.Contains(low, "new account")) {
			e.Action = "new_admin"
		}
		if (strings.Contains(low, "usermod") || strings.Contains(low, "gpasswd")) &&
			(strings.Contains(low, "sudo") || strings.Contains(low, "wheel") || strings.Contains(low, "admin")) {
			e.Action = "new_admin"
		}
		if strings.Contains(low, "to group 'sudo'") || strings.Contains(low, "to group 'wheel'") {
			e.Action = "new_admin"
		}
	}

	// Destination port (firewall/flow lines: "DPT=22" or "dport 22" or ":443").
	if p := findDstPort(msg); p != 0 {
		e.DstPort = p
	}
	// Egress bytes (firewall/proxy accounting: "bytes=12345" / "OUT=... BYTES=..").
	if b := findBytes(msg); b != 0 {
		e.BytesOut = b
	}

	// Coarse firewall action.
	if e.Action == "" {
		switch {
		case strings.Contains(low, " deny") || strings.Contains(low, "blocked") || strings.Contains(low, "drop"):
			e.Action = "deny"
		case strings.Contains(low, " accept") || strings.Contains(low, "allow") || strings.Contains(low, "pass "):
			e.Action = "accept"
		}
	}
}

var (
	reFrom    = regexp.MustCompile(`(?i)(?:from|rhost=|src=|client=)\s*[:\[]?([0-9a-fA-F\.:]+)`)
	reAnyIP   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reUser    = regexp.MustCompile(`(?i)(?:for(?: invalid user)?|user=?|account(?: name)?:?)\s+"?([A-Za-z0-9._\-\\$]+)"?`)
	reDPTeq   = regexp.MustCompile(`(?i)(?:DPT=|dport[ =])(\d{1,5})`)
	reBytes   = regexp.MustCompile(`(?i)(?:bytes[=:]?|BYTES=|sent[=:]?)\s*(\d{2,})`)
	reNameKV  = regexp.MustCompile(`(?i)\bname=["']?([A-Za-z0-9._\-\\$]+)`)
	reEventID = func(id string) *regexp.Regexp {
		return regexp.MustCompile(`(?i)(?:event\s*id[:=]?\s*|eventid[:=]?\s*|\b)` + id + `\b`)
	}
)

func findSrcIP(msg string) string {
	if m := reFrom.FindStringSubmatch(msg); m != nil && looksLikeIP(m[1]) {
		return strings.Trim(m[1], "[]")
	}
	if m := reAnyIP.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return ""
}

func findUser(msg string) string {
	if m := reUser.FindStringSubmatch(msg); m != nil {
		u := strings.Trim(m[1], `"`)
		if u != "" && !looksLikeIP(u) {
			return u
		}
	}
	return ""
}

func findDstPort(msg string) int {
	if m := reDPTeq.FindStringSubmatch(msg); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 0
}

func findBytes(msg string) int64 {
	if m := reBytes.FindStringSubmatch(msg); m != nil {
		if n, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func containsEventID(msg, id string) bool {
	// Only treat a bare number as an event id when the line mentions Windows/EventID
	// context, to avoid matching a random "4625" elsewhere.
	low := strings.ToLower(msg)
	if !strings.Contains(low, "event") && !strings.Contains(low, "microsoft-windows") && !strings.Contains(low, "security") {
		return false
	}
	return reEventID(id).MatchString(msg)
}

// ParseLine is the generic entry for non-syslog sources (file/journald/docker):
// there is no <PRI> framing, so treat the whole line as the message and run the
// same field extraction. srcType/srcID label the origin.
func ParseLine(srcType SourceType, srcID, host, app, line string) Event {
	e := Event{
		Source: srcType, SourceID: srcID, Host: host, App: app,
		Severity: -1, Message: strings.TrimRight(line, "\r\n"),
		Raw: line, Parsed: true,
	}
	extractFields(&e)
	return e
}
