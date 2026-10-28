package logingest

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// --- Wazuh ------------------------------------------------------------------
//
// A Wazuh manager forwards alerts with <syslog_output><format>json</format>
// as RFC 3164 lines whose program is "ossec" and whose message is the alert
// JSON:
//
//	<132>Oct 28 10:58:43 wazuh-mgr ossec: {"timestamp":…,"rule":{"level":5,…},"data":{"srcip":"203.0.113.50",…}}
//
// fromWazuh turns that into an Event carrying the alert's own structured
// fields, so Loglight's detectors and correlator see the real actor, user and
// auth outcome instead of whatever the first IP in the JSON text happens to
// be. A Wazuh-relayed sshd failure then counts toward Loglight's own
// brute-force detector, and a Decoy trip from the same address completes an
// incident across both systems.

type wazuhAlert struct {
	Rule struct {
		Level       int      `json:"level"`
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Groups      []string `json:"groups"`
	} `json:"rule"`
	Agent struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
	Predecoder struct {
		Hostname string `json:"hostname"`
	} `json:"predecoder"`
	Data    map[string]any `json:"data"`
	FullLog string         `json:"full_log"`
}

// hexwardRules are the hexward-wazuh rule ids. A Hexward finding that went
// to Wazuh and comes back is already known to Loglight first-hand, so its
// echo is ignored rather than counted twice.
func isHexwardRule(id string) bool {
	n, err := strconv.Atoi(id)
	return err == nil && n >= 100500 && n <= 100599
}

func fromWazuh(e *Event) bool {
	msg := strings.TrimSpace(e.Message)
	if !strings.HasPrefix(msg, "{") || !strings.Contains(msg, `"rule"`) {
		return false
	}
	if a := strings.ToLower(e.App); a != "" && a != "ossec" && a != "wazuh" {
		return false
	}
	var a wazuhAlert
	if err := json.Unmarshal([]byte(msg), &a); err != nil || a.Rule.ID == "" {
		return false
	}
	e.Vendor, e.VendorRule, e.VendorLevel = "wazuh", a.Rule.ID, a.Rule.Level
	e.Parsed = true
	if h := firstNonEmpty(a.Predecoder.Hostname, a.Agent.Name); h != "" {
		e.Host = h
	}
	e.Severity = wazuhSyslogSeverity(a.Rule.Level)
	e.Message = fmt.Sprintf("wazuh rule %s (level %d): %s", a.Rule.ID, a.Rule.Level, a.Rule.Description)
	if a.FullLog != "" {
		e.Message += " | " + oneLine(a.FullLog)
	}
	if isHexwardRule(a.Rule.ID) {
		return true // structured, but not evidence of anything new
	}
	e.SrcIP = ipField(a.Data, "srcip", "src_ip")
	e.DstIP = ipField(a.Data, "dstip", "dst_ip")
	if p, err := strconv.Atoi(stringField(a.Data, "dstport", "dst_port")); err == nil && p > 0 && p < 65536 {
		e.DstPort = p
	}
	e.User = stringField(a.Data, "srcuser", "dstuser", "user")
	for _, g := range a.Rule.Groups {
		switch g {
		case "authentication_failed", "invalid_login":
			e.Auth = AuthFailure
		case "authentication_success":
			if e.Auth == AuthNone {
				e.Auth = AuthSuccess
			}
		}
	}
	return true
}

// wazuhSyslogSeverity maps a Wazuh rule level onto syslog severity.
func wazuhSyslogSeverity(level int) int {
	switch {
	case level >= 12:
		return 2
	case level >= 10:
		return 3
	case level >= 7:
		return 4
	case level >= 4:
		return 5
	}
	return 6
}

// --- Hexward Finding Schema ---------------------------------------------------
//
// Hexward products can send findings as HFS JSON (-syslog-format json). The
// findings detector keys on the key=value tail of the original syslog format,
// so fromHFS rewrites an HFS event into that same shape: one detector, both
// formats.

type hfsEvent struct {
	Schema  string `json:"schema"`
	Event   string `json:"event"`
	Product string `json:"product"`
	SrcIP   string `json:"src_ip"`
	Finding struct {
		Check    string `json:"check"`
		Title    string `json:"title"`
		Target   string `json:"target"`
		Severity string `json:"severity"`
	} `json:"finding"`
}

func fromHFS(e *Event) bool {
	msg := strings.TrimSpace(e.Message)
	if !strings.HasPrefix(msg, "{") || !strings.Contains(msg, `"hexward.finding/`) {
		return false
	}
	var h hfsEvent
	if err := json.Unmarshal([]byte(msg), &h); err != nil || !strings.HasPrefix(h.Schema, "hexward.finding/") {
		return false
	}
	status := "open"
	if h.Event == "resolved" {
		status = "resolved"
	}
	e.Vendor, e.VendorRule = "hexward", h.Finding.Check
	e.Parsed = true
	e.Message = fmt.Sprintf("%s | product=%s severity=%s check=%s target=%s status=%s",
		oneLine(h.Finding.Title), h.Product, h.Finding.Severity, h.Finding.Check, h.Finding.Target, status)
	if ip := net.ParseIP(h.SrcIP); ip != nil {
		e.SrcIP = ip.String()
		e.Message += " src=" + e.SrcIP
	}
	return true
}

func ipField(m map[string]any, keys ...string) string {
	s := stringField(m, keys...)
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
