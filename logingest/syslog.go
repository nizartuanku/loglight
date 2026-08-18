package logingest

import (
	"strconv"
	"strings"
	"time"
)

// ParseSyslog parses one syslog line (RFC5424 first, then RFC3164), enriches it
// with structured field extraction, and returns a normalized Event. A line that
// matches neither framing is still returned as an Event (Parsed=false at the
// framing level) but field extraction is still attempted on the whole line, so
// a bare "Failed password ..." forwarded without a proper header is not lost.
func ParseSyslog(line string, now time.Time) Event {
	line = strings.TrimRight(line, "\r\n")
	e := Event{Source: SourceSyslog, Severity: -1, Raw: line, Timestamp: now}

	if pri, rest, ok := splitPriority(line); ok {
		e.Severity = pri % 8
		if ev, ok := parse5424(rest, e); ok {
			e = ev
		} else if ev, ok := parse3164(rest, e); ok {
			e = ev
		} else {
			e.Message = rest
		}
	} else {
		// No <PRI> framing — treat the whole line as the message (still extract).
		e.Message = line
	}

	extractFields(&e)
	return e
}

// splitPriority pulls the leading "<NN>" priority. Returns the numeric priority
// and the remainder.
func splitPriority(line string) (int, string, bool) {
	if !strings.HasPrefix(line, "<") {
		return 0, line, false
	}
	end := strings.IndexByte(line, '>')
	if end < 2 || end > 4 {
		return 0, line, false
	}
	n, err := strconv.Atoi(line[1:end])
	if err != nil || n < 0 || n > 191 {
		return 0, line, false
	}
	return n, line[end+1:], true
}

// parse5424 handles RFC5424: "1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG".
func parse5424(rest string, e Event) (Event, bool) {
	if !strings.HasPrefix(rest, "1 ") {
		return e, false
	}
	f := strings.SplitN(rest, " ", 7)
	if len(f) < 7 {
		return e, false
	}
	// f[0]="1", f[1]=ts, f[2]=host, f[3]=app, f[4]=procid, f[5]=msgid, f[6]=SD+msg
	if ts, err := time.Parse(time.RFC3339, f[1]); err == nil {
		e.Timestamp = ts
	}
	e.Host = dashToEmpty(f[2])
	e.App = dashToEmpty(f[3])
	e.Parsed = true
	// f[6] is structured-data (possibly "[...]") followed by the message.
	e.Message = stripStructuredData(f[6])
	return e, true
}

// parse3164 handles the BSD format: "MMM dd HH:MM:SS HOST APP[pid]: MSG".
func parse3164(rest string, e Event) (Event, bool) {
	if len(rest) < 16 {
		return e, false
	}
	tsPart := rest[:15]
	ts, err := time.Parse(time.Stamp, tsPart)
	if err != nil {
		return e, false
	}
	// RFC3164 omits the year; assume the year from `now`.
	ts = ts.AddDate(e.Timestamp.Year(), 0, 0)
	e.Timestamp = ts
	remain := strings.TrimSpace(rest[15:])
	// remain = "HOST APP[pid]: message"
	sp := strings.IndexByte(remain, ' ')
	if sp < 0 {
		e.Message = remain
		e.Parsed = true
		return e, true
	}
	e.Host = remain[:sp]
	tail := strings.TrimSpace(remain[sp+1:])
	if colon := strings.IndexByte(tail, ':'); colon > 0 && colon < 64 {
		tag := tail[:colon]
		if br := strings.IndexByte(tag, '['); br >= 0 {
			tag = tag[:br]
		}
		e.App = tag
		e.Message = strings.TrimSpace(tail[colon+1:])
	} else {
		e.Message = tail
	}
	e.Parsed = true
	return e, true
}

func dashToEmpty(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// stripStructuredData removes a leading RFC5424 SD block ("[...]") or a bare "-"
// and returns the human message.
func stripStructuredData(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "- ") {
		return s[2:]
	}
	if s == "-" {
		return ""
	}
	if strings.HasPrefix(s, "[") {
		depth := 0
		for i, r := range s {
			switch r {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					return strings.TrimSpace(s[i+1:])
				}
			}
		}
	}
	return s
}
