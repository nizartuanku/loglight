// Package correlate stitches individual detections and login events for the same
// actor into one escalated incident — the "SIEM" bit. A port scan, then a brute
// force, then a successful login from the same source within a window is not
// three unrelated blips: it is a likely intrusion, and it outranks any of its
// parts. Correlation is time- and entity-bounded, so it joins real signal
// without manufacturing noise; every incident carries its member events so a
// human can judge.
package correlate

import (
	"fmt"
	"strings"
	"time"

	"github.com/nizartuanku/loglight/detect"
)

// Member is one event/detection that belongs to an incident's timeline.
type Member struct {
	At    time.Time
	Stage string // "scan" | "brute_force" | "success" | ...
	Note  string
}

// Incident is a correlated multi-stage finding, escalated above its members.
type Incident struct {
	Severity string // "critical" | "high"
	Actor    string
	Target   string
	Title    string
	Detail   string
	Stages   []string
	Members  []Member
	FirstAt  time.Time
	LastAt   time.Time
	Key      string
}

// actorState is the bounded per-actor memory the correlator keeps.
type actorState struct {
	scanAt   time.Time
	scanNote string
	bruteAt  time.Time
	brute    *detect.Detection
	target   string
}

// Correlator advances a per-actor kill-chain state machine. Not safe for
// concurrent use — the pipeline serialises through one goroutine.
type Correlator struct {
	window time.Duration
	cool   time.Duration
	states map[string]*actorState
	fired  map[string]time.Time
}

// New builds a correlator. window is how long stages may be apart to link;
// cooldown suppresses repeat incidents for the same actor.
func New(window, cooldown time.Duration) *Correlator {
	if window <= 0 {
		window = 10 * time.Minute
	}
	if cooldown <= 0 {
		cooldown = 15 * time.Minute
	}
	return &Correlator{window: window, cool: cooldown,
		states: map[string]*actorState{}, fired: map[string]time.Time{}}
}

func (c *Correlator) state(actor string) *actorState {
	s := c.states[actor]
	if s == nil {
		s = &actorState{}
		c.states[actor] = s
	}
	return s
}

// ObserveDetection records a scan/brute detection into the actor's chain. It
// never emits on its own — the escalation happens when a success completes the
// chain (ObserveSuccess).
func (c *Correlator) ObserveDetection(d detect.Detection) {
	switch d.Kind {
	case detect.KindScan:
		s := c.state(d.Actor)
		s.scanAt = d.LastAt
		s.scanNote = d.Title
		if d.Target != "" {
			s.target = d.Target
		}
	case detect.KindBruteForce:
		s := c.state(d.Actor)
		s.bruteAt = d.LastAt
		dd := d
		s.brute = &dd
		if d.Target != "" {
			s.target = d.Target
		}
	}
}

// ObserveSentinelFinding takes a high or critical finding that another Sentinel
// product sent over syslog and, if this actor was already doing something on
// this instance, closes the chain into one incident.
//
// It completes a chain on its own where a scan would not, and the asymmetry is
// deliberate. Scans and failed logins are constant background noise on any
// internet-facing host; bait is not. Nobody has a legitimate reason to open a
// decoy, so recon followed by a trip from the same address is the strongest
// pairing this correlator can see — stronger than a successful login, which at
// least has innocent explanations.
//
// With nothing else on record for the actor the finding is left alone: the
// product that raised it already alerted, and repeating it here would be the
// duplicate-alert problem this package exists to remove.
func (c *Correlator) ObserveSentinelFinding(d detect.Detection) *Incident {
	if d.Kind != detect.KindSentinel || d.Actor == "" {
		return nil
	}
	at := d.LastAt
	s := c.states[d.Actor]
	if s == nil {
		return nil
	}
	if last, ok := c.fired[d.Actor]; ok && at.Sub(last) < c.cool {
		return nil
	}

	hasScan := !s.scanAt.IsZero() && at.Sub(s.scanAt) <= c.window && !s.scanAt.After(at)
	hasBrute := s.brute != nil && at.Sub(s.bruteAt) <= c.window && !s.bruteAt.After(at)
	if !hasScan && !hasBrute {
		return nil
	}

	target := d.Target
	if target == "" {
		target = s.target
	}
	inc := &Incident{
		Severity: "critical", Actor: d.Actor, Target: target,
		LastAt: at, Key: "killchain|" + d.Actor,
	}
	if hasScan {
		inc.FirstAt = s.scanAt
		inc.Stages = append(inc.Stages, "scan")
		inc.Members = append(inc.Members, Member{At: s.scanAt, Stage: "scan", Note: s.scanNote})
	}
	if hasBrute {
		if inc.FirstAt.IsZero() || s.bruteAt.Before(inc.FirstAt) {
			inc.FirstAt = s.bruteAt
		}
		inc.Stages = append(inc.Stages, "brute_force")
		inc.Members = append(inc.Members, Member{At: s.bruteAt, Stage: "brute_force", Note: s.brute.Title})
	}
	inc.Stages = append(inc.Stages, "deception")
	inc.Members = append(inc.Members, Member{At: at, Stage: "deception", Note: d.Title})

	inc.Title = fmt.Sprintf("Confirmed intrusion from %s: %s → bait touched",
		d.Actor, strings.Join(inc.Stages[:len(inc.Stages)-1], " → "))
	inc.Detail = fmt.Sprintf(
		"%s tripped a decoy after %s from the same source. Bait has no legitimate users, "+
			"so this is not a heuristic: treat the host as compromised, isolate it, and review "+
			"everything that source touched.", d.Actor, phrase(hasScan, hasBrute))

	c.fired[d.Actor] = at
	delete(c.states, d.Actor)
	return inc
}

func phrase(hasScan, hasBrute bool) string {
	switch {
	case hasScan && hasBrute:
		return "a port scan and a brute-force attempt"
	case hasBrute:
		return "a brute-force attempt"
	default:
		return "a port scan"
	}
}

// ObserveSuccess reports a successful authentication. If the same actor recently
// brute-forced (optionally preceded by a scan) within the window, it completes a
// kill-chain and returns an escalated incident; otherwise nil.
func (c *Correlator) ObserveSuccess(actor, host, user string, at time.Time, raw string) *Incident {
	s := c.states[actor]
	if s == nil || s.brute == nil {
		return nil
	}
	if at.Sub(s.bruteAt) > c.window || at.Before(s.bruteAt) {
		return nil // brute too long ago (or out of order) — not linked
	}
	if last, ok := c.fired[actor]; ok && at.Sub(last) < c.cool {
		return nil
	}

	hasScan := !s.scanAt.IsZero() && s.bruteAt.Sub(s.scanAt) <= c.window && !s.scanAt.After(s.bruteAt)
	target := host
	if target == "" {
		target = s.target
	}

	inc := &Incident{
		Actor: actor, Target: target, FirstAt: s.bruteAt, LastAt: at,
		Key: "killchain|" + actor,
	}
	if !s.scanAt.IsZero() && s.scanAt.Before(inc.FirstAt) {
		inc.FirstAt = s.scanAt
	}

	if hasScan {
		inc.Severity = "critical"
		inc.Stages = []string{"scan", "brute_force", "success"}
		inc.Title = fmt.Sprintf("Likely intrusion from %s: scan → brute force → successful login", actor)
		inc.Members = append(inc.Members, Member{At: s.scanAt, Stage: "scan", Note: s.scanNote})
	} else {
		inc.Severity = "high"
		inc.Stages = []string{"brute_force", "success"}
		inc.Title = fmt.Sprintf("Successful login after brute force from %s", actor)
	}
	inc.Members = append(inc.Members,
		Member{At: s.bruteAt, Stage: "brute_force", Note: s.brute.Title},
		Member{At: at, Stage: "success", Note: successNote(user, target, raw)},
	)
	inc.Detail = fmt.Sprintf("%s authenticated successfully to %s immediately after a brute-force attempt%s. "+
		"Treat as a possible account compromise: rotate the credential and review the session.",
		actor, orAny(target), scanClause(hasScan))

	c.fired[actor] = at
	// Consume the chain so a later benign login doesn't re-trigger.
	delete(c.states, actor)
	return inc
}

func successNote(user, target, raw string) string {
	if user != "" {
		return fmt.Sprintf("successful login as %s on %s", user, orAny(target))
	}
	if raw != "" {
		return raw
	}
	return "successful login on " + orAny(target)
}

func scanClause(hasScan bool) string {
	if hasScan {
		return ", itself preceded by a port scan from the same source"
	}
	return ""
}

func orAny(s string) string {
	if s == "" {
		return "the host"
	}
	return s
}
