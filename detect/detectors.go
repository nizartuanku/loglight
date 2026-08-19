package detect

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

// evidenceKeep appends a sample line up to the configured max.
func evidenceKeep(ev []string, line string, max int) []string {
	if len(ev) >= max || line == "" {
		return ev
	}
	return append(ev, line)
}

// --- brute force ------------------------------------------------------------

type bruteForce struct {
	cfg   Config
	count *slidingCounter
	cool  *cooldown
	first map[string]time.Time
	evid  map[string][]string
}

func newBruteForce(c Config) *bruteForce {
	return &bruteForce{cfg: c, count: newSlidingCounter(c.BruteWindow), cool: newCooldown(c.Cooldown),
		first: map[string]time.Time{}, evid: map[string][]string{}}
}

func (b *bruteForce) observe(e logingest.Event) *Detection {
	if e.Auth != logingest.AuthFailure {
		return nil
	}
	actor := e.Actor()
	if actor == "" {
		return nil
	}
	if _, ok := b.first[actor]; !ok {
		b.first[actor] = e.Timestamp
	}
	b.evid[actor] = evidenceKeep(b.evid[actor], e.Raw, b.cfg.EvidenceMax)
	n := b.count.add(actor, e.Timestamp)
	if n < b.cfg.BruteFailures || !b.cool.firable("bf:"+actor, e.Timestamp) {
		return nil
	}
	d := &Detection{
		Kind: KindBruteForce, Severity: SevHigh, Actor: actor, Target: e.Host, User: e.User,
		Title:   fmt.Sprintf("Brute force: %d failed logins from %s", n, actor),
		Detail:  fmt.Sprintf("%d authentication failures within %s (target %s).", n, b.cfg.BruteWindow, orAny(e.Host)),
		Count:   n,
		FirstAt: b.first[actor], LastAt: e.Timestamp,
		Evidence: b.evid[actor],
		Key:      "brute|" + actor,
	}
	b.count.reset(actor)
	delete(b.first, actor)
	delete(b.evid, actor)
	return d
}

// --- port / host scan -------------------------------------------------------

type scan struct {
	cfg   Config
	ports *distinctWindow
	cool  *cooldown
	first map[string]time.Time
	evid  map[string][]string
}

func newScan(c Config) *scan {
	return &scan{cfg: c, ports: newDistinctWindow(c.ScanWindow), cool: newCooldown(c.Cooldown),
		first: map[string]time.Time{}, evid: map[string][]string{}}
}

func (s *scan) observe(e logingest.Event) *Detection {
	if e.SrcIP == "" || e.DstPort == 0 {
		return nil
	}
	if _, ok := s.first[e.SrcIP]; !ok {
		s.first[e.SrcIP] = e.Timestamp
	}
	s.evid[e.SrcIP] = evidenceKeep(s.evid[e.SrcIP], e.Raw, s.cfg.EvidenceMax)
	n := s.ports.add(e.SrcIP, strconv.Itoa(e.DstPort), e.Timestamp)
	if n < s.cfg.ScanPorts || !s.cool.firable("scan:"+e.SrcIP, e.Timestamp) {
		return nil
	}
	d := &Detection{
		Kind: KindScan, Severity: SevMedium, Actor: e.SrcIP, Target: e.Host,
		Title:   fmt.Sprintf("Port scan: %s hit %d distinct ports", e.SrcIP, n),
		Detail:  fmt.Sprintf("%d distinct destination ports within %s.", n, s.cfg.ScanWindow),
		Count:   n,
		FirstAt: s.first[e.SrcIP], LastAt: e.Timestamp,
		Evidence: s.evid[e.SrcIP],
		Key:      "scan|" + e.SrcIP,
	}
	s.ports.reset(e.SrcIP)
	delete(s.first, e.SrcIP)
	delete(s.evid, e.SrcIP)
	return d
}

// --- exfiltration / abnormal egress -----------------------------------------

type exfil struct {
	cfg  Config
	sum  *sumWindow
	base map[string]float64 // EWMA baseline per host
	cool *cooldown
	evid map[string][]string
}

func newExfil(c Config) *exfil {
	return &exfil{cfg: c, sum: newSumWindow(c.ExfilWindow), base: map[string]float64{},
		cool: newCooldown(c.Cooldown), evid: map[string][]string{}}
}

func (x *exfil) observe(e logingest.Event) *Detection {
	if e.BytesOut <= 0 || e.Host == "" {
		return nil
	}
	x.evid[e.Host] = evidenceKeep(x.evid[e.Host], e.Raw, x.cfg.EvidenceMax)
	total := x.sum.add(e.Host, e.Timestamp, e.BytesOut)
	base := x.base[e.Host]
	// Update EWMA baseline (before comparison so first observations set it).
	if base == 0 {
		x.base[e.Host] = float64(total)
	} else {
		x.base[e.Host] = 0.8*base + 0.2*float64(total)
	}
	// Fire when this window's egress is both above the absolute floor and a
	// large multiple over the established baseline.
	if total < x.cfg.ExfilBytes || base == 0 {
		return nil
	}
	if float64(total) < x.cfg.ExfilFactor*base {
		return nil
	}
	if !x.cool.firable("exfil:"+e.Host, e.Timestamp) {
		return nil
	}
	d := &Detection{
		Kind: KindExfil, Severity: SevHigh, Actor: e.Host, Target: e.Host,
		Title:   fmt.Sprintf("Abnormal egress from %s: %s", e.Host, humanBytes(total)),
		Detail:  fmt.Sprintf("%s outbound within %s — ~%.1f× this host's baseline.", humanBytes(total), x.cfg.ExfilWindow, float64(total)/base),
		Count:   1,
		FirstAt: e.Timestamp, LastAt: e.Timestamp,
		Evidence: x.evid[e.Host],
		Key:      "exfil|" + e.Host,
	}
	delete(x.evid, e.Host)
	return d
}

// --- new privileged account -------------------------------------------------

type newAdmin struct {
	cfg  Config
	cool *cooldown
}

func newNewAdmin(c Config) *newAdmin { return &newAdmin{cfg: c, cool: newCooldown(c.Cooldown)} }

func (n *newAdmin) observe(e logingest.Event) *Detection {
	if e.Action != "new_admin" {
		return nil
	}
	key := "newadmin|" + orAny(e.Host) + "|" + orAny(e.User)
	if !n.cool.firable(key, e.Timestamp) {
		return nil
	}
	who := e.User
	if who == "" {
		who = "a new account"
	}
	return &Detection{
		Kind: KindNewAdmin, Severity: SevHigh, Actor: e.Actor(), Target: e.Host, User: e.User,
		Title:   fmt.Sprintf("New privileged account created: %s", who),
		Detail:  "A new user/admin account or privilege grant was recorded — a classic persistence step. Confirm it was authorised.",
		Count:   1,
		FirstAt: e.Timestamp, LastAt: e.Timestamp,
		Evidence: []string{e.Raw},
		Key:      key,
	}
}

// --- auth-failure spike (per service, aggregate across sources) -------------

// authSpike keys on the service (host/app), not the actor — so it catches a
// distributed surge (many IPs failing against one login) that a per-IP
// brute-force threshold would miss. It fires when the windowed failure count for
// a service crosses SpikeMin, and — to distinguish a genuine distributed attack
// from one noisy IP already covered by brute force — only when the failures come
// from several distinct sources.
type authSpike struct {
	cfg     Config
	count   *slidingCounter
	sources *distinctWindow
	cool    *cooldown
	first   map[string]time.Time
	evid    map[string][]string
}

func newAuthSpike(c Config) *authSpike {
	return &authSpike{cfg: c, count: newSlidingCounter(c.SpikeWindow), sources: newDistinctWindow(c.SpikeWindow),
		cool: newCooldown(c.Cooldown), first: map[string]time.Time{}, evid: map[string][]string{}}
}

func (a *authSpike) observe(e logingest.Event) *Detection {
	if e.Auth != logingest.AuthFailure {
		return nil
	}
	svc := orAny(e.Host) + "/" + orAny(e.App)
	if _, ok := a.first[svc]; !ok {
		a.first[svc] = e.Timestamp
	}
	a.evid[svc] = evidenceKeep(a.evid[svc], e.Raw, a.cfg.EvidenceMax)
	n := a.count.add(svc, e.Timestamp)
	srcKey := e.SrcIP
	if srcKey == "" {
		srcKey = orAny(e.User)
	}
	distinctSrc := a.sources.add(svc, srcKey, e.Timestamp)
	if n < a.cfg.SpikeMin || distinctSrc < 3 || !a.cool.firable("spike:"+svc, e.Timestamp) {
		return nil
	}
	d := &Detection{
		Kind: KindAuthSpike, Severity: SevMedium, Actor: svc, Target: e.Host,
		Title:   fmt.Sprintf("Distributed auth-failure spike on %s: %d from %d sources", svc, n, distinctSrc),
		Detail:  fmt.Sprintf("%d auth failures on %s from %d distinct sources within %s — looks like credential stuffing.", n, svc, distinctSrc, a.cfg.SpikeWindow),
		Count:   n,
		FirstAt: a.first[svc], LastAt: e.Timestamp,
		Evidence: a.evid[svc],
		Key:      "spike|" + svc,
	}
	a.count.reset(svc)
	a.sources.reset(svc)
	delete(a.first, svc)
	delete(a.evid, svc)
	return d
}

// --- helpers ----------------------------------------------------------------

func orAny(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// --- Sentinel findings (the other five products) ----------------------------

// sentinelFinding recognises a finding emitted by another Sentinel tool over
// syslog and turns it into a detection, so the correlator can place it on the
// same actor's timeline as anything Loglight saw itself.
//
// Why deception outranks the rest: a Decoy trip is not a heuristic. Nobody has
// a legitimate reason to open the bait, so a trip following recon from the same
// address is about as close to proof of intrusion as a log line gets. That is
// why a high-severity finding here completes a chain in its own right, where a
// scan alone never would.
//
// It keys on the structured tail SyslogChannel writes — product=, severity=,
// check=, src= — and ignores anything without a source address, because an
// actorless finding cannot be correlated to anything.
type sentinelFinding struct {
	cfg  Config
	cool *cooldown
	evid map[string][]string
}

func newSentinelFinding(c Config) *sentinelFinding {
	return &sentinelFinding{cfg: c, cool: newCooldown(c.Cooldown), evid: map[string][]string{}}
}

var (
	reSentinelProduct = regexp.MustCompile(`\bproduct=([a-z0-9_.-]+)`)
	reSentinelSev     = regexp.MustCompile(`\bseverity=([a-z]+)`)
	reSentinelCheck   = regexp.MustCompile(`\bcheck=([a-zA-Z0-9_.-]+)`)
	reSentinelStatus  = regexp.MustCompile(`\bstatus=([a-z]+)`)
)

func (s *sentinelFinding) observe(e logingest.Event) *Detection {
	msg := e.Message
	if msg == "" {
		msg = e.Raw
	}
	product := firstGroup(reSentinelProduct, msg)
	if product == "" {
		return nil // not one of ours
	}
	if st := firstGroup(reSentinelStatus, msg); st == "resolved" {
		return nil // a resolution is good news, never an incident stage
	}
	sev := firstGroup(reSentinelSev, msg)
	if sev != "critical" && sev != "high" {
		return nil // armed traps, inventory notes and the like are not signal
	}
	// Correlation needs an actor. A finding about your own surface (a expiring
	// certificate, a shadowed firewall rule) has no attacker, and belongs on
	// its own product's dashboard rather than on someone's timeline.
	if e.SrcIP == "" {
		return nil
	}
	actor := e.SrcIP
	if !s.cool.firable("sentinel:"+product+":"+actor, e.Timestamp) {
		return nil
	}
	s.evid[actor] = evidenceKeep(s.evid[actor], e.Raw, s.cfg.EvidenceMax)
	check := firstGroup(reSentinelCheck, msg)

	severity := SevHigh
	if sev == "critical" {
		severity = SevCritical
	}
	return &Detection{
		Kind: KindSentinel, Severity: severity, Actor: actor, Target: e.Host,
		Title:  fmt.Sprintf("%s reported %s from %s", product, orAny(check), actor),
		Detail: fmt.Sprintf("A %s finding from %s arrived over syslog: %s", sev, product, msg),
		Count:  1, FirstAt: e.Timestamp, LastAt: e.Timestamp,
		Evidence: s.evid[actor],
		Key:      "sentinel|" + product + "|" + actor,
	}
}

func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}
