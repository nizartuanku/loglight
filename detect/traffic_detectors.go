package detect

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

// isInternalIP mirrors the "internal network" notion the flow source uses:
// RFC1918, loopback and link-local addresses.
func isInternalIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// --- beaconing ---------------------------------------------------------------

// beacon watches internal→external flow pairs for the C2 heartbeat pattern:
// many connections to one endpoint at a suspiciously regular interval. It keys
// on (src, dst), keeps a bounded ring of recent flow times (bursts within a
// second collapse to one), and fires when enough intervals are regular enough
// (low coefficient of variation) inside the plausible beacon range.
type beacon struct {
	cfg   Config
	times map[string][]time.Time
	cool  *cooldown
}

func newBeacon(c Config) *beacon {
	return &beacon{cfg: c, times: map[string][]time.Time{}, cool: newCooldown(c.Cooldown)}
}

func (b *beacon) observe(e logingest.Event) *Detection {
	if e.Source != logingest.SourceNetflow || e.SrcIP == "" || e.DstIP == "" {
		return nil
	}
	if !isInternalIP(e.SrcIP) || isInternalIP(e.DstIP) {
		return nil // beaconing is internal → external by definition
	}
	key := e.SrcIP + "|" + e.DstIP
	ts := b.times[key]
	// Collapse bursts: a flow within 1s of the previous one is the same beat.
	if n := len(ts); n > 0 && e.Timestamp.Sub(ts[n-1]) < time.Second {
		return nil
	}
	ts = append(ts, e.Timestamp)
	if max := b.cfg.BeaconMin * 2; len(ts) > max {
		ts = ts[len(ts)-max:]
	}
	b.times[key] = ts
	if len(ts) < b.cfg.BeaconMin {
		return nil
	}
	// Interval statistics over the retained beats.
	n := len(ts) - 1
	var sum float64
	gaps := make([]float64, 0, n)
	for i := 1; i < len(ts); i++ {
		g := ts[i].Sub(ts[i-1]).Seconds()
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(n)
	if mean < b.cfg.BeaconMinGap.Seconds() || mean > b.cfg.BeaconMaxGap.Seconds() {
		return nil
	}
	var varsum float64
	for _, g := range gaps {
		varsum += (g - mean) * (g - mean)
	}
	cv := math.Sqrt(varsum/float64(n)) / mean
	if cv > b.cfg.BeaconMaxCV {
		return nil
	}
	if !b.cool.firable("beacon:"+key, e.Timestamp) {
		return nil
	}
	d := &Detection{
		Kind: KindBeacon, Severity: SevHigh, Actor: e.SrcIP, Target: e.DstIP,
		Title: fmt.Sprintf("Beaconing: %s calls %s every ~%s", e.SrcIP, e.DstIP, humanInterval(mean)),
		Detail: fmt.Sprintf("%d connections at a regular ~%s interval (variation %.0f%%) — the heartbeat pattern of malware calling its command-and-control server.",
			len(ts), humanInterval(mean), cv*100),
		Count:   len(ts),
		FirstAt: ts[0], LastAt: e.Timestamp,
		Evidence: []string{e.Raw},
		Key:      "beacon|" + key,
	}
	delete(b.times, key)
	return d
}

func humanInterval(sec float64) string {
	d := time.Duration(sec * float64(time.Second)).Round(time.Second)
	return d.String()
}

// --- new service -------------------------------------------------------------

// newService learns which ports each internal host receives flows on, then
// flags a first-ever port after the learning window — a new listening service
// (or a backdoor) appearing on the network. State is in-memory with stable
// keys: after a restart the learning window re-arms, and a persisting service
// simply re-opens the same finding (documented honest limit).
type newService struct {
	cfg   Config
	seen  map[string]map[int]struct{}
	born  map[string]time.Time
	cool  *cooldown
}

func newNewService(c Config) *newService {
	return &newService{cfg: c, seen: map[string]map[int]struct{}{}, born: map[string]time.Time{}, cool: newCooldown(c.Cooldown)}
}

func (s *newService) observe(e logingest.Event) *Detection {
	if e.Source != logingest.SourceNetflow || e.DstIP == "" || e.DstPort == 0 {
		return nil
	}
	if !isInternalIP(e.DstIP) || e.SrcIP == e.DstIP {
		return nil // only services on internal hosts
	}
	if e.DstPort > 49151 {
		return nil // ephemeral range: return traffic, not a service
	}
	h := e.DstIP
	ports := s.seen[h]
	if ports == nil {
		ports = map[int]struct{}{}
		s.seen[h] = ports
		s.born[h] = e.Timestamp
	}
	if _, known := ports[e.DstPort]; known {
		return nil
	}
	if len(ports) < 4096 { // bounded per host
		ports[e.DstPort] = struct{}{}
	}
	if e.Timestamp.Sub(s.born[h]) < s.cfg.NewServiceLearn {
		return nil // still learning this host's normal
	}
	key := fmt.Sprintf("newsvc|%s|%d", h, e.DstPort)
	if !s.cool.firable(key, e.Timestamp) {
		return nil
	}
	return &Detection{
		Kind: KindNewService, Severity: SevMedium, Actor: e.SrcIP, Target: h,
		Title:  fmt.Sprintf("New service on %s: port %d", h, e.DstPort),
		Detail: fmt.Sprintf("%s started accepting connections on port %d, never seen for this host before. New listening services are how backdoors and unauthorised software announce themselves.", h, e.DstPort),
		Count:  1,
		FirstAt: e.Timestamp, LastAt: e.Timestamp,
		Evidence: []string{e.Raw},
		Key:      key,
	}
}
