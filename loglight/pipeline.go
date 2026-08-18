package loglight

import (
	"time"

	"github.com/nizartuanku/loglight/core"
	"github.com/nizartuanku/loglight/correlate"
	"github.com/nizartuanku/loglight/detect"
	"github.com/nizartuanku/loglight/logingest"
	"github.com/nizartuanku/loglight/notify"
	"github.com/nizartuanku/loglight/store"
)

// Pipeline is Path A: it consumes the normalized Event stream, runs the
// detectors and correlator, and writes every fired detection/incident straight
// to the findings store as open — notifying immediately. The Collector (Path B)
// then re-affirms and auto-resolves. Handle is called from the ingest engine's
// single delivery goroutine, so it needs no internal locking.
type Pipeline struct {
	Detect *detect.Engine
	Corr   *correlate.Correlator
	Log    Store        // loglight source/detection store
	Store  store.Store  // core findings store (Upsert)
	Disp   *notify.Dispatcher
	Now    func() time.Time
	NewID  func(t time.Time) (string, error)
}

// Handle processes one event end-to-end (Path A).
func (p *Pipeline) Handle(e logingest.Event) {
	// 1. Run detectors; persist + emit each fired detection.
	for _, d := range p.Detect.Observe(e) {
		p.Corr.ObserveDetection(d)
		p.recordDetection(e.SourceID, d)
	}
	// 2. Feed successful logins to the correlator; emit any completed kill-chain.
	if e.Auth == logingest.AuthSuccess {
		if inc := p.Corr.ObserveSuccess(e.Actor(), e.Host, e.User, e.Timestamp, e.Raw); inc != nil {
			p.recordIncident(e.SourceID, *inc)
		}
	}
}

func (p *Pipeline) recordDetection(sourceID string, d detect.Detection) {
	rec := DetectionRecord{
		Key: d.Key, SourceID: sourceID, Check: "detect." + string(d.Kind),
		Severity: string(d.Severity), Actor: d.Actor, Target: d.Target,
		Title: d.Title, Detail: d.Detail, Evidence: d.Evidence,
		Fix: fixFor(d.Kind), Count: d.Count, FirstAt: d.FirstAt, LastAt: d.LastAt,
	}
	p.persistAndEmit(rec)
}

func (p *Pipeline) recordIncident(sourceID string, inc correlate.Incident) {
	var ev []string
	for _, m := range inc.Members {
		ev = append(ev, m.At.Format(time.RFC3339)+"  ["+m.Stage+"]  "+m.Note)
	}
	rec := DetectionRecord{
		Key: inc.Key, SourceID: sourceID, Check: "incident.killchain",
		Severity: inc.Severity, Actor: inc.Actor, Target: inc.Target,
		Title: inc.Title, Detail: inc.Detail, Evidence: ev,
		Fix:     "Treat as a possible compromise: isolate the host, rotate the affected credential, and review the session.",
		Count:   len(inc.Members), FirstAt: inc.FirstAt, LastAt: inc.LastAt,
	}
	p.persistAndEmit(rec)
}

// persistAndEmit stores the detection for the backstop and writes the finding as
// open + notifies immediately (Path A). Recurrences (same Key) update in place;
// the detector/correlator cooldowns throttle how often this is reached.
func (p *Pipeline) persistAndEmit(rec DetectionRecord) {
	_ = p.Log.UpsertDetection(rec)

	f := detectionFinding(rec)
	id, err := p.newID(rec.LastAt)
	if err != nil {
		return
	}
	srec := store.Record{Finding: f}
	srec.ID = id
	srec.Module = ModuleID
	srec.Status = core.StatusOpen
	srec.FirstSeen = rec.FirstAt
	srec.LastSeen = rec.LastAt
	if p.Store != nil {
		if err := p.Store.Upsert(srec); err != nil {
			return
		}
	}
	if p.Disp != nil {
		p.Disp.Enqueue(notify.Event{Kind: notify.KindOpened, Module: ModuleID, Finding: f})
	}
}

func (p *Pipeline) newID(t time.Time) (string, error) {
	if p.NewID != nil {
		return p.NewID(t)
	}
	return store.NewULID(t)
}

func fixFor(k detect.Kind) string {
	switch k {
	case detect.KindBruteForce:
		return "Block the source IP and confirm no login succeeded. Enforce rate-limiting / fail2ban and key-only auth."
	case detect.KindScan:
		return "Confirm the source is authorised. Block it at the perimeter if not; ensure only intended ports are exposed."
	case detect.KindExfil:
		return "Investigate the outbound transfer from this host now — unexpected large egress can be data exfiltration."
	case detect.KindNewAdmin:
		return "Verify this account/privilege grant was authorised and change-controlled. If not, disable it and investigate."
	case detect.KindAuthSpike:
		return "Likely credential stuffing — enable rate-limiting/MFA and watch for any success from the same sources."
	}
	return "Investigate the actor and affected host."
}
