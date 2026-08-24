package netflow

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

// UDPSource listens for NetFlow v5/v9/IPFIX datagrams and emits one normalized
// logingest.Event per flow, so the existing detectors (scan, exfil) work over
// flow telemetry unchanged. OnFlow, when set, additionally receives every raw
// Flow — the traffic graph aggregator hangs off it.
type UDPSource struct {
	SourceID string
	Addr     string        // UDP listen address, e.g. "0.0.0.0:2055"
	OnFlow   func(Flow)    // optional tap for the traffic graph
	Now      func() time.Time

	templates *TemplateCache
}

// ID implements logingest.Source.
func (s *UDPSource) ID() string { return s.SourceID }

// Type implements logingest.Source.
func (s *UDPSource) Type() logingest.SourceType { return logingest.SourceNetflow }

func (s *UDPSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run implements logingest.Source: it binds the UDP socket and pumps flows
// until ctx is cancelled. A malformed datagram is skipped, never fatal.
func (s *UDPSource) Run(ctx context.Context, emit func(logingest.Event)) error {
	if s.templates == nil {
		s.templates = NewTemplateCache()
	}
	pc, err := net.ListenPacket("udp", s.Addr)
	if err != nil {
		return fmt.Errorf("netflow listen %s: %w", s.Addr, err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		exporter := from.String()
		if h, _, err := net.SplitHostPort(exporter); err == nil {
			exporter = h
		}
		for _, f := range ParseDatagram(buf[:n], exporter, s.now(), s.templates) {
			if s.OnFlow != nil {
				s.OnFlow(f)
			}
			emit(FlowEvent(f, s.SourceID))
		}
	}
}

// FlowEvent converts one Flow into the normalized Event the detectors consume.
// Host is the internal party (source if private, else destination if private,
// else the exporter), and BytesOut is set only for internal→external flows so
// the egress baseline measures what actually leaves the network.
func FlowEvent(f Flow, sourceID string) logingest.Event {
	srcPriv := IsPrivate(f.SrcIP)
	dstPriv := IsPrivate(f.DstIP)
	host := f.Exporter
	if srcPriv {
		host = f.SrcIP
	} else if dstPriv {
		host = f.DstIP
	}
	var out int64
	if srcPriv && !dstPriv {
		out = f.Bytes
	}
	ts := f.End
	if ts.IsZero() {
		ts = time.Now()
	}
	return logingest.Event{
		Timestamp: ts,
		Source:    logingest.SourceNetflow,
		SourceID:  sourceID,
		Host:      host,
		App:       "netflow",
		Severity:  -1,
		Message:   fmt.Sprintf("flow %s:%d -> %s:%d proto %d bytes %d", f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto, f.Bytes),
		SrcIP:     f.SrcIP,
		DstIP:     f.DstIP,
		DstPort:   f.DstPort,
		BytesOut:  out,
		Action:    "flow",
		Raw:       fmt.Sprintf("netflow %s %s:%d>%s:%d p%d b%d", f.Exporter, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Proto, f.Bytes),
		Parsed:    true,
	}
}

// IsPrivate reports whether ip is RFC1918/loopback/link-local — "internal".
func IsPrivate(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}
