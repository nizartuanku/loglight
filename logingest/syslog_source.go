package logingest

import (
	"bufio"
	"context"
	"net"
	"time"
)

// SyslogSource listens for syslog messages over UDP and/or TCP and emits one
// Event per datagram / line. This is the universal path: routers, firewalls,
// appliances, Linux hosts, and Windows boxes (via a forwarder) all send here.
// Mark Kind = SourceWindows for a listener dedicated to forwarded Windows events
// so the dashboard labels them, though parsing is identical.
type SyslogSource struct {
	SourceID string
	UDPAddr  string     // e.g. "0.0.0.0:5514"; empty disables UDP
	TCPAddr  string     // e.g. "0.0.0.0:5514"; empty disables TCP
	Kind     SourceType // SourceSyslog (default) or SourceWindows

	Now func() time.Time
}

func (s *SyslogSource) ID() string { return s.SourceID }
func (s *SyslogSource) Type() SourceType {
	if s.Kind != "" {
		return s.Kind
	}
	return SourceSyslog
}

func (s *SyslogSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SyslogSource) Run(ctx context.Context, emit func(Event)) error {
	errc := make(chan error, 2)
	started := 0
	if s.UDPAddr != "" {
		started++
		go func() { errc <- s.runUDP(ctx, emit) }()
	}
	if s.TCPAddr != "" {
		started++
		go func() { errc <- s.runTCP(ctx, emit) }()
	}
	if started == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	// Return on ctx cancel or the first listener error.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func (s *SyslogSource) tag(e Event) Event {
	e.SourceID = s.SourceID
	if s.Kind == SourceWindows {
		e.Source = SourceWindows
	}
	return e
}

func (s *SyslogSource) runUDP(ctx context.Context, emit func(Event)) error {
	pc, err := net.ListenPacket("udp", s.UDPAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 64*1024)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		emit(s.tag(ParseSyslog(string(buf[:n]), s.now())))
	}
}

func (s *SyslogSource) runTCP(ctx context.Context, emit func(Event)) error {
	ln, err := net.Listen("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.handleConn(ctx, conn, emit)
	}
}

func (s *SyslogSource) handleConn(ctx context.Context, conn net.Conn, emit func(Event)) {
	defer conn.Close()
	go func() { <-ctx.Done(); conn.Close() }()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if ctx.Err() != nil {
			return
		}
		emit(s.tag(ParseSyslog(sc.Text(), s.now())))
	}
}
