package netflow

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/nizartuanku/loglight/logingest"
)

func mkV5(t *testing.T, flows [][2]string, dstPort uint16, bytes uint32) []byte {
	t.Helper()
	b := make([]byte, 24+48*len(flows))
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(flows)))
	binary.BigEndian.PutUint32(b[4:8], 60_000) // uptime 60s
	binary.BigEndian.PutUint32(b[8:12], uint32(time.Now().Unix()))
	for i, f := range flows {
		r := b[24+i*48:]
		copy(r[0:4], net.ParseIP(f[0]).To4())
		copy(r[4:8], net.ParseIP(f[1]).To4())
		binary.BigEndian.PutUint32(r[16:20], 10) // packets
		binary.BigEndian.PutUint32(r[20:24], bytes)
		binary.BigEndian.PutUint32(r[24:28], 30_000) // first
		binary.BigEndian.PutUint32(r[28:32], 55_000) // last
		binary.BigEndian.PutUint16(r[32:34], 40000)
		binary.BigEndian.PutUint16(r[34:36], dstPort)
		r[38] = 6 // TCP
	}
	return b
}

func TestParseV5(t *testing.T) {
	pkt := mkV5(t, [][2]string{{"192.168.1.10", "203.0.113.7"}, {"192.168.1.11", "192.168.1.20"}}, 443, 1234)
	flows := ParseDatagram(pkt, "192.168.1.1", time.Now(), nil)
	if len(flows) != 2 {
		t.Fatalf("want 2 flows, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "192.168.1.10" || f.DstIP != "203.0.113.7" || f.DstPort != 443 || f.Bytes != 1234 || f.Proto != 6 {
		t.Fatalf("bad flow: %+v", f)
	}
	if !f.End.After(f.Start) {
		t.Fatalf("times not ordered: %v %v", f.Start, f.End)
	}
}

// buildV9 returns one datagram carrying a template and one carrying data.
func buildV9(t *testing.T) ([]byte, []byte) {
	t.Helper()
	// Template 260: srcaddr4, dstaddr4, srcport, dstport, proto, bytes, pkts
	tpl := []byte{
		0, 9, 0, 1, // version, count
		0, 0, 0, 1, // uptime
		0, 0, 0, 1, // unix secs
		0, 0, 0, 1, // seq
		0, 0, 0, 7, // source id
		0, 0, 0, 36, // flowset 0, len
		1, 4, 0, 7, // template id 260, 7 fields
		0, 8, 0, 4, // IPV4_SRC_ADDR
		0, 12, 0, 4, // IPV4_DST_ADDR
		0, 7, 0, 2, // SRC_PORT
		0, 11, 0, 2, // DST_PORT
		0, 4, 0, 1, // PROTOCOL
		0, 1, 0, 4, // IN_BYTES
		0, 2, 0, 4, // IN_PKTS
	}
	rec := make([]byte, 0, 21)
	rec = append(rec, net.ParseIP("10.0.0.5").To4()...)
	rec = append(rec, net.ParseIP("198.51.100.9").To4()...)
	rec = append(rec, 0x9c, 0x40) // srcport 40000
	rec = append(rec, 0x01, 0xbb) // dstport 443
	rec = append(rec, 17)         // udp
	rec = append(rec, 0, 0, 0x30, 0x39) // 12345 bytes
	rec = append(rec, 0, 0, 0, 9)
	data := []byte{
		0, 9, 0, 1,
		0, 0, 0, 1,
		0, 0, 0, 1,
		0, 0, 0, 2,
		0, 0, 0, 7,
		1, 4, 0, 0, // flowset 260, len patched below
	}
	data = append(data, rec...)
	for len(data)%4 != 0 {
		data = append(data, 0) // pad
	}
	binary.BigEndian.PutUint16(data[22:24], uint16(len(data)-20))
	return tpl, data
}

func TestParseV9TemplateThenData(t *testing.T) {
	tpl, data := buildV9(t)
	tc := NewTemplateCache()
	// Data before template → dropped.
	if got := ParseDatagram(data, "10.0.0.1", time.Now(), tc); len(got) != 0 {
		t.Fatalf("data without template should drop, got %d", len(got))
	}
	if tc.Dropped == 0 {
		t.Fatal("dropped counter not incremented")
	}
	ParseDatagram(tpl, "10.0.0.1", time.Now(), tc)
	flows := ParseDatagram(data, "10.0.0.1", time.Now(), tc)
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "10.0.0.5" || f.DstIP != "198.51.100.9" || f.DstPort != 443 || f.Bytes != 12345 || f.Proto != 17 || f.Packets != 9 {
		t.Fatalf("bad flow: %+v", f)
	}
	// Same template from a different exporter must not be visible.
	if got := ParseDatagram(data, "10.9.9.9", time.Now(), tc); len(got) != 0 {
		t.Fatalf("template must be per-exporter, got %d flows", len(got))
	}
}

func TestParseIPFIX(t *testing.T) {
	// Template set (id 2): template 300 with srcaddr4, dstaddr4, dstport, bytes.
	tpl := []byte{
		0, 10, 0, 0, // version, total length (patched)
		0, 0, 0, 1, // export time
		0, 0, 0, 1, // seq
		0, 0, 0, 3, // obs domain
		0, 2, 0, 24, // set 2, len 24
		1, 44, 0, 4, // template 300, 4 fields
		0, 8, 0, 4,
		0, 12, 0, 4,
		0, 11, 0, 2,
		0, 1, 0, 4,
	}
	binary.BigEndian.PutUint16(tpl[2:4], uint16(len(tpl)))
	rec := make([]byte, 0, 14)
	rec = append(rec, net.ParseIP("172.16.0.7").To4()...)
	rec = append(rec, net.ParseIP("203.0.113.99").To4()...)
	rec = append(rec, 0x00, 0x16)       // 22
	rec = append(rec, 0, 0x0f, 0x42, 0x40) // 1_000_000
	data := []byte{
		0, 10, 0, 0,
		0, 0, 0, 2,
		0, 0, 0, 2,
		0, 0, 0, 3,
		1, 44, 0, byte(4 + len(rec)),
	}
	data = append(data, rec...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))

	tc := NewTemplateCache()
	ParseDatagram(tpl, "172.16.0.1", time.Now(), tc)
	flows := ParseDatagram(data, "172.16.0.1", time.Now(), tc)
	if len(flows) != 1 {
		t.Fatalf("want 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "172.16.0.7" || f.DstIP != "203.0.113.99" || f.DstPort != 22 || f.Bytes != 1_000_000 {
		t.Fatalf("bad flow: %+v", f)
	}
}

func TestGarbageIsSilent(t *testing.T) {
	for _, b := range [][]byte{nil, {0}, {0, 99}, {0, 5, 0, 200}, make([]byte, 23)} {
		if got := ParseDatagram(b, "x", time.Now(), NewTemplateCache()); len(got) != 0 {
			t.Fatalf("garbage %v produced flows", b)
		}
	}
}

func TestFlowEventMapping(t *testing.T) {
	e := FlowEvent(Flow{Exporter: "192.168.1.1", SrcIP: "192.168.1.10", DstIP: "203.0.113.7",
		DstPort: 443, Bytes: 5000, End: time.Now()}, "flows")
	if e.Source != logingest.SourceNetflow || !e.Parsed {
		t.Fatalf("bad event meta: %+v", e)
	}
	if e.Host != "192.168.1.10" || e.BytesOut != 5000 || e.DstIP != "203.0.113.7" {
		t.Fatalf("internal→external mapping wrong: %+v", e)
	}
	// external→internal: no BytesOut, host = internal dst
	e2 := FlowEvent(Flow{Exporter: "192.168.1.1", SrcIP: "203.0.113.7", DstIP: "192.168.1.10",
		DstPort: 22, Bytes: 100, End: time.Now()}, "flows")
	if e2.Host != "192.168.1.10" || e2.BytesOut != 0 {
		t.Fatalf("external→internal mapping wrong: %+v", e2)
	}
}

func TestUDPSourceEndToEnd(t *testing.T) {
	got := make(chan logingest.Event, 16)
	var flows int
	src := &UDPSource{SourceID: "flows", Addr: "127.0.0.1:0"}
	// Bind on a fixed free port: use a helper listener to pick one.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	src.Addr = addr
	src.OnFlow = func(Flow) { flows++ }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = src.Run(ctx, func(e logingest.Event) { got <- e }) }()

	time.Sleep(100 * time.Millisecond)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(mkV5(t, [][2]string{{"192.168.1.10", "203.0.113.7"}}, 443, 999))

	select {
	case e := <-got:
		if e.SrcIP != "192.168.1.10" || e.DstPort != 443 {
			t.Fatalf("bad event: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event received")
	}
	if flows != 1 {
		t.Fatalf("OnFlow saw %d flows", flows)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("source did not stop on cancel")
	}
}
