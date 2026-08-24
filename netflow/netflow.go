// Package netflow parses NetFlow v5, NetFlow v9 and IPFIX datagrams into Flow
// records, and exposes a UDP Source that feeds them into the Loglight pipeline
// as normalized events. Flow telemetry is metadata only — who talked to whom,
// which port, how many bytes — never packet contents. The routers and firewalls
// customers already run (MikroTik, pfSense, Fortinet, Cisco, Ubiquiti) export
// it natively, so no agent and no privileged capture is needed.
package netflow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Flow is one flow record extracted from a datagram.
type Flow struct {
	Exporter string // exporter address (the router that sent the datagram)
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Proto    uint8
	Bytes    int64
	Packets  int64
	Start    time.Time
	End      time.Time
}

// templateField is one (type, length) entry of a v9/IPFIX template.
type templateField struct {
	Type uint16
	Len  uint16
	Ent  bool // IPFIX enterprise-specific field (skipped when decoding)
}

// TemplateCache caches v9/IPFIX templates per (exporter, observation domain,
// template id). Data records that arrive before their template are dropped and
// counted — normal NetFlow behaviour, exporters re-send templates periodically.
type TemplateCache struct {
	mu   sync.Mutex
	tpls map[string][]templateField
	// Dropped counts data records skipped for want of a template.
	Dropped int64
}

// NewTemplateCache returns an empty cache.
func NewTemplateCache() *TemplateCache {
	return &TemplateCache{tpls: map[string][]templateField{}}
}

func (c *TemplateCache) key(exporter string, domain uint32, id uint16) string {
	return fmt.Sprintf("%s|%d|%d", exporter, domain, id)
}

func (c *TemplateCache) put(exporter string, domain uint32, id uint16, f []templateField) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.tpls) > 4096 { // bounded: a hostile exporter cannot grow this forever
		c.tpls = map[string][]templateField{}
	}
	c.tpls[c.key(exporter, domain, id)] = f
}

func (c *TemplateCache) get(exporter string, domain uint32, id uint16) ([]templateField, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.tpls[c.key(exporter, domain, id)]
	return f, ok
}

// Field type / information element numbers shared by NetFlow v9 and IPFIX.
const (
	fieldInBytes  = 1
	fieldInPkts   = 2
	fieldProtocol = 4
	fieldSrcPort  = 7
	fieldSrcAddr4 = 8
	fieldDstPort  = 11
	fieldDstAddr4 = 12
	fieldLast     = 21
	fieldFirst    = 22
	fieldSrcAddr6 = 27
	fieldDstAddr6 = 28
)

// ParseDatagram parses one UDP payload from exporter, returning the flows it
// carries. Unknown versions and truncated packets return no flows and no error
// noise — a monitor must not crash or spam on garbage input.
func ParseDatagram(b []byte, exporter string, now time.Time, tc *TemplateCache) []Flow {
	if len(b) < 2 {
		return nil
	}
	switch binary.BigEndian.Uint16(b[0:2]) {
	case 5:
		return parseV5(b, exporter, now)
	case 9:
		return parseV9(b, exporter, now, tc)
	case 10:
		return parseIPFIX(b, exporter, now, tc)
	}
	return nil
}

// --- NetFlow v5 --------------------------------------------------------------

func parseV5(b []byte, exporter string, now time.Time) []Flow {
	const header, record = 24, 48
	if len(b) < header {
		return nil
	}
	count := int(binary.BigEndian.Uint16(b[2:4]))
	uptime := time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Millisecond
	secs := int64(binary.BigEndian.Uint32(b[8:12]))
	base := time.Unix(secs, 0)
	if secs == 0 {
		base = now
	}
	boot := base.Add(-uptime) // exporter boot time in absolute terms
	var out []Flow
	for i := 0; i < count; i++ {
		off := header + i*record
		if off+record > len(b) {
			break
		}
		r := b[off : off+record]
		first := boot.Add(time.Duration(binary.BigEndian.Uint32(r[24:28])) * time.Millisecond)
		last := boot.Add(time.Duration(binary.BigEndian.Uint32(r[28:32])) * time.Millisecond)
		out = append(out, Flow{
			Exporter: exporter,
			SrcIP:    netip.AddrFrom4([4]byte(r[0:4])).String(),
			DstIP:    netip.AddrFrom4([4]byte(r[4:8])).String(),
			Packets:  int64(binary.BigEndian.Uint32(r[16:20])),
			Bytes:    int64(binary.BigEndian.Uint32(r[20:24])),
			SrcPort:  int(binary.BigEndian.Uint16(r[32:34])),
			DstPort:  int(binary.BigEndian.Uint16(r[34:36])),
			Proto:    r[38],
			Start:    first,
			End:      last,
		})
	}
	return out
}

// --- NetFlow v9 --------------------------------------------------------------

func parseV9(b []byte, exporter string, now time.Time, tc *TemplateCache) []Flow {
	const header = 20
	if len(b) < header || tc == nil {
		return nil
	}
	domain := binary.BigEndian.Uint32(b[16:20]) // source id
	var out []Flow
	off := header
	for off+4 <= len(b) {
		setID := binary.BigEndian.Uint16(b[off : off+2])
		setLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(b) {
			break
		}
		body := b[off+4 : off+setLen]
		switch {
		case setID == 0: // template flowset
			parseTemplates(body, exporter, domain, tc, false)
		case setID == 1: // options template — not used
		case setID > 255: // data flowset
			out = append(out, decodeData(body, exporter, domain, setID, now, tc)...)
		}
		off += setLen
	}
	return out
}

// --- IPFIX (v10) -------------------------------------------------------------

func parseIPFIX(b []byte, exporter string, now time.Time, tc *TemplateCache) []Flow {
	const header = 16
	if len(b) < header || tc == nil {
		return nil
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total > len(b) {
		total = len(b)
	}
	domain := binary.BigEndian.Uint32(b[12:16])
	var out []Flow
	off := header
	for off+4 <= total {
		setID := binary.BigEndian.Uint16(b[off : off+2])
		setLen := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if setLen < 4 || off+setLen > total {
			break
		}
		body := b[off+4 : off+setLen]
		switch {
		case setID == 2: // template set
			parseTemplates(body, exporter, domain, tc, true)
		case setID == 3: // options template — not used
		case setID > 255:
			out = append(out, decodeData(body, exporter, domain, setID, now, tc)...)
		}
		off += setLen
	}
	return out
}

// parseTemplates reads one or more templates from a template (flow)set body.
func parseTemplates(b []byte, exporter string, domain uint32, tc *TemplateCache, ipfix bool) {
	off := 0
	for off+4 <= len(b) {
		id := binary.BigEndian.Uint16(b[off : off+2])
		n := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if id < 256 || n == 0 || n > 128 {
			return
		}
		fields := make([]templateField, 0, n)
		for i := 0; i < n; i++ {
			if off+4 > len(b) {
				return
			}
			ft := binary.BigEndian.Uint16(b[off : off+2])
			fl := binary.BigEndian.Uint16(b[off+2 : off+4])
			off += 4
			ent := false
			if ipfix && ft&0x8000 != 0 { // enterprise-specific IE: skip its number
				ft &= 0x7fff
				ent = true
				if off+4 > len(b) {
					return
				}
				off += 4
			}
			fields = append(fields, templateField{Type: ft, Len: fl, Ent: ent})
		}
		tc.put(exporter, domain, id, fields)
	}
}

// decodeData decodes a data (flow)set body against its cached template.
func decodeData(b []byte, exporter string, domain uint32, id uint16, now time.Time, tc *TemplateCache) []Flow {
	tpl, ok := tc.get(exporter, domain, id)
	if !ok {
		tc.mu.Lock()
		tc.Dropped++
		tc.mu.Unlock()
		return nil
	}
	recLen := 0
	varlen := false
	for _, f := range tpl {
		if f.Len == 0xffff {
			varlen = true
			break
		}
		recLen += int(f.Len)
	}
	var out []Flow
	off := 0
	for {
		if varlen {
			f, n := decodeRecordVar(b[off:], tpl, exporter, now)
			if n == 0 {
				break
			}
			if f != nil {
				out = append(out, *f)
			}
			off += n
		} else {
			if recLen == 0 || off+recLen > len(b) {
				break
			}
			if f := decodeRecordFixed(b[off:off+recLen], tpl, exporter, now); f != nil {
				out = append(out, *f)
			}
			off += recLen
		}
		if off >= len(b)-3 { // ≤3 trailing bytes = padding
			break
		}
	}
	return out
}

func decodeRecordFixed(r []byte, tpl []templateField, exporter string, now time.Time) *Flow {
	f := &Flow{Exporter: exporter, Packets: 0, Start: now, End: now}
	off := 0
	for _, tf := range tpl {
		v := r[off : off+int(tf.Len)]
		off += int(tf.Len)
		if !tf.Ent {
			applyField(f, tf.Type, v)
		}
	}
	if f.SrcIP == "" || f.DstIP == "" {
		return nil
	}
	if f.Packets == 0 {
		f.Packets = 1
	}
	return f
}

// decodeRecordVar handles IPFIX records containing variable-length fields.
func decodeRecordVar(r []byte, tpl []templateField, exporter string, now time.Time) (*Flow, int) {
	f := &Flow{Exporter: exporter, Start: now, End: now}
	off := 0
	for _, tf := range tpl {
		l := int(tf.Len)
		if tf.Len == 0xffff {
			if off >= len(r) {
				return nil, 0
			}
			l = int(r[off])
			off++
			if l == 255 {
				if off+2 > len(r) {
					return nil, 0
				}
				l = int(binary.BigEndian.Uint16(r[off : off+2]))
				off += 2
			}
		}
		if off+l > len(r) {
			return nil, 0
		}
		if !tf.Ent {
			applyField(f, tf.Type, r[off:off+l])
		}
		off += l
	}
	if f.SrcIP == "" || f.DstIP == "" {
		return nil, off
	}
	if f.Packets == 0 {
		f.Packets = 1
	}
	return f, off
}

// applyField maps one field value onto the Flow.
func applyField(f *Flow, typ uint16, v []byte) {
	switch typ {
	case fieldInBytes:
		f.Bytes = int64(uintN(v))
	case fieldInPkts:
		f.Packets = int64(uintN(v))
	case fieldProtocol:
		if len(v) >= 1 {
			f.Proto = v[len(v)-1]
		}
	case fieldSrcPort:
		f.SrcPort = int(uintN(v))
	case fieldDstPort:
		f.DstPort = int(uintN(v))
	case fieldSrcAddr4:
		if len(v) == 4 {
			f.SrcIP = netip.AddrFrom4([4]byte(v)).String()
		}
	case fieldDstAddr4:
		if len(v) == 4 {
			f.DstIP = netip.AddrFrom4([4]byte(v)).String()
		}
	case fieldSrcAddr6:
		if len(v) == 16 {
			f.SrcIP = netip.AddrFrom16([16]byte(v)).String()
		}
	case fieldDstAddr6:
		if len(v) == 16 {
			f.DstIP = netip.AddrFrom16([16]byte(v)).String()
		}
	}
}

// uintN reads a big-endian unsigned integer of 1..8 bytes.
func uintN(v []byte) uint64 {
	var out uint64
	if len(v) > 8 {
		v = v[len(v)-8:]
	}
	for _, b := range v {
		out = out<<8 | uint64(b)
	}
	return out
}
