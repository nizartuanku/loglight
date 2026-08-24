// Package traffic aggregates flow records into a host-to-host traffic graph —
// the data behind the dashboard's 3D network map. Edges are upserted into
// SQLite from a small in-memory buffer (one flush every few seconds, so a busy
// network never turns into per-flow writes), pruned by the tier's retention,
// and snapshotted as a nodes+links JSON document. At SMB scale this graph is
// small; a graph database would be a dependency, not an improvement.
package traffic

import (
	"database/sql"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/nizartuanku/loglight/netflow"
)

// Graph buffers flow aggregates in memory and persists them to SQLite.
type Graph struct {
	mu   sync.Mutex
	db   *sql.DB
	pend map[edgeKey]*agg
	Now  func() time.Time
}

type edgeKey struct {
	Src, Dst string
	Port     int
	Proto    uint8
}

type agg struct {
	Flows, Bytes, Packets int64
	First, Last           time.Time
}

// NewGraph creates the traffic tables (idempotent) and returns the aggregator.
func NewGraph(db *sql.DB) (*Graph, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS traffic_edges (
		src      TEXT NOT NULL,
		dst      TEXT NOT NULL,
		port     INTEGER NOT NULL,
		proto    INTEGER NOT NULL,
		flows    INTEGER NOT NULL,
		bytes    INTEGER NOT NULL,
		packets  INTEGER NOT NULL,
		first_at TIMESTAMP NOT NULL,
		last_at  TIMESTAMP NOT NULL,
		PRIMARY KEY (src, dst, port, proto)
	); CREATE INDEX IF NOT EXISTS idx_traffic_last ON traffic_edges(last_at);`)
	if err != nil {
		return nil, err
	}
	return &Graph{db: db, pend: map[edgeKey]*agg{}}, nil
}

func (g *Graph) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// Observe buffers one flow. Safe for concurrent use (sources run in goroutines).
func (g *Graph) Observe(f netflow.Flow) {
	if f.SrcIP == "" || f.DstIP == "" {
		return
	}
	end := f.End
	if end.IsZero() {
		end = g.now()
	}
	k := edgeKey{Src: f.SrcIP, Dst: f.DstIP, Port: f.DstPort, Proto: f.Proto}
	g.mu.Lock()
	a := g.pend[k]
	if a == nil {
		if len(g.pend) > 50_000 { // bounded buffer: force a flush point
			g.mu.Unlock()
			g.Flush()
			g.mu.Lock()
		}
		a = &agg{First: end}
		g.pend[k] = a
	}
	a.Flows++
	a.Bytes += f.Bytes
	a.Packets += f.Packets
	if end.After(a.Last) {
		a.Last = end
	}
	if end.Before(a.First) {
		a.First = end
	}
	g.mu.Unlock()
}

// Flush upserts the buffered aggregates into SQLite.
func (g *Graph) Flush() error {
	g.mu.Lock()
	pend := g.pend
	g.pend = map[edgeKey]*agg{}
	g.mu.Unlock()
	if len(pend) == 0 {
		return nil
	}
	tx, err := g.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO traffic_edges (src,dst,port,proto,flows,bytes,packets,first_at,last_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(src,dst,port,proto) DO UPDATE SET
		  flows=flows+excluded.flows, bytes=bytes+excluded.bytes, packets=packets+excluded.packets,
		  last_at=MAX(last_at, excluded.last_at)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for k, a := range pend {
		if _, err := stmt.Exec(k.Src, k.Dst, k.Port, k.Proto, a.Flows, a.Bytes, a.Packets, a.First, a.Last); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Prune drops edges quiet since before. Retention follows the tier, exactly
// like findings do.
func (g *Graph) Prune(before time.Time) error {
	_, err := g.db.Exec(`DELETE FROM traffic_edges WHERE last_at < ?`, before)
	return err
}

// RunFlusher flushes every interval until stop is closed. The cmd runs it.
func (g *Graph) RunFlusher(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			g.Flush()
			return
		case <-t.C:
			g.Flush()
		}
	}
}

// --- snapshot ----------------------------------------------------------------

// Node is one vertex of the map. Kind: "internal" | "external" | "group"
// (an aggregated external /24). Severity is the worst open detection whose
// actor or target is this node ("" = none).
type Node struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Bytes    int64  `json:"bytes"`
	Flows    int64  `json:"flows"`
	Severity string `json:"severity,omitempty"`
	Members  int    `json:"members,omitempty"` // >1 on aggregated groups
}

// Link is one edge of the map (direction preserved, ports folded per pair).
type Link struct {
	Source  string `json:"source"`
	Target  string `json:"target"`
	Bytes   int64  `json:"bytes"`
	Flows   int64  `json:"flows"`
	TopPort int    `json:"top_port"`
}

// MapData is the /api/loglight/trafficmap payload.
type MapData struct {
	Nodes       []Node    `json:"nodes"`
	Links       []Link    `json:"links"`
	GeneratedAt time.Time `json:"generated_at"`
	WindowFrom  time.Time `json:"window_from"`
	Collapsed   bool      `json:"collapsed"` // externals grouped per /24
}

// maxExternals before external nodes collapse into /24 groups. Internal hosts
// are never collapsed — they are what the customer runs.
const maxExternals = 150

// Snapshot builds the map over edges active since 'since'. severityOf maps a
// host to its worst open-detection severity ("" when quiet).
func (g *Graph) Snapshot(since time.Time, severityOf func(ip string) string) (MapData, error) {
	if err := g.Flush(); err != nil {
		return MapData{}, err
	}
	rows, err := g.db.Query(`SELECT src,dst,port,flows,bytes FROM traffic_edges WHERE last_at >= ?`, since)
	if err != nil {
		return MapData{}, err
	}
	defer rows.Close()

	type rawEdge struct {
		src, dst     string
		port         int
		flows, bytes int64
	}
	var edges []rawEdge
	externals := map[string]bool{}
	for rows.Next() {
		var e rawEdge
		if err := rows.Scan(&e.src, &e.dst, &e.port, &e.flows, &e.bytes); err != nil {
			return MapData{}, err
		}
		edges = append(edges, e)
		if !netflow.IsPrivate(e.src) {
			externals[e.src] = true
		}
		if !netflow.IsPrivate(e.dst) {
			externals[e.dst] = true
		}
	}
	if err := rows.Err(); err != nil {
		return MapData{}, err
	}

	collapse := len(externals) > maxExternals
	name := func(ip string) (id, kind string, members int) {
		if netflow.IsPrivate(ip) {
			return ip, "internal", 1
		}
		if collapse {
			return cidr24(ip), "group", 1
		}
		return ip, "external", 1
	}

	nodes := map[string]*Node{}
	links := map[[2]string]*Link{}
	portBytes := map[[2]string]map[int]int64{}
	groupMembers := map[string]map[string]bool{}
	for _, e := range edges {
		sid, skind, _ := name(e.src)
		did, dkind, _ := name(e.dst)
		for _, nk := range [][2]string{{sid, skind}, {did, dkind}} {
			n := nodes[nk[0]]
			if n == nil {
				n = &Node{ID: nk[0], Kind: nk[1]}
				nodes[nk[0]] = n
			}
			n.Bytes += e.bytes
			n.Flows += e.flows
		}
		if skind == "group" {
			addMember(groupMembers, sid, e.src)
		}
		if dkind == "group" {
			addMember(groupMembers, did, e.dst)
		}
		if sid == did {
			continue
		}
		lk := [2]string{sid, did}
		l := links[lk]
		if l == nil {
			l = &Link{Source: sid, Target: did}
			links[lk] = l
			portBytes[lk] = map[int]int64{}
		}
		l.Bytes += e.bytes
		l.Flows += e.flows
		portBytes[lk][e.port] += e.bytes
	}

	out := MapData{GeneratedAt: g.now(), WindowFrom: since, Collapsed: collapse}
	for _, n := range nodes {
		if severityOf != nil && n.Kind != "group" {
			n.Severity = severityOf(n.ID)
		}
		if m := groupMembers[n.ID]; m != nil {
			n.Members = len(m)
		}
		out.Nodes = append(out.Nodes, *n)
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	for lk, l := range links {
		var topPort int
		var topBytes int64 = -1
		for p, b := range portBytes[lk] {
			if b > topBytes {
				topBytes, topPort = b, p
			}
		}
		l.TopPort = topPort
		out.Links = append(out.Links, *l)
	}
	sort.Slice(out.Links, func(i, j int) bool {
		if out.Links[i].Source != out.Links[j].Source {
			return out.Links[i].Source < out.Links[j].Source
		}
		return out.Links[i].Target < out.Links[j].Target
	})
	return out, nil
}

func addMember(m map[string]map[string]bool, group, ip string) {
	set := m[group]
	if set == nil {
		set = map[string]bool{}
		m[group] = set
	}
	set[ip] = true
}

// cidr24 maps an IPv4 address to its /24 label; IPv6 to its /48.
func cidr24(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if a.Is4() {
		p, _ := a.Prefix(24)
		return p.String()
	}
	p, _ := a.Prefix(48)
	return p.String()
}
