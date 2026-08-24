package traffic

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/nizartuanku/loglight/netflow"
)

func openGraph(t *testing.T) *Graph {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	g, err := NewGraph(db)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestObserveFlushSnapshot(t *testing.T) {
	g := openGraph(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		g.Observe(netflow.Flow{SrcIP: "192.168.1.10", DstIP: "203.0.113.7", DstPort: 443, Proto: 6, Bytes: 1000, Packets: 3, End: now})
	}
	g.Observe(netflow.Flow{SrcIP: "192.168.1.10", DstIP: "192.168.1.20", DstPort: 5432, Proto: 6, Bytes: 500, Packets: 2, End: now})

	sev := func(ip string) string {
		if ip == "192.168.1.10" {
			return "high"
		}
		return ""
	}
	m, err := g.Snapshot(now.Add(-time.Hour), sev)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d: %+v", len(m.Nodes), m.Nodes)
	}
	if len(m.Links) != 2 {
		t.Fatalf("want 2 links, got %d", len(m.Links))
	}
	var found bool
	for _, n := range m.Nodes {
		if n.ID == "192.168.1.10" {
			found = true
			if n.Kind != "internal" || n.Severity != "high" {
				t.Fatalf("bad node: %+v", n)
			}
		}
		if n.ID == "203.0.113.7" && n.Kind != "external" {
			t.Fatalf("external node misclassified: %+v", n)
		}
	}
	if !found {
		t.Fatal("internal node missing")
	}
	for _, l := range m.Links {
		if l.Source == "192.168.1.10" && l.Target == "203.0.113.7" {
			if l.Bytes != 5000 || l.Flows != 5 || l.TopPort != 443 {
				t.Fatalf("aggregation wrong: %+v", l)
			}
		}
	}
	if m.Collapsed {
		t.Fatal("small graph must not collapse")
	}
}

func TestUpsertAcrossFlushes(t *testing.T) {
	g := openGraph(t)
	now := time.Now()
	g.Observe(netflow.Flow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80, Proto: 6, Bytes: 100, Packets: 1, End: now})
	if err := g.Flush(); err != nil {
		t.Fatal(err)
	}
	g.Observe(netflow.Flow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80, Proto: 6, Bytes: 200, Packets: 1, End: now.Add(time.Second)})
	m, err := g.Snapshot(now.Add(-time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Links) != 1 || m.Links[0].Bytes != 300 || m.Links[0].Flows != 2 {
		t.Fatalf("upsert failed: %+v", m.Links)
	}
}

func TestPruneByRetention(t *testing.T) {
	g := openGraph(t)
	old := time.Now().Add(-48 * time.Hour)
	g.Observe(netflow.Flow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80, Proto: 6, Bytes: 1, Packets: 1, End: old})
	g.Flush()
	if err := g.Prune(time.Now().Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	m, _ := g.Snapshot(time.Now().Add(-72*time.Hour), nil)
	if len(m.Links) != 0 {
		t.Fatalf("pruned edge still present: %+v", m.Links)
	}
}

func TestExternalCollapse(t *testing.T) {
	g := openGraph(t)
	now := time.Now()
	// 200 distinct external destinations in two /24s → must collapse to groups.
	for i := 0; i < 100; i++ {
		g.Observe(netflow.Flow{SrcIP: "192.168.1.10", DstIP: fmt.Sprintf("203.0.113.%d", i+1), DstPort: 443, Proto: 6, Bytes: 10, Packets: 1, End: now})
		g.Observe(netflow.Flow{SrcIP: "192.168.1.10", DstIP: fmt.Sprintf("198.51.100.%d", i+1), DstPort: 443, Proto: 6, Bytes: 10, Packets: 1, End: now})
	}
	m, err := g.Snapshot(now.Add(-time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Collapsed {
		t.Fatal("large external set did not collapse")
	}
	var groups, internals int
	for _, n := range m.Nodes {
		switch n.Kind {
		case "group":
			groups++
			if n.Members != 100 {
				t.Fatalf("group members wrong: %+v", n)
			}
		case "internal":
			internals++
		}
	}
	if groups != 2 || internals != 1 {
		t.Fatalf("want 2 groups + 1 internal, got %d/%d", groups, internals)
	}
}
