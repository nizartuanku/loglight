// loglight is the Loglight product binary: self-hosted threat detection from
// logs and network flows on Hexward Core.
//
//	loglight                       # dashboard on 127.0.0.1:8427
//	loglight -webhook <url>        # push incidents to a webhook
//
// Add ingest sources (syslog, file, journald, Docker, forwarded Windows
// events, or NetFlow/IPFIX from a router) on the dashboard, and Loglight
// surfaces brute force, scanning, exfiltration, new-admin, beaconing,
// new-service, and correlated kill-chain incidents — worst first, plus a 3D
// map of who talks to whom on the network.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3" // dev driver; release swaps to modernc.org/sqlite

	"github.com/nizartuanku/loglight/correlate"
	"github.com/nizartuanku/loglight/detect"
	"github.com/nizartuanku/loglight/license"
	"github.com/nizartuanku/loglight/logingest"
	"github.com/nizartuanku/loglight/loglight"
	"github.com/nizartuanku/loglight/notify"
	"github.com/nizartuanku/loglight/sched"
	"github.com/nizartuanku/loglight/store"
	"github.com/nizartuanku/loglight/traffic"
	"github.com/nizartuanku/loglight/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// loglightTierLimits: free = 1 source, Pro = 10, Team = unlimited.
var loglightTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 1, RetentionDays: 3, Channels: []string{"webhook", "syslog"}},
	license.TierPro: {MaxTargets: 10, RetentionDays: 30,
		Channels: []string{"webhook", "syslog", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "syslog", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8427", "dashboard listen address")
	dbPath := flag.String("db", "loglight.db", "SQLite database path")
	licFile := flag.String("license", "loglight-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
	syslogAddr := flag.String("syslog", "", "syslog collector host:port for findings, e.g. 127.0.0.1:5514 (point this at Loglight to correlate across products)")
	syslogNet := flag.String("syslog-network", "udp", "syslog transport: udp or tcp")
	aiURL := flag.String("ai-assist-url", os.Getenv("LOGLIGHT_AI_ASSIST_URL"), "optional hexward-ai sidecar URL for AI-narrated explanations, e.g. http://127.0.0.1:8435 (off when empty)")
	aiKeyFile := flag.String("ai-assist-key-file", os.Getenv("LOGLIGHT_AI_ASSIST_KEY_FILE"), "API key file for a dedicated AI host or your own OpenAI-compatible endpoint (Pro/Team)")
	aiLang := flag.String("ai-assist-lang", os.Getenv("LOGLIGHT_AI_ASSIST_LANG"), "language of AI explanations: en (default) or id")
	aiNoThinking := flag.Bool("ai-assist-no-thinking", os.Getenv("LOGLIGHT_AI_ASSIST_NO_THINKING") == "1", "disable reasoning mode (Qwen3 enterprise profiles)")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fatal("open database: " + err.Error())
	}
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	logStore, err := loglight.NewSQLiteStore(db)
	if err != nil {
		fatal(err.Error())
	}
	graph, err := traffic.NewGraph(db)
	if err != nil {
		fatal(err.Error())
	}
	engine := store.NewEngine(st)

	// Optional webhook dispatcher (Path A notifies through it immediately).
	var disp *notify.Dispatcher
	var channels []notify.Channel
	if *webhook != "" {
		channels = append(channels, &notify.WebhookChannel{URL: *webhook})
	}
	if *syslogAddr != "" {
		channels = append(channels, &notify.SyslogChannel{Addr: *syslogAddr, Network: *syslogNet})
	}
	if len(channels) > 0 {
		disp = notify.NewDispatcher(notify.Config{}, channels...)
		defer disp.Close()
	}

	// Detection + correlation + ingest pipeline (Path A).
	detEngine := detect.NewEngine(detect.Config{})
	corr := correlate.New(10*time.Minute, 15*time.Minute)
	pipeline := &loglight.Pipeline{Detect: detEngine, Corr: corr, Log: logStore, Store: st, Disp: disp}
	ingest := logingest.NewEngine(pipeline.Handle)

	// Backstop Collector (Path B).
	module := loglight.New(logStore, ingest.ParseRate)
	scheduler := sched.New(engine, sched.Config{})
	if err := scheduler.Register(module); err != nil {
		fatal(err.Error())
	}
	modID := module.Describe().ID

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ingest.Start(ctx)

	// Restore saved sources: start ingesting + register the scheduler target.
	startSource := func(name string) {
		src, ok, err := logStore.GetSource(name)
		if err != nil || !ok {
			return
		}
		if s, err := loglight.BuildSourceWith(src, loglight.SourceDeps{OnFlow: graph.Observe}); err == nil {
			ingest.Add(s)
		} else {
			fmt.Fprintf(os.Stderr, "loglight: source %q not started: %v\n", name, err)
		}
	}
	if saved, err := st.ListSavedTargets(modID); err == nil {
		for _, raw := range saved {
			if _, err := scheduler.AddTarget(modID, raw); err != nil {
				fmt.Fprintf(os.Stderr, "loglight: skipping saved source %q: %v\n", raw, err)
				continue
			}
			startSource(raw)
		}
	}

	var pub ed25519.PublicKey
	if issuerPublicKeyB64 != "" {
		if b, err := base64.StdEncoding.DecodeString(issuerPublicKeyB64); err == nil {
			pub = ed25519.PublicKey(b)
		}
	}
	server := web.NewServer(module.Describe(), st, scheduler, pub, *licFile)

	aiAssist, aiErr := web.NewAIAssist(web.AIConfig{URL: *aiURL, KeyFile: *aiKeyFile, Language: *aiLang, NoThinking: *aiNoThinking})
	if aiErr != nil {
		fmt.Fprintln(os.Stderr, "loglight: "+aiErr.Error())
		os.Exit(2)
	}
	server.AI = aiAssist
	if aiAssist != nil {
		fmt.Fprintf(os.Stderr, "loglight: AI Assist on — explanations from %s (language %s)\n", aiAssist.Endpoint, aiAssist.Language)
	}
	server.Targets = st
	server.TierLimits = loglightTierLimits

	console := &loglight.Console{
		Store:     logStore,
		Caps:      func() int { return server.EffectiveLimits().MaxTargets },
		ParseRate: ingest.ParseRate,
		Traffic: func() (any, error) {
			// Map window follows the tier's retention (free 3d, Pro 30d, ∞ Team).
			since := time.Time{}
			if days := server.EffectiveLimits().RetentionDays; days > 0 {
				since = time.Now().AddDate(0, 0, -days)
			}
			return graph.Snapshot(since, func(ip string) string {
				return worstDetectionSeverity(logStore, ip)
			})
		},
		OnSaved: func(s loglight.SourceConfig) error {
			src, err := loglight.BuildSourceWith(s, loglight.SourceDeps{OnFlow: graph.Observe})
			if err != nil {
				return err
			}
			if _, err := scheduler.AddTarget(modID, s.Name); err != nil {
				return err
			}
			ingest.Add(src)
			return st.SaveTarget(modID, s.Name, s.Name)
		},
		OnDelete: func(name string) {
			ingest.Remove(name)
			scheduler.RemoveTarget(modID, name)
			_ = st.DeleteTarget(modID, name)
		},
	}
	server.ExtraRoutes = console.Register

	if disp != nil {
		notify.BindScheduler(scheduler, disp) // Path B digests too
	}

	if err := scheduler.Start(ctx); err != nil {
		fatal(err.Error())
	}

	// Prune events/detections older than the active window periodically.
	go pruneLoop(ctx, logStore)

	// Flush the traffic graph buffer and prune it by the tier's retention.
	go graph.RunFlusher(ctx.Done(), 5*time.Second)
	go trafficPruneLoop(ctx, graph, func() int { return server.EffectiveLimits().RetentionDays })

	httpSrv := &http.Server{Addr: *listen, Handler: server.Handler()}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sc)
		scheduler.Stop()
	}()

	fmt.Printf("Loglight %s — %s edition\n", module.Describe().Version, server.Activation().Tier)
	fmt.Printf("Dashboard: http://%s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal(err.Error())
	}
}

// worstDetectionSeverity maps a host to the worst active detection touching it,
// so the 3D map can colour compromised hosts.
func worstDetectionSeverity(s loglight.Store, ip string) string {
	dets, err := s.ListDetections("")
	if err != nil {
		return ""
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	worst := ""
	for _, d := range dets {
		if d.Actor != ip && d.Target != ip {
			continue
		}
		if rank[d.Severity] > rank[worst] {
			worst = d.Severity
		}
	}
	return worst
}

func trafficPruneLoop(ctx context.Context, g *traffic.Graph, retentionDays func() int) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if days := retentionDays(); days > 0 {
				_ = g.Prune(time.Now().AddDate(0, 0, -days))
			}
		}
	}
}

func pruneLoop(ctx context.Context, s loglight.Store) {
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = s.PruneDetections(time.Now().Add(-2 * loglight.ActiveWindow))
		}
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "loglight: "+msg)
	os.Exit(1)
}
