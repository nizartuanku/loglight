// loglight is the Loglight product binary: self-hosted threat detection from
// logs on Sentinel Core.
//
//	loglight                       # dashboard on 127.0.0.1:8427
//	loglight -webhook <url>        # push incidents to a webhook
//
// Add ingest sources (syslog, file, journald, Docker, or forwarded Windows
// events) on the dashboard, and Loglight surfaces brute force, scanning,
// exfiltration, new-admin, and correlated kill-chain incidents — worst first.
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
	"github.com/nizartuanku/loglight/web"
)

// issuerPublicKeyB64 is baked in at build time by the release process.
// Empty → every key invalid → permanent free edition (this open-source build).
var issuerPublicKeyB64 = ""

// loglightTierLimits: free = 1 source, Pro = 10, Team = unlimited.
var loglightTierLimits = map[license.Tier]license.Limits{
	license.TierFree: {MaxTargets: 1, RetentionDays: 3, Channels: []string{"webhook"}},
	license.TierPro: {MaxTargets: 10, RetentionDays: 30,
		Channels: []string{"webhook", "email", "slack", "telegram"}, CustomInterval: true, ScanNow: true},
	license.TierTeam: {MaxTargets: 0, RetentionDays: 0,
		Channels:  []string{"webhook", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser: true, CustomInterval: true, ScanNow: true},
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8427", "dashboard listen address")
	dbPath := flag.String("db", "loglight.db", "SQLite database path")
	licFile := flag.String("license", "loglight-license.key", "license key file")
	webhook := flag.String("webhook", "", "webhook URL for alerts")
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
	engine := store.NewEngine(st)

	// Optional webhook dispatcher (Path A notifies through it immediately).
	var disp *notify.Dispatcher
	if *webhook != "" {
		disp = notify.NewDispatcher(notify.Config{}, &notify.WebhookChannel{URL: *webhook})
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
		if s, err := loglight.BuildSource(src); err == nil {
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
	server.Targets = st
	server.TierLimits = loglightTierLimits

	console := &loglight.Console{
		Store:     logStore,
		Caps:      func() int { return server.EffectiveLimits().MaxTargets },
		ParseRate: ingest.ParseRate,
		OnSaved: func(s loglight.SourceConfig) error {
			src, err := loglight.BuildSource(s)
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
