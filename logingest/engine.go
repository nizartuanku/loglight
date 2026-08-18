package logingest

import (
	"context"
	"sync"
)

// Engine runs a set of Sources concurrently and delivers every normalized Event
// to a single handler, in order per source. It tracks a per-source parse-rate so
// the dashboard can show ingest coverage honestly (like RuleHawk's unparsed
// finding). Sources can be added/removed while running — the pipeline
// reconfigures live.
type Engine struct {
	state   *engineState
	handler func(Event)

	mu      sync.Mutex
	running map[string]context.CancelFunc // sourceID → cancel
	baseCtx context.Context
}

// NewEngine builds an engine that calls handler for every Event. handler must be
// fast and safe for concurrent calls (events arrive from many source goroutines).
func NewEngine(handler func(Event)) *Engine {
	return &Engine{
		state:   newEngineState(),
		handler: handler,
		running: map[string]context.CancelFunc{},
	}
}

// Start binds a base context; sources added later inherit cancellation from it.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	e.baseCtx = ctx
	e.mu.Unlock()
	go func() {
		<-ctx.Done()
		e.mu.Lock()
		for id, cancel := range e.running {
			cancel()
			delete(e.running, id)
		}
		e.mu.Unlock()
	}()
}

// Add registers and runs a source. Re-adding the same ID replaces the old one.
func (e *Engine) Add(s Source) {
	e.mu.Lock()
	base := e.baseCtx
	if base == nil {
		base = context.Background()
	}
	if cancel, ok := e.running[s.ID()]; ok {
		cancel() // replace an existing source of the same id
	}
	ctx, cancel := context.WithCancel(base)
	e.running[s.ID()] = cancel
	e.mu.Unlock()

	go func() {
		emit := func(ev Event) {
			if ev.SourceID == "" {
				ev.SourceID = s.ID()
			}
			e.state.record(ev)
			e.handler(ev)
		}
		_ = s.Run(ctx, emit) // a source error just stops that source; others run on
	}()
}

// Remove stops a source by id.
func (e *Engine) Remove(id string) {
	e.mu.Lock()
	if cancel, ok := e.running[id]; ok {
		cancel()
		delete(e.running, id)
	}
	e.mu.Unlock()
}

// ParseRate returns the parsed/total ratio for a source (1.0 if none seen).
func (e *Engine) ParseRate(id string) float64 { return e.state.ParseRate(id) }
