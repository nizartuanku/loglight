package logingest

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"
)

// Source is one configured ingest input. Run streams normalized Events to emit
// until ctx is cancelled. Implementations run concurrently (one goroutine each)
// and must be cancellation-safe. A Source never blocks the pipeline: emit is a
// fast hand-off onto the engine's channel.
type Source interface {
	ID() string
	Type() SourceType
	Run(ctx context.Context, emit func(Event)) error
}

// --- File tailer ------------------------------------------------------------

// FileSource follows a log file, emitting one Event per new line. It is
// rotation-safe: if the file is truncated (size shrinks) or replaced (inode
// changes), it reopens from the start. Existing content at startup is skipped
// (we tail new lines, like `tail -F`), unless FromStart is set.
type FileSource struct {
	SourceID  string
	Path      string
	Host      string
	App       string
	Kind      SourceType // SourceFile by default; may be SourceWindows for a forwarded file
	FromStart bool
	Poll      time.Duration // re-check interval; default 500ms

	Now func() time.Time
}

func (f *FileSource) ID() string         { return f.SourceID }
func (f *FileSource) Type() SourceType {
	if f.Kind != "" {
		return f.Kind
	}
	return SourceFile
}

func (f *FileSource) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *FileSource) Run(ctx context.Context, emit func(Event)) error {
	poll := f.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	var (
		file   *os.File
		reader *bufio.Reader
		offset int64
		inode  uint64
	)
	open := func() {
		if file != nil {
			file.Close()
			file, reader = nil, nil
		}
		fh, err := os.Open(f.Path)
		if err != nil {
			return
		}
		file = fh
		reader = bufio.NewReader(fh)
		if st, err := fh.Stat(); err == nil {
			inode = inodeOf(st)
			if f.FromStart {
				offset = 0
			} else {
				offset = st.Size()
				fh.Seek(offset, 0)
			}
		}
	}
	open()
	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		if file == nil {
			open()
			continue
		}
		st, err := os.Stat(f.Path)
		if err != nil {
			continue // file gone; wait for it to come back
		}
		// Rotation: truncated (smaller) or replaced (different inode).
		if st.Size() < offset || inodeOf(st) != inode {
			open()
		}
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				if line[len(line)-1] == '\n' {
					emit(ParseLine(f.Type(), f.SourceID, f.Host, f.App, line))
				} else {
					// partial line; rewind so we re-read it whole next tick
					offset -= int64(len(line))
					break
				}
			}
			if err != nil {
				break
			}
		}
	}
}

// --- helpers ----------------------------------------------------------------

// multiSource fans several sources into one; used by the engine.
type engineState struct {
	mu       sync.Mutex
	parseHit map[string]int64 // sourceID → parsed count
	parseTot map[string]int64 // sourceID → total count
}

func newEngineState() *engineState {
	return &engineState{parseHit: map[string]int64{}, parseTot: map[string]int64{}}
}

func (s *engineState) record(e Event) {
	s.mu.Lock()
	s.parseTot[e.SourceID]++
	if e.Parsed {
		s.parseHit[e.SourceID]++
	}
	s.mu.Unlock()
}

// ParseRate returns parsed/total for a source (1.0 when nothing seen yet).
func (s *engineState) ParseRate(sourceID string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	tot := s.parseTot[sourceID]
	if tot == 0 {
		return 1
	}
	return float64(s.parseHit[sourceID]) / float64(tot)
}
