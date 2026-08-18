package logingest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileSourceTailAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("preexisting line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []Event
	fs := &FileSource{SourceID: "auth", Path: path, Poll: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fs.Run(ctx, func(e Event) { mu.Lock(); got = append(got, e); mu.Unlock() })

	time.Sleep(60 * time.Millisecond) // let it seek to end (skip preexisting)

	appendLine(t, path, "<38>Aug 17 11:22:33 web01 sshd[1]: Failed password for admin from 203.0.113.9 port 1 ssh2\n")
	waitFor(t, &mu, &got, 1)

	// Rotate: replace the file (new inode), then write.
	os.Rename(path, path+".1")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	appendLine(t, path, "Accepted password for deploy from 203.0.113.9 port 2 ssh2\n")
	waitFor(t, &mu, &got, 2)

	mu.Lock()
	defer mu.Unlock()
	if len(got) < 2 {
		t.Fatalf("expected >=2 events across rotation, got %d", len(got))
	}
	if got[0].Auth != AuthFailure {
		t.Errorf("first event auth=%q", got[0].Auth)
	}
	if got[len(got)-1].Auth != AuthSuccess {
		t.Errorf("post-rotation event auth=%q", got[len(got)-1].Auth)
	}
	// preexisting line must NOT appear (we tail new lines only)
	for _, e := range got {
		if e.Raw == "preexisting line\n" {
			t.Errorf("should not have emitted preexisting content")
		}
	}
}

func TestEngineParseRate(t *testing.T) {
	var seen int
	var mu sync.Mutex
	e := NewEngine(func(Event) { mu.Lock(); seen++; mu.Unlock() })
	e.Start(context.Background())
	// A source that emits one parsed and one unparsed event then idles.
	e.Add(&fixedSource{id: "s1", evs: []Event{
		{SourceID: "s1", Parsed: true}, {SourceID: "s1", Parsed: false},
	}})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := seen
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := e.ParseRate("s1"); r != 0.5 {
		t.Errorf("parse rate should be 0.5, got %v", r)
	}
}

type fixedSource struct {
	id  string
	evs []Event
}

func (f *fixedSource) ID() string         { return f.id }
func (f *fixedSource) Type() SourceType   { return SourceFile }
func (f *fixedSource) Run(ctx context.Context, emit func(Event)) error {
	for _, e := range f.evs {
		emit(e)
	}
	<-ctx.Done()
	return ctx.Err()
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, mu *sync.Mutex, got *[]Event, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := len(*got)
		mu.Unlock()
		if c >= n {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events", n)
}
