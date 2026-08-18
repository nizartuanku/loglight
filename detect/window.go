package detect

import "time"

// slidingCounter counts events per key within a time window, pruning old
// entries. Bounded by design: only timestamps inside the window are retained.
type slidingCounter struct {
	window time.Duration
	times  map[string][]time.Time
}

func newSlidingCounter(w time.Duration) *slidingCounter {
	return &slidingCounter{window: w, times: map[string][]time.Time{}}
}

// add records an event for key at t and returns the count within the window.
func (s *slidingCounter) add(key string, t time.Time) int {
	cutoff := t.Add(-s.window)
	buf := append(s.times[key], t)
	i := 0
	for ; i < len(buf); i++ {
		if !buf[i].Before(cutoff) {
			break
		}
	}
	buf = buf[i:]
	s.times[key] = buf
	return len(buf)
}

// reset clears a key (used after firing so the window starts fresh).
func (s *slidingCounter) reset(key string) { delete(s.times, key) }

// distinctWindow tracks the set of distinct values seen per key within a window.
type distinctWindow struct {
	window time.Duration
	seen   map[string]map[string]time.Time
}

func newDistinctWindow(w time.Duration) *distinctWindow {
	return &distinctWindow{window: w, seen: map[string]map[string]time.Time{}}
}

// add records value under key at t and returns the distinct count in the window.
func (d *distinctWindow) add(key, value string, t time.Time) int {
	cutoff := t.Add(-d.window)
	m := d.seen[key]
	if m == nil {
		m = map[string]time.Time{}
		d.seen[key] = m
	}
	m[value] = t
	for v, ts := range m {
		if ts.Before(cutoff) {
			delete(m, v)
		}
	}
	return len(m)
}

func (d *distinctWindow) reset(key string) { delete(d.seen, key) }

// sumWindow tracks a rolling sum per key within a window (for egress bytes).
type sumWindow struct {
	window time.Duration
	events map[string][]sample
}

type sample struct {
	t time.Time
	v int64
}

func newSumWindow(w time.Duration) *sumWindow {
	return &sumWindow{window: w, events: map[string][]sample{}}
}

// add records value at t and returns the sum within the window.
func (s *sumWindow) add(key string, t time.Time, v int64) int64 {
	cutoff := t.Add(-s.window)
	buf := append(s.events[key], sample{t, v})
	i := 0
	for ; i < len(buf); i++ {
		if !buf[i].t.Before(cutoff) {
			break
		}
	}
	buf = buf[i:]
	s.events[key] = buf
	var total int64
	for _, e := range buf {
		total += e.v
	}
	return total
}

// cooldown suppresses repeated firing of the same key within a window.
type cooldown struct {
	d    time.Duration
	last map[string]time.Time
}

func newCooldown(d time.Duration) *cooldown {
	return &cooldown{d: d, last: map[string]time.Time{}}
}

// firable reports whether key may fire at t (and records the fire if so).
func (c *cooldown) firable(key string, t time.Time) bool {
	if last, ok := c.last[key]; ok && t.Sub(last) < c.d {
		return false
	}
	c.last[key] = t
	return true
}
