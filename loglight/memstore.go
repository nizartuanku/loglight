package loglight

import (
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store for tests and ephemeral runs.
type MemStore struct {
	mu      sync.RWMutex
	sources map[string]SourceConfig
	dets    map[string]DetectionRecord // keyed by SourceID+"\x00"+Key
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{sources: map[string]SourceConfig{}, dets: map[string]DetectionRecord{}}
}

func (m *MemStore) PutSource(s SourceConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sources[s.Name] = s
	return nil
}

func (m *MemStore) GetSource(name string) (SourceConfig, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sources[name]
	return s, ok, nil
}

func (m *MemStore) ListSources() ([]SourceConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SourceConfig, 0, len(m.sources))
	for _, s := range m.sources {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *MemStore) DeleteSource(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sources, name)
	return nil
}

func detKey(sourceID, key string) string { return sourceID + "\x00" + key }

func (m *MemStore) UpsertDetection(d DetectionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := detKey(d.SourceID, d.Key)
	if existing, ok := m.dets[k]; ok {
		// preserve the earliest FirstAt on recurrence
		if existing.FirstAt.Before(d.FirstAt) {
			d.FirstAt = existing.FirstAt
		}
	}
	m.dets[k] = d
	return nil
}

func (m *MemStore) ListDetections(sourceID string) ([]DetectionRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []DetectionRecord
	for _, d := range m.dets {
		if d.SourceID == sourceID {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAt.After(out[j].LastAt) })
	return out, nil
}

func (m *MemStore) PruneDetections(before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, d := range m.dets {
		if d.LastAt.Before(before) {
			delete(m.dets, k)
		}
	}
	return nil
}
