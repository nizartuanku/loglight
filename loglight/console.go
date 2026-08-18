package loglight

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Console serves Loglight's source endpoints (add/list/delete an ingest source)
// and the live incidents view. The cmd wires OnSaved (register the scheduler
// target + persist + start the live source) and OnDelete (stop it).
type Console struct {
	Store     Store
	Caps      func() int                 // max sources for the tier (0 = unlimited)
	OnSaved   func(s SourceConfig) error // start ingesting + register target
	OnDelete  func(name string)          // stop ingesting + deregister
	ParseRate func(name string) float64  // live parse-rate probe (nil → omit)
	Now       func() time.Time
}

// Register mounts the console routes.
func (c *Console) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/loglight/sources", c.handleList)
	mux.HandleFunc("POST /api/loglight/source", c.handleSave)
	mux.HandleFunc("DELETE /api/loglight/source", c.handleDelete)
	mux.HandleFunc("GET /api/loglight/incidents", c.handleIncidents)
}

func (c *Console) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type sourceView struct {
	SourceConfig
	ParseRate float64 `json:"parse_rate"`
}

// SourceTypes lists the ingest source kinds the console accepts.
func SourceTypes() []map[string]string {
	return []map[string]string{
		{"id": "syslog", "label": "Syslog (UDP/TCP)"},
		{"id": "file", "label": "File tail"},
		{"id": "journald", "label": "systemd journald"},
		{"id": "docker", "label": "Docker container"},
		{"id": "windows", "label": "Windows Event (via syslog forwarder)"},
	}
}

func (c *Console) handleList(w http.ResponseWriter, r *http.Request) {
	srcs, err := c.Store.ListSources()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]sourceView, 0, len(srcs))
	for _, s := range srcs {
		v := sourceView{SourceConfig: s, ParseRate: 1}
		if c.ParseRate != nil {
			v.ParseRate = c.ParseRate(s.Name)
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": views, "types": SourceTypes()})
}

type saveRequest struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

func (c *Console) handleSave(w http.ResponseWriter, r *http.Request) {
	var req saveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		httpErr(w, http.StatusBadRequest, "a source name is required")
		return
	}
	if req.Params == nil {
		req.Params = map[string]string{}
	}
	if err := validateSource(req.Type, req.Params); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}

	_, exists, _ := c.Store.GetSource(req.Name)
	if !exists && c.Caps != nil {
		if max := c.Caps(); max != 0 {
			if srcs, _ := c.Store.ListSources(); len(srcs) >= max {
				httpErr(w, http.StatusForbidden, "source limit reached for your tier — upgrade to add more")
				return
			}
		}
	}

	src := SourceConfig{Name: req.Name, Type: req.Type, Params: req.Params, Enabled: true, CreatedAt: c.now()}
	if err := c.Store.PutSource(src); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c.OnSaved != nil {
		if err := c.OnSaved(src); err != nil {
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": req.Name, "type": req.Type})
}

func (c *Console) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		httpErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if c.OnDelete != nil {
		c.OnDelete(name)
	}
	if err := c.Store.DeleteSource(name); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

// handleIncidents returns the currently-active detections/incidents across all
// sources for the live view, newest first, correlated incidents ranked top.
func (c *Console) handleIncidents(w http.ResponseWriter, r *http.Request) {
	srcs, err := c.Store.ListSources()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cutoff := c.now().Add(-ActiveWindow)
	var live []map[string]any
	for _, s := range srcs {
		dets, _ := c.Store.ListDetections(s.Name)
		for _, d := range dets {
			if d.LastAt.Before(cutoff) {
				continue
			}
			live = append(live, map[string]any{
				"key": d.Key, "source": d.SourceID, "check": d.Check, "severity": d.Severity,
				"actor": d.Actor, "target": d.Target, "title": d.Title, "detail": d.Detail,
				"evidence": d.Evidence, "count": d.Count,
				"first_at": d.FirstAt.Format(time.RFC3339), "last_at": d.LastAt.Format(time.RFC3339),
				"incident": strings.HasPrefix(d.Check, "incident."),
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": live})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
