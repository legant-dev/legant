package auth

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/live"
)

// LiveHandler serves the superadmin real-time console: a dashboard shell, a JSON
// snapshot of the current authority graph, and an SSE stream of live activity
// events (mints, revocations, gateway decisions) fanned out from the hub.
type LiveHandler struct {
	pool        *pgxpool.Pool
	sessions    *SessionManager
	tmpl        *template.Template
	hub         *live.Hub
	pub         *live.Publisher // cross-process emit for ingested decisions
	ingestToken string          // shared secret for POST /admin/live/ingest ("" disables)
}

func NewLiveHandler(pool *pgxpool.Pool, sessions *SessionManager, tmpl *template.Template, hub *live.Hub, pub *live.Publisher, ingestToken string) *LiveHandler {
	return &LiveHandler{pool: pool, sessions: sessions, tmpl: tmpl, hub: hub, pub: pub, ingestToken: ingestToken}
}

// Ingest accepts an allow/deny decision from a connected resource server (a
// `legant guard` hook) and publishes it to the live console. It is authenticated
// by a shared bearer token (not a user session), so an off-box guard with no
// Legant login can report. Disabled (404) unless a token is configured. The event
// goes through the cross-process publisher so every replica's console sees it.
func (h *LiveHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	if h.ingestToken == "" {
		http.NotFound(w, r)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.ingestToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Decision   string `json:"decision"` // ALLOW | DENY
		Subject    string `json:"subject"`
		Actor      string `json:"actor"`
		Provenance string `json:"provenance"`
		Tool       string `json:"tool"`
		Reason     string `json:"reason"`
		Source     string `json:"source"` // e.g. "claude-code"
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	decision := strings.ToUpper(strings.TrimSpace(req.Decision))
	if decision != "ALLOW" && decision != "DENY" {
		http.Error(w, "decision must be ALLOW or DENY", http.StatusBadRequest)
		return
	}
	source := req.Source
	if source == "" {
		source = "resource-server"
	}
	e := live.Event{
		Type:       "decision",
		Decision:   decision,
		Subject:    req.Subject,
		Actor:      req.Actor,
		Provenance: req.Provenance,
		Tool:       req.Tool,
		Upstream:   source,
		Reason:     req.Reason,
		Time:       time.Now(),
	}
	if h.pub != nil {
		h.pub.Publish(e) // NOTIFY → every replica's Listener → Hub → SSE
	} else {
		h.hub.Publish(e)
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorize enforces session + superadmin, mirroring the audit viewer. On
// failure it writes the response (a login redirect for a page, 401/403 for an
// API/SSE call) and returns false.
func (h *LiveHandler) authorize(w http.ResponseWriter, r *http.Request, page bool) bool {
	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil || sess.UserID == "" {
		if page {
			http.Redirect(w, r, "/login?redirect=/admin/live", http.StatusFound)
		} else {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}
		return false
	}
	var isSuper bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT is_superadmin FROM users WHERE id = $1 AND status = 'active'`, sess.UserID).Scan(&isSuper); err != nil || !isSuper {
		http.Error(w, "superadmin access required", http.StatusForbidden)
		return false
	}
	return true
}

// Dashboard renders the live console shell.
func (h *LiveHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, true) {
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "live.html", map[string]any{}); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// Snapshot returns the current active authority graph as JSON. The console
// fetches it on load and refreshes it when a mint or revoke arrives.
func (h *LiveHandler) Snapshot(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, false) {
		return
	}
	g, err := live.Snapshot(r.Context(), h.pool)
	if err != nil {
		http.Error(w, "snapshot error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(g)
}

// Events streams live activity as Server-Sent Events.
func (h *LiveHandler) Events(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, false) {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // defang nginx proxy buffering

	rc := http.NewResponseController(w)
	// Clear the server's WriteTimeout for this long-lived stream (best-effort:
	// if the writer chain doesn't support it, EventSource simply reconnects).
	_ = rc.SetWriteDeadline(time.Time{})

	sub, stop := h.hub.Subscribe(128)
	defer stop()

	// Replay a tail of the recent ring so a freshly-opened console isn't blank
	// (the UI only renders ~16 lines, so the whole 300-entry ring isn't needed).
	recent := h.hub.Recent()
	if len(recent) > 60 {
		recent = recent[len(recent)-60:]
	}
	for _, e := range recent {
		writeSSE(w, e)
	}
	_ = rc.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-sub:
			if !ok {
				return
			}
			writeSSE(w, e)
			_ = rc.Flush()
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			_ = rc.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e live.Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
}
