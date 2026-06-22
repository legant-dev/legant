package auth

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/legant-dev/legant/internal/audit"
)

// AdminHandler serves superadmin dashboard pages — currently the tamper-evident
// audit/provenance viewer, the user-facing surface of Legant's most
// differentiated asset (who-acted-for-whom, provably).
type AdminHandler struct {
	pool     *pgxpool.Pool
	sessions *SessionManager
	tmpl     *template.Template
}

func NewAdminHandler(pool *pgxpool.Pool, sessions *SessionManager, tmpl *template.Template) *AdminHandler {
	return &AdminHandler{pool: pool, sessions: sessions, tmpl: tmpl}
}

type auditRow struct {
	Time       string
	Actor      string
	Action     string
	Provenance string
	Resource   string
}

// Audit renders the audit trail with provenance and a chain-verified badge.
func (h *AdminHandler) Audit(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil || sess.UserID == "" {
		http.Redirect(w, r, "/login?redirect=/admin/audit", http.StatusFound)
		return
	}
	var isSuper bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT is_superadmin FROM users WHERE id = $1 AND status = 'active'`, sess.UserID).Scan(&isSuper); err != nil || !isSuper {
		http.Error(w, "superadmin access required", http.StatusForbidden)
		return
	}

	f := audit.Filter{
		Action:     r.URL.Query().Get("action"),
		OnBehalfOf: r.URL.Query().Get("on_behalf_of_sub"),
		ActorType:  r.URL.Query().Get("actor_type"),
		Limit:      100,
	}
	events, total, err := audit.Query(r.Context(), h.pool, f)
	if err != nil {
		http.Error(w, "could not load audit log", http.StatusInternalServerError)
		return
	}
	verify, _ := audit.Verify(r.Context(), h.pool)

	rows := make([]auditRow, 0, len(events))
	for _, e := range events {
		actor := e.ActorType
		if e.ActorID != "" {
			actor = e.ActorType + ":" + short(e.ActorID)
		}
		resource := e.ResourceType
		if e.ResourceID != "" {
			resource = e.ResourceType + " " + e.ResourceID
		}
		rows = append(rows, auditRow{
			Time:       e.CreatedAt.UTC().Format("2006-01-02 15:04:05 MST"),
			Actor:      actor,
			Action:     e.Action,
			Provenance: provenance(e.OnBehalfOf, e.ActorChain),
			Resource:   resource,
		})
	}

	data := map[string]any{
		"Rows":     rows,
		"Total":    total,
		"VerifyOK": verify.OK,
		"Events":   verify.Events,
		"HeadHash": shortHash(verify.HeadHash),
		"Break":    verify.BreakKind,
		"BreakID":  verify.BreakID,
		"Filter": map[string]string{
			"action":           f.Action,
			"on_behalf_of_sub": f.OnBehalfOf,
			"actor_type":       f.ActorType,
		},
	}
	if err := h.tmpl.ExecuteTemplate(w, "audit.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// provenance renders "user:alice -> agent:assistant -> agent:ocr" from the
// on-behalf-of subject and the actor chain (stored most-recent-first).
func provenance(onBehalfOf string, chain []string) string {
	if onBehalfOf == "" && len(chain) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(chain)+1)
	if onBehalfOf != "" {
		parts = append(parts, onBehalfOf)
	}
	for i := len(chain) - 1; i >= 0; i-- { // reverse to root..leaf
		parts = append(parts, chain[i])
	}
	return strings.Join(parts, " → ")
}

func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}
