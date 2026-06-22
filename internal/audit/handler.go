package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler serves the read side of the tamper-evident audit trail.
type Handler struct {
	pool *pgxpool.Pool
}

func NewHandler(pool *pgxpool.Pool) *Handler { return &Handler{pool: pool} }

// Routes mounts the audit read endpoints (intended behind admin authorization).
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.List)
	r.Get("/verify", h.VerifyChain)
	return r
}

// List returns audit events matching the query filters, newest first, paginated.
//
//	GET /audit?actor_type=&actor_id=&action=&on_behalf_of_sub=&delegation_id=
//	          &grant_jti=&since=&until=&limit=&offset=
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{
		ActorType:    q.Get("actor_type"),
		ActorID:      q.Get("actor_id"),
		Action:       q.Get("action"),
		OnBehalfOf:   q.Get("on_behalf_of_sub"),
		DelegationID: q.Get("delegation_id"),
		GrantJTI:     q.Get("grant_jti"),
		Limit:        atoiDefault(q.Get("limit"), 50),
		Offset:       atoiDefault(q.Get("offset"), 0),
	}
	if t, ok := parseTime(q.Get("since")); ok {
		f.Since = &t
	}
	if t, ok := parseTime(q.Get("until")); ok {
		f.Until = &t
	}

	events, total, err := Query(r.Context(), h.pool, f)
	if err != nil {
		http.Error(w, `{"error":"could not query audit log"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

// VerifyChain reports whether the audit hash chain is intact.
//
//	GET /audit/verify
func (h *Handler) VerifyChain(w http.ResponseWriter, r *http.Request) {
	res, err := Verify(r.Context(), h.pool)
	if err != nil {
		http.Error(w, `{"error":"could not verify audit chain"}`, http.StatusInternalServerError)
		return
	}
	resp := map[string]any{
		"ok":        res.OK,
		"events":    res.Events,
		"head_hash": res.HeadHash,
	}
	if !res.OK {
		resp["break_id"] = res.BreakID
		resp["break_kind"] = res.BreakKind
	}
	writeJSON(w, http.StatusOK, resp)
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// parseTime accepts an RFC 3339 timestamp or a Unix-seconds integer.
func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	return time.Time{}, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
