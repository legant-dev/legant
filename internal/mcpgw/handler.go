package mcpgw

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// UpstreamHandler is the superadmin CRUD API over the DB-backed upstream registry,
// mounted under /api/v1/gateway/upstreams. The gateway process refreshes from the
// same table, so changes here propagate without a redeploy.
type UpstreamHandler struct {
	store *UpstreamStore
}

func NewUpstreamHandler(store *UpstreamStore) *UpstreamHandler {
	return &UpstreamHandler{store: store}
}

func (h *UpstreamHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.list)
	r.Put("/", h.upsert)
	r.Delete("/{slug}", h.delete)
	return r
}

func (h *UpstreamHandler) list(w http.ResponseWriter, r *http.Request) {
	ups, err := h.store.List(r.Context())
	if err != nil {
		http.Error(w, `{"error":"could not list upstreams"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, ups)
}

func (h *UpstreamHandler) upsert(w http.ResponseWriter, r *http.Request) {
	var u Upstream
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&u); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if u.Slug == "" || u.InboundAudience == "" || u.URL == "" || u.ResourceID == "" {
		http.Error(w, `{"error":"slug, inbound_audience, url and resource_id are required"}`, http.StatusBadRequest)
		return
	}
	if err := h.store.Upsert(r.Context(), &u); err != nil {
		// A duplicate inbound_audience (the UNIQUE constraint) lands here.
		http.Error(w, `{"error":"could not save upstream (duplicate inbound_audience?)"}`, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *UpstreamHandler) delete(w http.ResponseWriter, r *http.Request) {
	removed, err := h.store.Delete(r.Context(), chi.URLParam(r, "slug"))
	if err != nil {
		http.Error(w, `{"error":"could not delete upstream"}`, http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
