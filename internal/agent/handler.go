package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/legant-dev/legant/internal/authz"
)

// DelegationRevoker cascades a delegation revocation to the live tokens minted
// from it. Satisfied by the revocation store; an interface keeps the agent
// package decoupled from it.
type DelegationRevoker interface {
	RevokeByDelegation(ctx context.Context, delegationID string) (int64, error)
}

type Handler struct {
	service *Service
	revoker DelegationRevoker
}

func NewHandler(service *Service, revoker DelegationRevoker) *Handler {
	return &Handler{service: service, revoker: revoker}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Route("/{agentID}", func(r chi.Router) {
		r.Use(h.requireAgentAccess)
		r.Get("/", h.Get)
		r.Put("/", h.Update)
		r.Delete("/", h.Revoke)

		// Tokens
		r.Get("/tokens", h.ListTokens)
		r.Post("/tokens", h.CreateToken)
		r.Delete("/tokens/{tokenID}", h.RevokeToken)

		// Delegations for this agent
		r.Get("/delegations", h.ListDelegations)
	})

	// Delegation management (user-centric)
	r.Route("/delegations", func(r chi.Router) {
		r.Post("/", h.CreateDelegation)
		r.Delete("/{delegationID}", h.RevokeDelegation)
	})

	return r
}

// requireAgentAccess loads the addressed agent and ensures the caller may act in
// its organization, returning 404 (not 403) when they may not — so the API does
// not leak which agent ids exist across tenants.
func (h *Handler) requireAgentAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.FromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ag, err := h.service.GetByID(r.Context(), chi.URLParam(r, "agentID"))
		if err != nil {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		orgID := ""
		if ag.OrgID != nil {
			orgID = *ag.OrgID
		}
		if !p.CanAccessOrg(orgID) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		// Reads require org membership; writes (mutations, token issuance) require
		// an org-admin role.
		if r.Method != http.MethodGet && !p.IsOrgAdmin(orgID) {
			writeError(w, http.StatusForbidden, "organization admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Agent CRUD ----

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req CreateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Authorize the target organization from the principal — never trust the body
	// alone. A non-superadmin may only create agents in an org they administer;
	// only a superadmin may create an org-less (global) agent.
	if req.OrgID == nil || *req.OrgID == "" {
		if !p.IsSuperadmin {
			writeError(w, http.StatusForbidden, "org_id is required")
			return
		}
	} else if !p.IsOrgAdmin(*req.OrgID) {
		writeError(w, http.StatusForbidden, "must be an admin of the target organization")
		return
	}
	agent, err := h.service.Create(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": agent})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	agent, err := h.service.GetByID(r.Context(), chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": agent})
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	agents, total, err := h.service.List(r.Context(), p.OrgIDs(), p.IsSuperadmin, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": agents, "total": total})
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var req UpdateAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, err := h.service.Update(r.Context(), chi.URLParam(r, "agentID"), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": agent})
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Revoke(r.Context(), chi.URLParam(r, "agentID")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Tokens ----

func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.service.ListTokens(r.Context(), chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": tokens})
}

func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req CreateAgentTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	resp, err := h.service.CreateToken(r.Context(), chi.URLParam(r, "agentID"), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": resp})
}

func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	// Bind the delete to the agent in the path (already org-checked by
	// requireAgentAccess) so a token from another agent cannot be deleted by id.
	if err := h.service.RevokeToken(r.Context(), chi.URLParam(r, "agentID"), chi.URLParam(r, "tokenID")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Delegations ----

func (h *Handler) ListDelegations(w http.ResponseWriter, r *http.Request) {
	delegations, err := h.service.ListDelegationsByAgent(r.Context(), chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": delegations})
}

func (h *Handler) CreateDelegation(w http.ResponseWriter, r *http.Request) {
	var req CreateDelegationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// The delegator is the authenticated user — never a client-supplied header.
	// A delegation grants a slice of a human's authority, so only a user
	// principal may create one.
	p, ok := authz.FromContext(r.Context())
	if !ok || p.Type != authz.TypeUser {
		writeError(w, http.StatusForbidden, "only an authenticated user may create a delegation")
		return
	}

	// The caller must be able to access the delegatee agent's organization;
	// otherwise treat the agent as nonexistent (no cross-tenant existence probe).
	ag, err := h.service.GetByID(r.Context(), req.DelegateeAgentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	orgID := ""
	if ag.OrgID != nil {
		orgID = *ag.OrgID
	}
	if !p.CanAccessOrg(orgID) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	delegation, err := h.service.CreateDelegation(r.Context(), p.ID, orgID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": delegation})
}

func (h *Handler) RevokeDelegation(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// A user may revoke only their own delegations; a superadmin may revoke any.
	filter := ""
	if !p.IsSuperadmin {
		if p.Type != authz.TypeUser {
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		filter = p.ID
	}
	n, err := h.service.RevokeDelegation(r.Context(), chi.URLParam(r, "delegationID"), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "delegation not found")
		return
	}
	// Cascade: kill any live tokens minted from this delegation.
	if h.revoker != nil {
		_, _ = h.revoker.RevokeByDelegation(r.Context(), chi.URLParam(r, "delegationID"))
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
