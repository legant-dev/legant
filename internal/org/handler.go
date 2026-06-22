package org

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.ListOrgs)
	r.Post("/", h.CreateOrg)
	r.Route("/{orgID}", func(r chi.Router) {
		r.Get("/", h.GetOrg)
		r.Put("/", h.UpdateOrg)
		r.Delete("/", h.DeleteOrg)

		// Members
		r.Get("/members", h.ListMembers)
		r.Post("/members", h.AddMember)
		r.Put("/members/{userID}", h.UpdateMemberRole)
		r.Delete("/members/{userID}", h.RemoveMember)

		// SSO
		r.Get("/sso", h.ListSSO)
		r.Post("/sso", h.CreateSSO)
		r.Route("/sso/{ssoID}", func(r chi.Router) {
			r.Get("/", h.GetSSO)
			r.Put("/", h.UpdateSSO)
			r.Delete("/", h.DeleteSSO)
		})

		// Invitations
		r.Get("/invitations", h.ListInvitations)
		r.Post("/invitations", h.CreateInvitation)
		r.Delete("/invitations/{inviteID}", h.RevokeInvitation)
	})
	return r
}

// ---- Org CRUD ----

func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	org, err := h.service.CreateOrg(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": org})
}

func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	org, err := h.service.GetOrg(r.Context(), chi.URLParam(r, "orgID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": org})
}

func (h *Handler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	orgs, total, err := h.service.ListOrgs(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": orgs, "total": total})
}

func (h *Handler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	var req UpdateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	org, err := h.service.UpdateOrg(r.Context(), chi.URLParam(r, "orgID"), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": org})
}

func (h *Handler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteOrg(r.Context(), chi.URLParam(r, "orgID")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Members ----

func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	members, total, err := h.service.ListMembers(r.Context(), chi.URLParam(r, "orgID"), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": members, "total": total})
}

func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request) {
	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	member, err := h.service.AddMember(r.Context(), chi.URLParam(r, "orgID"), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": member})
}

func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	var req UpdateMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	err := h.service.UpdateMemberRole(r.Context(), chi.URLParam(r, "orgID"), chi.URLParam(r, "userID"), req.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	err := h.service.RemoveMember(r.Context(), chi.URLParam(r, "orgID"), chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- SSO ----

func (h *Handler) ListSSO(w http.ResponseWriter, r *http.Request) {
	connections, err := h.service.ListSSO(r.Context(), chi.URLParam(r, "orgID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": connections})
}

func (h *Handler) CreateSSO(w http.ResponseWriter, r *http.Request) {
	var req CreateSSORequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sso, err := h.service.CreateSSO(r.Context(), chi.URLParam(r, "orgID"), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": sso})
}

func (h *Handler) GetSSO(w http.ResponseWriter, r *http.Request) {
	sso, err := h.service.GetSSO(r.Context(), chi.URLParam(r, "ssoID"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": sso})
}

func (h *Handler) UpdateSSO(w http.ResponseWriter, r *http.Request) {
	var req UpdateSSORequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sso, err := h.service.UpdateSSO(r.Context(), chi.URLParam(r, "ssoID"), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": sso})
}

func (h *Handler) DeleteSSO(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteSSO(r.Context(), chi.URLParam(r, "ssoID")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Invitations (stubs for now, full implementation with email below) ----

func (h *Handler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	invitations, err := h.service.ListInvitations(r.Context(), chi.URLParam(r, "orgID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": invitations})
}

func (h *Handler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	var req CreateInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// TODO: get inviter ID from auth context
	inv, err := h.service.CreateInvitation(r.Context(), chi.URLParam(r, "orgID"), "", req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": inv})
}

func (h *Handler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	if err := h.service.RevokeInvitation(r.Context(), chi.URLParam(r, "inviteID")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
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
