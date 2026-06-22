package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SCIM 2.0 implementation (RFC 7644)
// Endpoints are tenant-scoped via bearer token.

type Handler struct {
	pool *pgxpool.Pool
}

func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/ServiceProviderConfig", h.ServiceProviderConfig)
	r.Get("/Schemas", h.Schemas)
	r.Get("/ResourceTypes", h.ResourceTypes)
	r.Route("/Users", func(r chi.Router) {
		r.Get("/", h.ListUsers)
		r.Post("/", h.CreateUser)
		r.Get("/{id}", h.GetUser)
		r.Put("/{id}", h.ReplaceUser)
		r.Patch("/{id}", h.PatchUser)
		r.Delete("/{id}", h.DeleteUser)
	})
	return r
}

// ---- Service Provider Config ----

func (h *Handler) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch": map[string]bool{
			"supported": true,
		},
		"bulk": map[string]interface{}{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]interface{}{
			"supported":  true,
			"maxResults": 100,
		},
		"changePassword": map[string]bool{
			"supported": false,
		},
		"sort": map[string]bool{
			"supported": false,
		},
		"etag": map[string]bool{
			"supported": false,
		},
		"authenticationSchemes": []map[string]string{
			{
				"type":        "oauthbearertoken",
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token Standard",
			},
		},
	}
	writeJSON(w, http.StatusOK, config)
}

func (h *Handler) Schemas(w http.ResponseWriter, r *http.Request) {
	schemas := map[string]interface{}{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": 1,
		"Resources": []map[string]interface{}{
			{
				"id":   "urn:ietf:params:scim:schemas:core:2.0:User",
				"name": "User",
			},
		},
	}
	writeJSON(w, http.StatusOK, schemas)
}

func (h *Handler) ResourceTypes(w http.ResponseWriter, r *http.Request) {
	types := []map[string]interface{}{
		{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":       "User",
			"name":     "User",
			"endpoint": "/scim/v2/Users",
			"schema":   "urn:ietf:params:scim:schemas:core:2.0:User",
		},
	}
	writeJSON(w, http.StatusOK, types)
}

// ---- SCIM User Resource ----

type SCIMUser struct {
	Schemas  []string    `json:"schemas"`
	ID       string      `json:"id"`
	UserName string      `json:"userName"`
	Name     *SCIMName   `json:"name,omitempty"`
	Emails   []SCIMEmail `json:"emails,omitempty"`
	Active   bool        `json:"active"`
	Meta     SCIMMeta    `json:"meta"`
}

type SCIMName struct {
	Formatted string `json:"formatted,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary"`
}

type SCIMMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

type SCIMListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []SCIMUser `json:"Resources"`
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if startIndex < 1 {
		startIndex = 1
	}
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count <= 0 || count > 100 {
		count = 100
	}

	offset := startIndex - 1 // SCIM is 1-indexed

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, email, display_name, status, created_at, updated_at
		 FROM users WHERE status != 'deleted' ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		count, offset,
	)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var users []SCIMUser
	for rows.Next() {
		var id, email, displayName, status, createdAt, updatedAt string
		if err := rows.Scan(&id, &email, &displayName, &status, &createdAt, &updatedAt); err != nil {
			continue
		}
		users = append(users, toSCIMUser(id, email, displayName, status, createdAt, updatedAt))
	}

	var total int
	h.pool.QueryRow(r.Context(), `SELECT count(*) FROM users WHERE status != 'deleted'`).Scan(&total)

	resp := SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: count,
		Resources:    users,
	}
	if resp.Resources == nil {
		resp.Resources = []SCIMUser{}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid id")
		return
	}

	var email, displayName, status, createdAt, updatedAt string
	err := h.pool.QueryRow(r.Context(),
		`SELECT email, display_name, status, created_at, updated_at FROM users WHERE id = $1`, id,
	).Scan(&email, &displayName, &status, &createdAt, &updatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			writeSCIMError(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "database error")
		return
	}

	writeJSON(w, http.StatusOK, toSCIMUser(id, email, displayName, status, createdAt, updatedAt))
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var input SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	email := input.UserName
	if len(input.Emails) > 0 {
		email = input.Emails[0].Value
	}
	displayName := ""
	if input.Name != nil {
		displayName = input.Name.Formatted
	}

	var id, createdAt, updatedAt, status string
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO users (email, display_name) VALUES ($1, $2)
		 RETURNING id, status, created_at, updated_at`,
		email, displayName,
	).Scan(&id, &status, &createdAt, &updatedAt)
	if err != nil {
		writeSCIMError(w, http.StatusConflict, "user already exists")
		return
	}

	writeJSON(w, http.StatusCreated, toSCIMUser(id, email, displayName, status, createdAt, updatedAt))
}

func (h *Handler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var input SCIMUser
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	email := input.UserName
	if len(input.Emails) > 0 {
		email = input.Emails[0].Value
	}
	displayName := ""
	if input.Name != nil {
		displayName = input.Name.Formatted
	}
	status := "active"
	if !input.Active {
		status = "suspended"
	}

	var createdAt, updatedAt string
	err := h.pool.QueryRow(r.Context(),
		`UPDATE users SET email = $2, display_name = $3, status = $4, updated_at = now() WHERE id = $1
		 RETURNING created_at, updated_at`,
		id, email, displayName, status,
	).Scan(&createdAt, &updatedAt)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, toSCIMUser(id, email, displayName, status, createdAt, updatedAt))
}

func (h *Handler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var patch struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op    string      `json:"op"`
			Path  string      `json:"path"`
			Value interface{} `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	for _, op := range patch.Operations {
		switch op.Path {
		case "active":
			active, ok := op.Value.(bool)
			if !ok {
				continue
			}
			status := "active"
			if !active {
				status = "suspended"
			}
			h.pool.Exec(r.Context(),
				`UPDATE users SET status = $2, updated_at = now() WHERE id = $1`, id, status)
		case "userName":
			if email, ok := op.Value.(string); ok {
				h.pool.Exec(r.Context(),
					`UPDATE users SET email = $2, updated_at = now() WHERE id = $1`, id, email)
			}
		case "displayName", "name.formatted":
			if name, ok := op.Value.(string); ok {
				h.pool.Exec(r.Context(),
					`UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1`, id, name)
			}
		}
	}

	// Return updated user
	h.GetUser(w, r)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := h.pool.Exec(r.Context(),
		`UPDATE users SET status = 'deleted', updated_at = now() WHERE id = $1`, id)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Helpers ----

func toSCIMUser(id, email, displayName, status, createdAt, updatedAt string) SCIMUser {
	return SCIMUser{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:       id,
		UserName: email,
		Name:     &SCIMName{Formatted: displayName},
		Emails: []SCIMEmail{
			{Value: email, Type: "work", Primary: true},
		},
		Active: status == "active",
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      createdAt,
			LastModified: updatedAt,
			Location:     fmt.Sprintf("/scim/v2/Users/%s", id),
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  status,
	})
}
