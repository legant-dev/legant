package auth

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/legant-dev/legant/internal/delegation"
	"github.com/legant-dev/legant/internal/delegation/chains"
)

// SameOrigin reports whether a state-changing request's Origin/Referer matches
// its own host. It is a CSRF defense-in-depth on top of SameSite=Lax cookies: a
// cross-site form POST that does carry an Origin is rejected, closing the
// same-site/subdomain gap that Lax alone leaves open. A request with no
// Origin/Referer is allowed (and still protected by the Lax session cookie).
func SameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		o = r.Header.Get("Referer")
	}
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// AccountHandler serves the self-service delegation-management UI: a user views
// the delegations they have granted to agents and can revoke any of them (and
// the whole sub-agent chain it seeded).
type AccountHandler struct {
	chains   *chains.Service
	sessions *SessionManager
	tmpl     *template.Template
}

func NewAccountHandler(ch *chains.Service, sessions *SessionManager, tmpl *template.Template) *AccountHandler {
	return &AccountHandler{chains: ch, sessions: sessions, tmpl: tmpl}
}

// delegationView is the template-friendly, pre-formatted form of a delegation.
type delegationView struct {
	ID          string
	Agent       string
	Scopes      string
	Constraints string
	Created     string
	Expires     string
	Active      bool
}

// Delegations renders the list of the logged-in user's granted delegations.
func (h *AccountHandler) Delegations(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil || sess.UserID == "" {
		http.Redirect(w, r, "/login?redirect=/account/delegations", http.StatusFound)
		return
	}
	rows, err := h.chains.ListUserDelegations(r.Context(), sess.UserID)
	if err != nil {
		http.Error(w, "could not load delegations", http.StatusInternalServerError)
		return
	}
	views := make([]delegationView, 0, len(rows))
	for _, d := range rows {
		expires := "never"
		if d.ExpiresAt != nil {
			expires = d.ExpiresAt.UTC().Format("2006-01-02 15:04 MST")
		}
		views = append(views, delegationView{
			ID:          d.ID,
			Agent:       d.AgentName,
			Scopes:      strings.Join(d.Scopes, " "),
			Constraints: summarizeConstraints(d.Constraints),
			Created:     d.CreatedAt.UTC().Format("2006-01-02 15:04 MST"),
			Expires:     expires,
			Active:      d.Active,
		})
	}
	data := map[string]any{
		"Delegations": views,
		"Message":     r.URL.Query().Get("msg"),
		"Error":       r.URL.Query().Get("err"),
		"CSRF":        h.sessions.CSRFToken(sess),
	}
	if err := h.tmpl.ExecuteTemplate(w, "delegations.html", data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// Revoke revokes one delegation (and its sub-agent chain) owned by the user.
func (h *AccountHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sessions.Get(r.Context(), r)
	if err != nil || sess.UserID == "" {
		http.Redirect(w, r, "/login?redirect=/account/delegations", http.StatusFound)
		return
	}
	if !SameOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if !h.sessions.ValidateCSRF(r, sess) {
		http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	if _, _, err := h.chains.RevokeDelegationTree(r.Context(), id, sess.UserID); err != nil {
		http.Redirect(w, r, "/account/delegations?err=revoke_failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/delegations?msg=revoked", http.StatusSeeOther)
}

// summarizeConstraints renders constraints as a compact human string. The
// deny-all sentinel (an allow-list intersected to nothing) is shown as "none".
func summarizeConstraints(c delegation.Constraints) string {
	var parts []string
	if c.MaxAmount != nil {
		parts = append(parts, fmt.Sprintf("max %.2f", *c.MaxAmount))
	}
	if s := summarizeList("categories", c.Categories); s != "" {
		parts = append(parts, s)
	}
	if s := summarizeList("tools", c.Tools); s != "" {
		parts = append(parts, s)
	}
	if s := summarizeList("resources", c.Resources); s != "" {
		parts = append(parts, s)
	}
	if c.TimeWindow != nil {
		parts = append(parts, "window "+summarizeWindow(c.TimeWindow))
	}
	if c.Rate != nil {
		parts = append(parts, fmt.Sprintf("rate %d/h", c.Rate.MaxPerHour))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

func summarizeList(label string, vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	clean := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.HasPrefix(v, "\x00") { // deny-all sentinel
			return label + ": none"
		}
		clean = append(clean, v)
	}
	return label + ": " + strings.Join(clean, ", ")
}

var weekdayNames = []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}

func summarizeWindow(w *delegation.TimeWindow) string {
	tz := w.TZ
	if tz == "" {
		tz = "UTC"
	}
	days := "any day"
	if len(w.Weekdays) > 0 {
		ds := make([]string, 0, len(w.Weekdays))
		for _, d := range w.Weekdays {
			if d >= 0 && d < 7 {
				ds = append(ds, weekdayNames[d])
			}
		}
		if len(ds) == 0 {
			days = "no day"
		} else {
			days = strings.Join(ds, ",")
		}
	}
	return fmt.Sprintf("%s %02d:%02d-%02d:%02d %s", days,
		w.StartMin/60, w.StartMin%60, w.EndMin/60, w.EndMin%60, tz)
}
