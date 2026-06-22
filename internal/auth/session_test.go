package auth_test

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/auth"
)

func TestCSRFToken(t *testing.T) {
	sm := auth.NewSessionManager(nil, "csrf-secret-csrf-secret-csrf-1234", time.Hour, false)
	s := &auth.Session{ID: "session-abc"}
	tok := sm.CSRFToken(s)
	if tok == "" {
		t.Fatal("CSRF token should not be empty")
	}
	if sm.CSRFToken(s) != tok {
		t.Fatal("CSRF token should be stable for a session")
	}

	// Header path (JSON / fetch clients).
	rHdr := httptest.NewRequest("POST", "/x", nil)
	rHdr.Header.Set("X-CSRF-Token", tok)
	if !sm.ValidateCSRF(rHdr, s) {
		t.Error("a correct X-CSRF-Token header should validate")
	}

	// Form-field path (HTML forms).
	form := url.Values{"csrf_token": {tok}}
	rForm := httptest.NewRequest("POST", "/x", strings.NewReader(form.Encode()))
	rForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !sm.ValidateCSRF(rForm, s) {
		t.Error("a correct csrf_token form field should validate")
	}

	// Missing, wrong, and cross-session tokens are all rejected.
	if sm.ValidateCSRF(httptest.NewRequest("POST", "/x", nil), s) {
		t.Error("a missing token must be rejected")
	}
	rWrong := httptest.NewRequest("POST", "/x", nil)
	rWrong.Header.Set("X-CSRF-Token", "not-the-token")
	if sm.ValidateCSRF(rWrong, s) {
		t.Error("a wrong token must be rejected")
	}
	if sm.ValidateCSRF(rHdr, &auth.Session{ID: "different-session"}) {
		t.Error("one session's token must not validate for another session")
	}
}
