package auth_test

import (
	"context"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/auth"
	"github.com/legant-dev/legant/internal/live"
	"github.com/legant-dev/legant/internal/testsupport"
)

// TestLiveTemplateParses guards against html/template breakage in live.html — it
// is parsed once at startup, so a syntax error would only surface at render time
// without this.
func TestLiveTemplateParses(t *testing.T) {
	sub, err := fs.Sub(legant.TemplatesFS, "web/templates")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.ParseFS(sub, "*.html")
	if err != nil {
		t.Fatal(err)
	}
	if err := tmpl.ExecuteTemplate(io.Discard, "live.html", map[string]any{}); err != nil {
		t.Fatalf("execute live.html: %v", err)
	}
}

// TestLiveIngest covers the connected-resource-server decision ingest endpoint
// (DB-free: with a nil publisher it publishes straight to the hub).
func TestLiveIngest(t *testing.T) {
	hub := live.NewHub(10)

	// Token unset → endpoint disabled (404), even with a valid body.
	disabled := auth.NewLiveHandler(nil, nil, nil, hub, nil, "")
	rec := httptest.NewRecorder()
	disabled.Ingest(rec, httptest.NewRequest(http.MethodPost, "/admin/live/ingest", strings.NewReader(`{"decision":"DENY"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no ingest token should 404, got %d", rec.Code)
	}

	h := auth.NewLiveHandler(nil, nil, nil, hub, nil, "s3cret")

	// Wrong bearer → 401.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/live/ingest", strings.NewReader(`{"decision":"DENY"}`))
	req.Header.Set("Authorization", "Bearer wrong")
	h.Ingest(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should 401, got %d", rec.Code)
	}

	// Bad decision value → 400.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/live/ingest", strings.NewReader(`{"decision":"maybe"}`))
	req.Header.Set("Authorization", "Bearer s3cret")
	h.Ingest(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad decision should 400, got %d", rec.Code)
	}

	// Valid → 204, and the event lands on the hub as a decision.
	sub, stop := hub.Subscribe(4)
	defer stop()
	rec = httptest.NewRecorder()
	body := `{"decision":"deny","subject":"user:alice","actor":"agent:builder","provenance":"user:alice -> agent:builder","tool":"Bash: curl x","reason":"command \"curl\" denied","source":"claude-code"}`
	req = httptest.NewRequest(http.MethodPost, "/admin/live/ingest", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	h.Ingest(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid ingest should 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	select {
	case e := <-sub:
		if e.Type != "decision" || e.Decision != "DENY" || e.Upstream != "claude-code" || e.Tool != "Bash: curl x" {
			t.Fatalf("unexpected event: %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("ingested event did not reach the hub")
	}
}

func superadminCookie(t *testing.T, sm *auth.SessionManager, ctx context.Context, userID string) *http.Cookie {
	t.Helper()
	sess, err := sm.Create(ctx, userID, httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	sm.SetCookie(rec, sess)
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie was set")
	}
	return cookies[0]
}

func TestLiveHandlerGuardAndStream(t *testing.T) {
	pool := testsupport.DB(t)
	ctx := context.Background()
	sm := auth.NewSessionManager(pool, strings.Repeat("c", 32), time.Hour, false)
	hub := live.NewHub(10)
	h := auth.NewLiveHandler(pool, sm, nil, hub, nil, "")

	var superID, plainID string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status,is_superadmin) VALUES ('super@x.com','active',true) RETURNING id::text`).Scan(&superID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,status,is_superadmin) VALUES ('plain@x.com','active',false) RETURNING id::text`).Scan(&plainID); err != nil {
		t.Fatal(err)
	}

	// No session → 401 on the snapshot API.
	rec := httptest.NewRecorder()
	h.Snapshot(rec, httptest.NewRequest(http.MethodGet, "/admin/live/snapshot", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session should be 401, got %d", rec.Code)
	}

	// Authenticated but not superadmin → 403.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/live/snapshot", nil)
	req.AddCookie(superadminCookie(t, sm, ctx, plainID))
	h.Snapshot(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-superadmin should be 403, got %d", rec.Code)
	}

	// Superadmin → 200 JSON graph.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/live/snapshot", nil)
	req.AddCookie(superadminCookie(t, sm, ctx, superID))
	h.Snapshot(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("superadmin snapshot should be 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"nodes"`) {
		t.Errorf("snapshot should be a graph JSON, got %s", rec.Body.String())
	}

	// SSE replay: an event in the ring is streamed to a superadmin client. The
	// handler blocks on the SSE loop, so cancel the request context shortly.
	hub.Publish(live.Event{Type: "mint", Decision: "MINT", Actor: "agent:x", Provenance: "user:alice → agent:x"})
	sctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/live/events", nil).WithContext(sctx)
	req.AddCookie(superadminCookie(t, sm, ctx, superID))
	h.Events(rec, req)
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("SSE content-type should be text/event-stream, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "agent:x") || !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "data:") {
		t.Errorf("SSE should replay the ring event as a data frame, got %q", rec.Body.String())
	}
}
