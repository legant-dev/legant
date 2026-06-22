package auth

import (
	"bytes"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	legant "github.com/legant-dev/legant"
	"github.com/legant-dev/legant/internal/delegation"
)

func TestSameOrigin(t *testing.T) {
	mk := func(origin string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/account/delegations/x/revoke", nil)
		r.Host = "legant.example"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	if !SameOrigin(mk("")) {
		t.Error("a request with no Origin/Referer should pass (relies on SameSite)")
	}
	if !SameOrigin(mk("https://legant.example")) {
		t.Error("a same-origin request should pass")
	}
	if SameOrigin(mk("https://evil.example")) {
		t.Error("a cross-origin request must be rejected")
	}
}

func TestSummarizeConstraints(t *testing.T) {
	max := 500.0
	got := summarizeConstraints(delegation.Constraints{
		MaxAmount:  &max,
		Categories: []string{"travel", "meals"},
		Tools:      []string{"get_weather"},
		TimeWindow: &delegation.TimeWindow{Weekdays: []int{1, 2, 3, 4, 5}, StartMin: 9 * 60, EndMin: 17*60 + 30, TZ: "UTC"},
		Rate:       &delegation.RateLimit{MaxPerHour: 10},
	})
	for _, want := range []string{"max 500.00", "categories: travel, meals", "tools: get_weather", "Mon,Tue,Wed,Thu,Fri 09:00-17:30 UTC", "rate 10/h"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q missing %q", got, want)
		}
	}

	// The deny-all sentinel (a fully-intersected-away allow-list) renders as "none".
	if s := summarizeConstraints(delegation.Constraints{Categories: []string{"\x00legant:deny-all"}}); !strings.Contains(s, "categories: none") {
		t.Errorf("deny-all sentinel should render as 'none', got %q", s)
	}

	if s := summarizeConstraints(delegation.Constraints{}); s != "—" {
		t.Errorf("empty constraints should render as em dash, got %q", s)
	}
}

func TestProvenanceString(t *testing.T) {
	// actor_chain is stored most-recent-first; provenance renders root -> leaf.
	if got := provenance("user:alice", []string{"agent:ocr", "agent:assistant"}); got != "user:alice → agent:assistant → agent:ocr" {
		t.Errorf("provenance = %q", got)
	}
	if got := provenance("", nil); got != "—" {
		t.Errorf("empty provenance = %q, want em dash", got)
	}
}

func TestAuditTemplateRenders(t *testing.T) {
	sub, err := fs.Sub(legant.TemplatesFS, "web/templates")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.ParseFS(sub, "*.html")
	if err != nil {
		t.Fatalf("templates must parse (audit.html included): %v", err)
	}
	var buf bytes.Buffer
	data := map[string]any{
		"Rows": []auditRow{{
			Time: "2026-06-21 10:00:00 UTC", Actor: "agent:abc12345",
			Action: "token.exchanged", Provenance: "user:alice → agent:assistant", Resource: "token x",
		}},
		"Total": 1, "VerifyOK": true, "Events": int64(1), "HeadHash": "deadbeefdeadbeef…",
		"Filter": map[string]string{},
	}
	if err := tmpl.ExecuteTemplate(&buf, "audit.html", data); err != nil {
		t.Fatalf("render audit.html: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Audit trail", "user:alice → agent:assistant", "token.exchanged", "chain verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered audit page missing %q", want)
		}
	}
}

func TestDelegationsTemplateRenders(t *testing.T) {
	sub, err := fs.Sub(legant.TemplatesFS, "web/templates")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.ParseFS(sub, "*.html")
	if err != nil {
		t.Fatalf("templates must parse (delegations.html included): %v", err)
	}
	var buf bytes.Buffer
	data := map[string]any{
		"Delegations": []delegationView{
			{ID: "d1", Agent: "Expense Assistant", Scopes: "expenses:read expenses:submit",
				Constraints: "max 500.00; categories: travel", Created: "2026-06-20 10:00 UTC",
				Expires: "2026-06-21 10:00 UTC", Active: true},
		},
		"Message": "revoked",
	}
	if err := tmpl.ExecuteTemplate(&buf, "delegations.html", data); err != nil {
		t.Fatalf("render delegations.html: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Expense Assistant", "expenses:submit", "/account/delegations/d1/revoke", "Revoke", "Delegation revoked."} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}
