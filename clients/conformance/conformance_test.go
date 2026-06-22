// Package conformance validates the golden vectors (clients/conformance/vectors.json)
// against the Go SDK. The TypeScript and Python SDKs run the SAME vectors, so all
// three implementations are proven to agree. Regenerate vectors with:
//
//	go run ./clients/conformance/gen
package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/legant-dev/legant/sdk"
)

type vectors struct {
	Issuer    string          `json:"issuer"`
	Audience  string          `json:"audience"`
	JWKS      json.RawMessage `json:"jwks"`
	Verify    []verifyVec     `json:"verify"`
	Audience2 []audVec        `json:"audienceCanonicalization"`
	Authorize []authVec       `json:"authorize"`
	Revoke    revVec          `json:"revocation"`
}
type verifyVec struct {
	Name       string `json:"name"`
	Token      string `json:"token"`
	Valid      bool   `json:"valid"`
	Provenance string `json:"provenance"`
}
type audVec struct {
	Name               string `json:"name"`
	ConfiguredAudience string `json:"configuredAudience"`
	Token              string `json:"token"`
	Valid              bool   `json:"valid"`
}
type actionVec struct {
	Scope    string  `json:"scope"`
	Amount   float64 `json:"amount"`
	Category string  `json:"category"`
	Tool     string  `json:"tool"`
	Resource string  `json:"resource"`
	At       string  `json:"at"`
}
type authVec struct {
	Name   string    `json:"name"`
	Token  string    `json:"token"`
	Action actionVec `json:"action"`
	Allow  bool      `json:"allow"`
}
type revVec struct {
	RevokedToken string `json:"revokedToken"`
	LiveToken    string `json:"liveToken"`
	RevokedJTI   string `json:"revokedJti"`
	LiveJTI      string `json:"liveJti"`
	Feed         string `json:"feed"`
	FeedRollback string `json:"feedRollback"`
	FeedNewer    string `json:"feedNewer"`
}

func load(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyVectors(t *testing.T) {
	v := load(t)
	keys, err := sdk.ParseJWKS(v.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	ver := sdk.NewVerifier(v.Issuer, v.Audience, keys)
	for _, c := range v.Verify {
		claims, err := ver.Verify(c.Token)
		if c.Valid && err != nil {
			t.Errorf("[%s] expected valid, got error: %v", c.Name, err)
			continue
		}
		if !c.Valid && err == nil {
			t.Errorf("[%s] expected invalid, but it verified", c.Name)
			continue
		}
		if c.Valid && c.Provenance != "" && claims.Provenance() != c.Provenance {
			t.Errorf("[%s] provenance = %q, want %q", c.Name, claims.Provenance(), c.Provenance)
		}
	}
}

func TestAudienceVectors(t *testing.T) {
	v := load(t)
	keys, _ := sdk.ParseJWKS(v.JWKS)
	for _, c := range v.Audience2 {
		ver := sdk.NewVerifier(v.Issuer, c.ConfiguredAudience, keys)
		_, err := ver.Verify(c.Token)
		if c.Valid != (err == nil) {
			t.Errorf("[%s] audience %q: valid=%v, got err=%v", c.Name, c.ConfiguredAudience, c.Valid, err)
		}
	}
}

func TestAuthorizeVectors(t *testing.T) {
	v := load(t)
	keys, _ := sdk.ParseJWKS(v.JWKS)
	ver := sdk.NewVerifier(v.Issuer, v.Audience, keys)
	for _, c := range v.Authorize {
		claims, err := ver.Verify(c.Token)
		if err != nil {
			t.Fatalf("[%s] token did not verify: %v", c.Name, err)
		}
		act := sdk.Action{Scope: c.Action.Scope, Amount: c.Action.Amount, Category: c.Action.Category, Tool: c.Action.Tool, Resource: c.Action.Resource}
		if c.Action.At != "" {
			at, perr := time.Parse(time.RFC3339, c.Action.At)
			if perr != nil {
				t.Fatal(perr)
			}
			act.At = at
		}
		allowed := claims.Authorize(act) == nil
		if allowed != c.Allow {
			t.Errorf("[%s] allow=%v, want %v", c.Name, allowed, c.Allow)
		}
	}
}

func TestRevocationVectors(t *testing.T) {
	v := load(t)
	keys, _ := sdk.ParseJWKS(v.JWKS)
	ctx := context.Background()

	body := v.Revoke.Feed
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	feed, err := sdk.FetchRevocationFeed(ctx, srv.URL, v.Issuer, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !feed.IsRevoked(v.Revoke.RevokedJTI) {
		t.Error("revoked jti should be in the feed")
	}
	if feed.IsRevoked(v.Revoke.LiveJTI) {
		t.Error("live jti should NOT be in the feed")
	}

	ver := sdk.NewVerifier(v.Issuer, v.Audience, keys, sdk.WithRevocationFeed(feed))
	if _, err := ver.Verify(v.Revoke.RevokedToken); err != sdk.ErrRevoked {
		t.Errorf("revoked token should return ErrRevoked, got %v", err)
	}
	if _, err := ver.Verify(v.Revoke.LiveToken); err != nil {
		t.Errorf("live token should verify, got %v", err)
	}

	// A rollback (lower version) is rejected; revocation persists.
	body = v.Revoke.FeedRollback
	if err := feed.Refresh(ctx); err == nil {
		t.Error("a version regression must be rejected")
	}
	if !feed.IsRevoked(v.Revoke.RevokedJTI) {
		t.Error("after a rejected rollback the token must still be revoked")
	}

	// A newer feed dropping the jti clears the revocation.
	body = v.Revoke.FeedNewer
	if err := feed.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if feed.IsRevoked(v.Revoke.RevokedJTI) {
		t.Error("a newer feed without the jti should clear the revocation")
	}
}
