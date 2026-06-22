package mcpauth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ProtectedResourceMetadata is the RFC 9728 document a resource server publishes
// at /.well-known/oauth-protected-resource so a client can discover which
// authorization server to use, and how to present tokens.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// ProtectedResourceMetadataHandler serves RFC 9728 metadata for a resource whose
// authorization server is issuerURL. Tokens are only accepted in the
// Authorization header (never the query string), per the MCP spec.
func ProtectedResourceMetadataHandler(resourceURI, issuerURL string) http.HandlerFunc {
	doc := ProtectedResourceMetadata{
		Resource:               resourceURI,
		AuthorizationServers:   []string{issuerURL},
		BearerMethodsSupported: []string{"header"},
	}
	data, _ := json.MarshalIndent(doc, "", "  ")
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(data)
	}
}

// Challenge writes an RFC 6750 / RFC 9728 WWW-Authenticate header and status. A
// bare challenge (no error) is sent when no credentials were presented; an error
// is added only when a token was presented and rejected. resourceMetadata points
// the client at the protected-resource metadata document.
func Challenge(w http.ResponseWriter, status int, resourceMetadata, errCode, errDesc string) {
	parts := []string{`Bearer realm="legant"`}
	if resourceMetadata != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata=%q`, resourceMetadata))
	}
	if errCode != "" {
		parts = append(parts, fmt.Sprintf(`error=%q`, errCode))
		if errDesc != "" {
			parts = append(parts, fmt.Sprintf(`error_description=%q`, errDesc))
		}
	}
	w.Header().Set("WWW-Authenticate", joinChallenge(parts))
	w.WriteHeader(status)
}

func joinChallenge(parts []string) string {
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
