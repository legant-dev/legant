package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ory/fosite"

	"github.com/legant-dev/legant/internal/safehttp"
)

const cimdMaxBytes = 64 * 1024

// cimdDocument is the subset of a Client ID Metadata Document Legant consumes.
type cimdDocument struct {
	ClientID      string   `json:"client_id"`
	ClientName    string   `json:"client_name"`
	RedirectURIs  []string `json:"redirect_uris"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	Scope         string   `json:"scope"`
}

// CIMDResolver fetches and validates Client ID Metadata Documents, where the
// client_id is itself an https URL pointing at the document. CIMD clients are
// always PUBLIC and rely on S256 PKCE — there is no client secret to leak.
type CIMDResolver struct {
	client *http.Client
}

func NewCIMDResolver(client *http.Client) *CIMDResolver {
	return &CIMDResolver{client: client}
}

// IsCIMD reports whether a client_id is a CIMD URL.
func IsCIMD(clientID string) bool {
	return strings.HasPrefix(clientID, "https://")
}

// Resolve fetches the document at clientID (over the SSRF-hardened client) and
// returns a public fosite.Client. The document must self-identify with the same
// URL it was fetched from, and carry valid redirect URIs.
func (r *CIMDResolver) Resolve(ctx context.Context, clientID string) (fosite.Client, error) {
	if !IsCIMD(clientID) {
		return nil, fmt.Errorf("not a CIMD client_id")
	}
	var doc cimdDocument
	if err := safehttp.GetJSON(ctx, r.client, clientID, &doc, cimdMaxBytes); err != nil {
		return nil, fmt.Errorf("fetching client metadata document: %w", err)
	}
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("client metadata document client_id does not match its URL")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("client metadata document has no redirect_uris")
	}
	for _, u := range doc.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	grants := doc.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	responses := doc.ResponseTypes
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	return &fosite.DefaultClient{
		ID:            clientID,
		Public:        true, // no secret; PKCE (S256, enforced globally) protects the flow
		RedirectURIs:  doc.RedirectURIs,
		GrantTypes:    grants,
		ResponseTypes: responses,
		Scopes:        strings.Fields(doc.Scope),
	}, nil
}
