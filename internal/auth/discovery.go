package auth

import (
	"encoding/json"
	"net/http"
)

type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// BuildMetadata constructs the authorization-server metadata shared by the OIDC
// discovery document and the RFC 8414 endpoint. It advertises only what the
// server actually implements — notably scopes and claims that are genuinely
// issued, so clients are not told to expect email/profile claims that the server
// does not populate.
func BuildMetadata(issuerURL string) DiscoveryDocument {
	return DiscoveryDocument{
		Issuer:                            issuerURL,
		AuthorizationEndpoint:             issuerURL + "/oauth2/authorize",
		TokenEndpoint:                     issuerURL + "/oauth2/token",
		UserinfoEndpoint:                  issuerURL + "/oauth2/userinfo",
		JwksURI:                           issuerURL + "/.well-known/jwks.json",
		RevocationEndpoint:                issuerURL + "/oauth2/revoke",
		IntrospectionEndpoint:             issuerURL + "/oauth2/introspect",
		RegistrationEndpoint:              issuerURL + "/oauth2/register",
		ScopesSupported:                   []string{"openid", "offline_access"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token", TokenExchangeGrantType},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat"},
	}
}

func metadataHandler(issuerURL string) http.HandlerFunc {
	data, _ := json.MarshalIndent(BuildMetadata(issuerURL), "", "  ")
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(data)
	}
}

// DiscoveryHandler serves the OpenID Connect discovery document.
func DiscoveryHandler(issuerURL string) http.HandlerFunc { return metadataHandler(issuerURL) }

// AuthServerMetadataHandler serves RFC 8414 OAuth 2.0 Authorization Server Metadata.
func AuthServerMetadataHandler(issuerURL string) http.HandlerFunc { return metadataHandler(issuerURL) }
