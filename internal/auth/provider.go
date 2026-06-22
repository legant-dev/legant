package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// signingKID holds the kid of the active signing key so that ID tokens carry a
// matching `kid` header, letting verifiers select the right JWKS key (and
// reject tokens signed by a retired key). It is updated at boot and on rotation.
var signingKID atomic.Value // string

// SetSigningKID records the active signing key id for stamping on issued tokens.
func SetSigningKID(kid string) { signingKID.Store(kid) }

func currentSigningKID() string {
	if v, ok := signingKID.Load().(string); ok {
		return v
	}
	return ""
}

// NewOAuth2Provider builds the Fosite OAuth2/OIDC provider. activeKey returns the
// current signing private key on each call, so key rotation performed in-process
// is picked up without rebuilding the provider.
func NewOAuth2Provider(storage *Storage, issuerURL string, activeKey func() *rsa.PrivateKey, systemSecret []byte) fosite.OAuth2Provider {
	config := &fosite.Config{
		AccessTokenLifespan:        15 * time.Minute,
		RefreshTokenLifespan:       30 * 24 * time.Hour,
		AuthorizeCodeLifespan:      10 * time.Minute,
		IDTokenLifespan:            1 * time.Hour,
		ScopeStrategy:              fosite.WildcardScopeStrategy,
		AudienceMatchingStrategy:   fosite.DefaultAudienceMatchingStrategy,
		EnforcePKCE:                true,
		IDTokenIssuer:              issuerURL,
		TokenURL:                   issuerURL + "/oauth2/token",
		SendDebugMessagesToClients: false,
		GlobalSecret:               systemSecret,
	}

	keyGetter := func(ctx context.Context) (interface{}, error) {
		k := activeKey()
		if k == nil {
			return nil, fmt.Errorf("no active signing key available")
		}
		return k, nil
	}

	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}

	provider := compose.Compose(
		config,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
	)

	return provider
}

// NewSession creates a new OpenID Connect session for the given subject, stamping
// the active signing key id into the token headers.
func NewSession(subject string) *openid.DefaultSession {
	headers := &jwt.Headers{}
	if kid := currentSigningKID(); kid != "" {
		headers.Extra = map[string]interface{}{"kid": kid}
	}
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:     subject,
			RequestedAt: time.Now().UTC(),
		},
		Headers: headers,
		Subject: subject,
	}
}
