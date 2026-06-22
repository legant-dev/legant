package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"

	"github.com/legant-dev/legant/internal/crypto"
)

type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Secrets       SecretsConfig       `mapstructure:"secrets"`
	Issuer        IssuerConfig        `mapstructure:"issuer"`
	Session       SessionConfig       `mapstructure:"session"`
	Keystore      KeystoreConfig      `mapstructure:"keystore"`
	TokenExchange TokenExchangeConfig `mapstructure:"token_exchange"`
	Gateway       GatewayConfig       `mapstructure:"gateway"`
}

// GatewayConfig configures `legant gateway` — the MCP auth-gateway mode.
type GatewayConfig struct {
	Upstreams []UpstreamConfig `mapstructure:"upstreams"`
	// DownstreamTTL caps the lifetime of the fresh per-call token the gateway mints
	// for an upstream (still clamped to the inbound token's expiry). Default 60s.
	DownstreamTTL time.Duration `mapstructure:"downstream_ttl"`
	// RevocationRefresh selects the revocation-check mode. 0 (default) = check the
	// store per call (Tier A, instant). >0 = keep an in-memory set of revoked,
	// unexpired token ids refreshed on this interval (Tier B, avoids a per-call DB
	// read for high-QPS gateways; a revoke then takes effect within the interval).
	RevocationRefresh time.Duration `mapstructure:"revocation_refresh"`
}

type UpstreamConfig struct {
	Slug            string            `mapstructure:"slug"`
	InboundAudience string            `mapstructure:"inbound_audience"`
	URL             string            `mapstructure:"url"`
	ResourceID      string            `mapstructure:"resource_id"`
	ToolScopes      map[string]string `mapstructure:"tool_scopes"`
}

type TokenExchangeConfig struct {
	// AccessTokenLifespan caps the lifetime of a minted delegation token. Short
	// by default so a leaked token's blast radius is bounded despite offline use.
	AccessTokenLifespan time.Duration `mapstructure:"access_token_lifespan"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	// LiveIngestToken, when set, enables POST /admin/live/ingest: a shared secret a
	// connected resource server (e.g. a `legant guard` hook) presents to stream its
	// allow/deny decisions into the /admin/live console. Empty disables the endpoint.
	LiveIngestToken string `mapstructure:"live_ingest_token"`
}

func (s ServerConfig) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

type DatabaseConfig struct {
	URL          string `mapstructure:"url"`
	MaxOpenConns int    `mapstructure:"max_open_conns"`
	MaxIdleConns int    `mapstructure:"max_idle_conns"`
	AutoMigrate  bool   `mapstructure:"auto_migrate"`
}

type SecretsConfig struct {
	System string `mapstructure:"system"` // 32+ bytes, Fosite global HMAC secret
	Cookie string `mapstructure:"cookie"` // 32+ bytes, cookie signing
	// KeyEncryption is the master key used to envelope-encrypt signing keys at
	// rest. If empty it is derived from System via HKDF (domain-separated), so
	// dev works out of the box; production should set a distinct value so the
	// at-rest key is not the same material as the Fosite HMAC secret.
	KeyEncryption string `mapstructure:"key_encryption"`
}

// KeyEncryptionMaterial returns the 32-byte key used to encrypt signing keys at
// rest: the explicit KeyEncryption secret if set, otherwise an HKDF-derived
// subkey of System with a fixed domain-separation label.
func (s SecretsConfig) KeyEncryptionMaterial() ([]byte, error) {
	if s.KeyEncryption != "" {
		return []byte(s.KeyEncryption), nil
	}
	return crypto.DeriveKey([]byte(s.System), "legant-key-encryption-v1")
}

type KeystoreConfig struct {
	// RotationOverlap is how long a rotated-out signing key remains published in
	// the JWKS (so tokens it signed keep verifying) before it can be pruned.
	RotationOverlap time.Duration `mapstructure:"rotation_overlap"`
}

type IssuerConfig struct {
	URL string `mapstructure:"url"`
}

type SessionConfig struct {
	Lifetime    time.Duration `mapstructure:"lifetime"`
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
}

// Load reads configuration for the authorization server (`legant serve`), which
// requires the full secret set.
func Load() (*Config, error) { return load(validate) }

// LoadGateway reads configuration for the MCP auth-gateway (`legant gateway`),
// which does not need the Fosite system or cookie secrets.
func LoadGateway() (*Config, error) { return load(validateGateway) }

// LoadMinimal reads configuration for commands that only touch the database
// (migrations, maintenance/retention) and therefore require none of the secrets.
func LoadMinimal() (*Config, error) { return load(validateMinimal) }

func load(validateFn func(*Config) error) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("database.url", "postgres://legant:legant@localhost:5432/legant?sslmode=disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	// Default off: production runs migrations as an explicit pre-deploy step
	// (`legant migrate up`). Dev/compose opt in via LEGANT_DATABASE_AUTO_MIGRATE.
	v.SetDefault("database.auto_migrate", false)
	v.SetDefault("issuer.url", "http://localhost:8080")
	v.SetDefault("session.lifetime", "24h")
	v.SetDefault("session.idle_timeout", "1h")
	v.SetDefault("keystore.rotation_overlap", "840h") // 35 days
	v.SetDefault("token_exchange.access_token_lifespan", "5m")
	v.SetDefault("gateway.downstream_ttl", "60s")
	v.SetDefault("gateway.revocation_refresh", "0s")

	// Environment variables
	v.SetEnvPrefix("LEGANT")
	v.AutomaticEnv()

	// Explicit env bindings for nested keys
	v.BindEnv("server.host", "LEGANT_SERVER_HOST")
	v.BindEnv("server.port", "LEGANT_SERVER_PORT")
	v.BindEnv("server.live_ingest_token", "LEGANT_LIVE_INGEST_TOKEN")
	v.BindEnv("database.url", "LEGANT_DATABASE_URL")
	v.BindEnv("database.auto_migrate", "LEGANT_DATABASE_AUTO_MIGRATE")
	v.BindEnv("secrets.system", "LEGANT_SECRETS_SYSTEM")
	v.BindEnv("secrets.cookie", "LEGANT_SECRETS_COOKIE")
	v.BindEnv("secrets.key_encryption", "LEGANT_SECRETS_KEY_ENCRYPTION")
	v.BindEnv("issuer.url", "LEGANT_ISSUER_URL")
	v.BindEnv("keystore.rotation_overlap", "LEGANT_KEYSTORE_ROTATION_OVERLAP")
	v.BindEnv("token_exchange.access_token_lifespan", "LEGANT_TOKEN_EXCHANGE_ACCESS_TOKEN_LIFESPAN")
	v.BindEnv("gateway.downstream_ttl", "LEGANT_GATEWAY_DOWNSTREAM_TTL")
	v.BindEnv("gateway.revocation_refresh", "LEGANT_GATEWAY_REVOCATION_REFRESH")

	// Config file (optional)
	v.SetConfigName("legant")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/legant")
	v.AddConfigPath("$HOME/.legant")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := validateFn(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Secrets.System == "" {
		return fmt.Errorf("LEGANT_SECRETS_SYSTEM is required (32+ byte random string)")
	}
	if len(cfg.Secrets.System) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_SYSTEM must be at least 32 bytes")
	}
	if cfg.Secrets.Cookie == "" {
		return fmt.Errorf("LEGANT_SECRETS_COOKIE is required (32+ byte random string)")
	}
	if len(cfg.Secrets.Cookie) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_COOKIE must be at least 32 bytes")
	}
	if cfg.Secrets.KeyEncryption != "" && len(cfg.Secrets.KeyEncryption) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_KEY_ENCRYPTION, if set, must be at least 32 bytes")
	}
	return nil
}

// validateGateway validates config for `legant gateway`, which runs no
// OAuth/session endpoints and therefore needs neither the Fosite system secret
// nor the cookie secret. It only needs database access and the key-decryption
// material — which must match the server's so it can read the published signing
// keys (KeyEncryptionMaterial derives from System when KeyEncryption is unset, so
// at least one of the two must be present).
// validateMinimal validates config for DB-only commands (migrate, maintenance).
// They need no secrets, so only the optional key-encryption length is checked.
func validateMinimal(cfg *Config) error {
	if cfg.Secrets.KeyEncryption != "" && len(cfg.Secrets.KeyEncryption) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_KEY_ENCRYPTION, if set, must be at least 32 bytes")
	}
	return nil
}

func validateGateway(cfg *Config) error {
	if cfg.Secrets.KeyEncryption == "" && cfg.Secrets.System == "" {
		return fmt.Errorf("gateway requires LEGANT_SECRETS_KEY_ENCRYPTION (or LEGANT_SECRETS_SYSTEM) to read signing keys")
	}
	if cfg.Secrets.KeyEncryption != "" && len(cfg.Secrets.KeyEncryption) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_KEY_ENCRYPTION, if set, must be at least 32 bytes")
	}
	if cfg.Secrets.System != "" && len(cfg.Secrets.System) < 32 {
		return fmt.Errorf("LEGANT_SECRETS_SYSTEM, if set, must be at least 32 bytes")
	}
	return nil
}
