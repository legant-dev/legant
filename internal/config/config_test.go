package config

import (
	"strings"
	"testing"
)

func TestValidators(t *testing.T) {
	s32 := strings.Repeat("a", 32)

	// Server mode requires both the system and cookie secrets.
	full := Config{Secrets: SecretsConfig{System: s32, Cookie: s32}}
	if err := validate(&full); err != nil {
		t.Fatalf("server validate with full secrets: %v", err)
	}
	if err := validate(&Config{Secrets: SecretsConfig{System: s32}}); err == nil {
		t.Fatal("server validate must require the cookie secret")
	}

	// Gateway mode needs neither system nor cookie — only key material to read the
	// signing keys (so the gateway pod no longer crash-loops on missing secrets).
	if err := validateGateway(&Config{Secrets: SecretsConfig{KeyEncryption: s32}}); err != nil {
		t.Fatalf("gateway validate with only key-encryption: %v", err)
	}
	if err := validateGateway(&Config{Secrets: SecretsConfig{System: s32}}); err != nil {
		t.Fatalf("gateway validate with only system: %v", err)
	}
	if err := validateGateway(&Config{}); err == nil {
		t.Fatal("gateway validate must require system OR key-encryption")
	}

	// Minimal mode (migrate, maintenance) requires no secrets at all.
	if err := validateMinimal(&Config{}); err != nil {
		t.Fatalf("minimal validate with no secrets: %v", err)
	}
	if err := validateMinimal(&Config{Secrets: SecretsConfig{KeyEncryption: "short"}}); err == nil {
		t.Fatal("minimal validate must reject a too-short key-encryption secret")
	}
}

func TestKeyEncryptionMaterialDerivesWhenUnset(t *testing.T) {
	s := SecretsConfig{System: "a-sufficiently-long-system-secret-value!!"}
	m, err := s.KeyEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 32 {
		t.Fatalf("derived material should be 32 bytes, got %d", len(m))
	}
	if string(m) == s.System {
		t.Fatal("derived key must not equal the raw system secret (must be domain-separated)")
	}
}

func TestKeyEncryptionMaterialUsesExplicitWhenSet(t *testing.T) {
	explicit := "an-explicit-key-encryption-secret-32!!"
	s := SecretsConfig{System: "x", KeyEncryption: explicit}
	m, err := s.KeyEncryptionMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if string(m) != explicit {
		t.Fatal("an explicitly configured key-encryption secret must be used verbatim")
	}
}
