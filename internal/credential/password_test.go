package credential_test

import (
	"strings"
	"testing"

	"github.com/legant-dev/legant/internal/credential"
)

func TestHashAndVerifyPassword(t *testing.T) {
	const pw = "correct horse battery staple"
	enc, err := credential.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Errorf("encoded hash should be argon2id PHC form, got %q", enc)
	}

	ok, err := credential.VerifyPassword(pw, enc)
	if err != nil || !ok {
		t.Fatalf("correct password must verify, ok=%v err=%v", ok, err)
	}
	if ok, _ := credential.VerifyPassword("wrong password", enc); ok {
		t.Error("a wrong password must not verify")
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	a, _ := credential.HashPassword("same")
	b, _ := credential.HashPassword("same")
	if a == b {
		t.Error("two hashes of the same password must differ (random salt)")
	}
	// Each still verifies its own input.
	if ok, _ := credential.VerifyPassword("same", a); !ok {
		t.Error("salted hash a must verify")
	}
	if ok, _ := credential.VerifyPassword("same", b); !ok {
		t.Error("salted hash b must verify")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2id$only$three", "$a$b$c$d$e"} {
		if ok, err := credential.VerifyPassword("x", bad); ok || err == nil {
			t.Errorf("malformed hash %q must error and not verify (ok=%v err=%v)", bad, ok, err)
		}
	}
}
