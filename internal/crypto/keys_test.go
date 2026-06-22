package crypto

import (
	"bytes"
	"testing"
)

func TestAESGCMWithAADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	aad := []byte("legant-kek-v1|rk_abc123|sig")
	pt := []byte("an RSA private key in PEM form")

	ct, err := EncryptAESGCMWithAAD(pt, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAESGCMWithAAD(ct, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round-trip mismatch")
	}
}

func TestAESGCMAADMismatchFails(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	ct, err := EncryptAESGCMWithAAD([]byte("data"), key, []byte("aad-for-key-A"))
	if err != nil {
		t.Fatal(err)
	}
	// Decrypting with a different AAD (e.g. another key's id) must fail — this is
	// what prevents one signing key's ciphertext from being swapped for another's.
	if _, err := DecryptAESGCMWithAAD(ct, key, []byte("aad-for-key-B")); err == nil {
		t.Fatal("decrypt with mismatched AAD must fail")
	}
}

func TestAESGCMTamperFails(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	ct, err := EncryptAESGCMWithAAD([]byte("data"), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xff
	if _, err := DecryptAESGCMWithAAD(ct, key, nil); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestEncryptAESGCMBackwardCompatible(t *testing.T) {
	key := bytes.Repeat([]byte("x"), 16)
	ct, err := EncryptAESGCM([]byte("hello"), key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptAESGCM(ct, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatal("no-AAD round-trip mismatch")
	}
}

func TestDeriveKeyDeterministicAndSeparated(t *testing.T) {
	master := []byte("a-master-secret-of-sufficient-length!!")

	a1, err := DeriveKey(master, "use-a")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := DeriveKey(master, "use-a")
	b, _ := DeriveKey(master, "use-b")

	if !bytes.Equal(a1, a2) {
		t.Fatal("derivation must be deterministic for the same label")
	}
	if bytes.Equal(a1, b) {
		t.Fatal("different labels must yield independent keys (domain separation)")
	}
	if len(a1) != 32 {
		t.Fatalf("want 32-byte key, got %d", len(a1))
	}
	if bytes.Equal(a1, master[:32]) {
		t.Fatal("derived key must not equal the raw master secret")
	}
}

func TestDeriveKeyRejectsEmptyMaster(t *testing.T) {
	if _, err := DeriveKey(nil, "use"); err == nil {
		t.Fatal("empty master secret must error")
	}
}
