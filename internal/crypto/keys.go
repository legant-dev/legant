package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// DeriveKey derives a 32-byte subkey from a master secret for a specific use
// (e.g. "key-encryption"), using HKDF-SHA256. Domain separation means a single
// configured secret cannot be silently reused across two cryptographic contexts:
// the same master yields independent keys for different info labels.
func DeriveKey(master []byte, info string) ([]byte, error) {
	if len(master) == 0 {
		return nil, fmt.Errorf("deriving key: empty master secret")
	}
	key, err := hkdf.Key(sha256.New, master, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}
	return key, nil
}

func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}
	return key, nil
}

func MarshalPrivateKeyPEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func MarshalPublicKeyPEM(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// EncryptAESGCM encrypts plaintext with AES-256-GCM. The nonce is prepended to
// the returned ciphertext.
func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	return EncryptAESGCMWithAAD(plaintext, key, nil)
}

// DecryptAESGCM reverses EncryptAESGCM.
func DecryptAESGCM(ciphertext, key []byte) ([]byte, error) {
	return DecryptAESGCMWithAAD(ciphertext, key, nil)
}

// EncryptAESGCMWithAAD encrypts plaintext with AES-256-GCM, additionally
// authenticating (but not encrypting) additionalData. Binding AAD — e.g. a
// key id and use-type — to a stored ciphertext makes it tamper-evident and
// prevents a row from being swapped for another key's ciphertext: decryption
// fails unless the exact same AAD is supplied.
func EncryptAESGCMWithAAD(plaintext, key, additionalData []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

// DecryptAESGCMWithAAD reverses EncryptAESGCMWithAAD. It returns an error if the
// ciphertext was tampered with or additionalData does not match.
func DecryptAESGCMWithAAD(ciphertext, key, additionalData []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, body := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, body, additionalData)
}

// newGCM derives a 32-byte AES key from the provided key material via SHA-256.
// This means any key length is accepted and stretched; callers that want a
// specific security level must supply sufficiently strong material (Legant's
// envelope key is a 32-byte secret or an HKDF-derived 32-byte subkey).
func newGCM(key []byte) (cipher.AEAD, error) {
	hashedKey := sha256.Sum256(key)
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}
