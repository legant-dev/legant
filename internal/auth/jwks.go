package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sort"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

// JWKSHandler serves the JSON Web Key Set. It is backed by a function returning
// the currently-trusted public keys indexed by kid, so the set reflects key
// rotation without a restart and publishes every key a verifier may need during
// an overlap window.
func JWKSHandler(keysFn func() map[string]*rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys := keysFn()

		kids := make([]string, 0, len(keys))
		for kid := range keys {
			kids = append(kids, kid)
		}
		sort.Strings(kids) // deterministic output

		resp := JWKSResponse{Keys: make([]JWK, 0, len(keys))}
		for _, kid := range kids {
			pub := keys[kid]
			resp.Keys = append(resp.Keys, JWK{
				Kty: "RSA",
				Use: "sig",
				Kid: kid,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			})
		}

		data, _ := json.MarshalIndent(resp, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(data)
	}
}
