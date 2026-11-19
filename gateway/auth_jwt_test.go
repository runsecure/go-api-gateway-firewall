package gateway

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"
)

func pubPEM(t *testing.T, k crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signAsym(t *testing.T, alg string, key crypto.Signer, claims map[string]any) string {
	enc := base64.RawURLEncoding
	hb, _ := json.Marshal(map[string]string{"alg": alg})
	cb, _ := json.Marshal(claims)
	in := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		var err error
		if alg == "PS256" {
			sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		}
		if err != nil {
			t.Fatal(err)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	}
	return in + "." + enc.EncodeToString(sig)
}

func TestJWTAsymmetric(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := map[string]any{"sub": "u", "exp": time.Now().Add(time.Minute).Unix()}

	for _, tc := range []struct {
		alg string
		key crypto.Signer
	}{{"RS256", rk}, {"PS256", rk}, {"ES256", ek}} {
		t.Run(tc.alg, func(t *testing.T) {
			a, err := NewJWTAuthenticator(JWTOptions{Algorithms: []string{tc.alg}, PublicKey: pubPEM(t, tc.key.Public())})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer "+signAsym(t, tc.alg, tc.key, claims))
			p, err := a.Authenticate(req)
			if err != nil || p.Subject != "u" {
				t.Fatalf("verify: %v", err)
			}
			// Tamper with payload.
			tok := signAsym(t, tc.alg, tc.key, claims)
			req.Header.Set("Authorization", "Bearer "+tok[:len(tok)-4]+"AAAA")
			if _, err := a.Authenticate(req); err == nil {
				t.Fatal("tampered signature accepted")
			}
		})
	}

	// Algorithm confusion: an RSA key must not be usable as an HMAC secret.
	if _, err := NewJWTAuthenticator(JWTOptions{Algorithms: []string{"RS256", "HS256"}, PublicKey: pubPEM(t, rk.Public())}); err == nil {
		t.Fatal("mixed algorithm families accepted")
	}
	if _, err := NewJWTAuthenticator(JWTOptions{Algorithms: []string{"ES256"}, PublicKey: pubPEM(t, rk.Public())}); err == nil {
		t.Fatal("RSA key accepted for ES256")
	}
	a, _ := NewJWTAuthenticator(JWTOptions{Algorithms: []string{"RS256"}, PublicKey: pubPEM(t, rk.Public())})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+signHS256(t, pubPEM(t, rk.Public()), claims))
	if _, err := a.Authenticate(req); err == nil {
		t.Fatal("HS256 token accepted by RS256 authenticator")
	}
}
