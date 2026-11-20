package gateway

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"
)

// JWTOptions configures the built-in "jwt" authenticator. It verifies
// compact JWS tokens using a single static key; for JWKS or token
// introspection, register a custom authenticator type.
type JWTOptions struct {
	// Algorithms allowed, e.g. ["RS256"]. All must match the key type, which
	// prevents algorithm-confusion attacks. "none" is never accepted.
	Algorithms []string `json:"algorithms"`
	// Secret is the HMAC key for HS* algorithms (supports env:/file:).
	Secret string `json:"secret,omitempty"`
	// PublicKey is a PEM public key for RS*/PS*/ES* (supports env:/file:).
	PublicKey string `json:"publicKey,omitempty"`

	Issuer   string   `json:"issuer,omitempty"`
	Audience []string `json:"audience,omitempty"`
	Leeway   Duration `json:"leeway,omitempty"`
	// ScopeClaim holds scopes as a space-separated string or array
	// (default "scope").
	ScopeClaim string `json:"scopeClaim,omitempty"`
	// Header carrying "Bearer <token>" (default Authorization).
	Header string `json:"header,omitempty"`
}

const maxTokenBytes = 8 << 10

type jwtAuth struct {
	algs       []string
	hmacKey    []byte
	pub        crypto.PublicKey
	issuer     string
	audience   []string
	leeway     time.Duration
	scopeClaim string
	header     string
	now        func() time.Time
}

func newJWTAuthenticator(name string, raw json.RawMessage) (Authenticator, error) {
	var o JWTOptions
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	return NewJWTAuthenticator(o)
}

// NewJWTAuthenticator builds a JWT authenticator from options.
func NewJWTAuthenticator(o JWTOptions) (Authenticator, error) {
	if len(o.Algorithms) == 0 {
		return nil, errors.New("algorithms is required")
	}
	a := &jwtAuth{
		algs: o.Algorithms, issuer: o.Issuer, audience: o.Audience,
		leeway: o.Leeway.D(), scopeClaim: o.ScopeClaim, header: o.Header, now: time.Now,
	}
	if a.scopeClaim == "" {
		a.scopeClaim = "scope"
	}
	if a.header == "" {
		a.header = "Authorization"
	}
	family := ""
	for _, alg := range o.Algorithms {
		f, ok := jwtAlgFamily(alg)
		if !ok {
			return nil, fmt.Errorf("unsupported algorithm %q", alg)
		}
		if family != "" && f != family {
			return nil, errors.New("algorithms must all use the same key type")
		}
		family = f
	}
	switch family {
	case "HS":
		s, err := resolveSecret(o.Secret)
		if err != nil {
			return nil, fmt.Errorf("secret: %w", err)
		}
		if len(s) < 32 {
			return nil, errors.New("HMAC secret must be at least 32 bytes")
		}
		a.hmacKey = []byte(s)
	default:
		p, err := resolveSecret(o.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("publicKey: %w", err)
		}
		pub, err := parsePublicKey([]byte(p))
		if err != nil {
			return nil, err
		}
		switch pub.(type) {
		case *rsa.PublicKey:
			if family != "RS" && family != "PS" {
				return nil, errors.New("RSA key requires RS*/PS* algorithms")
			}
		case *ecdsa.PublicKey:
			if family != "ES" {
				return nil, errors.New("EC key requires ES* algorithms")
			}
		default:
			return nil, errors.New("unsupported public key type")
		}
		a.pub = pub
	}
	return a, nil
}

func jwtAlgFamily(alg string) (string, bool) {
	switch alg {
	case "HS256", "HS384", "HS512":
		return "HS", true
	case "RS256", "RS384", "RS512":
		return "RS", true
	case "PS256", "PS384", "PS512":
		return "PS", true
	case "ES256", "ES384", "ES512":
		return "ES", true
	}
	return "", false
}

func jwtHash(alg string) (crypto.Hash, func() hash.Hash) {
	switch alg[2:] {
	case "384":
		return crypto.SHA384, sha512.New384
	case "512":
		return crypto.SHA512, sha512.New
	default:
		return crypto.SHA256, sha256.New
	}
}

func parsePublicKey(b []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("publicKey: no PEM block found")
	}
	switch blk.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(blk.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(blk.Bytes)
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		return c.PublicKey, nil
	}
	return nil, fmt.Errorf("publicKey: unsupported PEM type %q", blk.Type)
}

var b64 = base64.RawURLEncoding

func (a *jwtAuth) Authenticate(r *http.Request) (*Principal, error) {
	h := r.Header.Get(a.header)
	if h == "" {
		return nil, ErrNoCredentials
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, ErrNoCredentials
	}
	tok = strings.TrimSpace(tok)
	if len(tok) > maxTokenBytes {
		return nil, errors.New("token too large")
	}
	claims, err := a.verify(tok)
	if err != nil {
		return nil, err
	}
	p := &Principal{Claims: claims}
	if sub, ok := claims["sub"].(string); ok {
		p.Subject = sub
	}
	switch s := claims[a.scopeClaim].(type) {
	case string:
		p.Scopes = strings.Fields(s)
	case []any:
		for _, v := range s {
			if str, ok := v.(string); ok {
				p.Scopes = append(p.Scopes, str)
			}
		}
	}
	return p, nil
}

func (a *jwtAuth) verify(tok string) (map[string]any, error) {
	hdrB64, rest, ok := strings.Cut(tok, ".")
	if !ok {
		return nil, errors.New("malformed token")
	}
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(sigB64, ".") {
		return nil, errors.New("malformed token")
	}
	hdrJSON, err := b64.DecodeString(hdrB64)
	if err != nil {
		return nil, errors.New("malformed header")
	}
	var hdr struct {
		Alg  string   `json:"alg"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		return nil, errors.New("malformed header")
	}
	if len(hdr.Crit) > 0 {
		return nil, errors.New("unsupported critical header")
	}
	if !slices.Contains(a.algs, hdr.Alg) {
		return nil, fmt.Errorf("algorithm %q not allowed", hdr.Alg)
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	if err := a.checkSignature(hdr.Alg, tok[:len(hdrB64)+1+len(payloadB64)], sig); err != nil {
		return nil, err
	}
	payload, err := b64.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("malformed payload")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, errors.New("malformed claims")
	}
	return claims, a.checkClaims(claims)
}

func (a *jwtAuth) checkSignature(alg, signingInput string, sig []byte) error {
	ch, hf := jwtHash(alg)
	switch alg[:2] {
	case "HS":
		m := hmac.New(hf, a.hmacKey)
		m.Write([]byte(signingInput))
		if !hmac.Equal(m.Sum(nil), sig) {
			return errors.New("invalid signature")
		}
		return nil
	}
	hh := hf()
	hh.Write([]byte(signingInput))
	digest := hh.Sum(nil)
	switch k := a.pub.(type) {
	case *rsa.PublicKey:
		var err error
		if alg[:2] == "PS" {
			err = rsa.VerifyPSS(k, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			err = rsa.VerifyPKCS1v15(k, ch, digest, sig)
		}
		if err != nil {
			return errors.New("invalid signature")
		}
		return nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("invalid signature")
		}
		rr := new(big.Int).SetBytes(sig[:size])
		ss := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, rr, ss) {
			return errors.New("invalid signature")
		}
		return nil
	}
	return errors.New("invalid signature")
}

func (a *jwtAuth) checkClaims(c map[string]any) error {
	now := a.now()
	exp, ok := numericDate(c["exp"])
	if !ok {
		return errors.New("missing or invalid exp")
	}
	if !now.Before(exp.Add(a.leeway)) {
		return errors.New("token expired")
	}
	if _, present := c["nbf"]; present {
		nbf, ok := numericDate(c["nbf"])
		if !ok {
			return errors.New("invalid nbf")
		}
		if now.Add(a.leeway).Before(nbf) {
			return errors.New("token not yet valid")
		}
	}
	if a.issuer != "" {
		if iss, _ := c["iss"].(string); iss != a.issuer {
			return errors.New("issuer mismatch")
		}
	}
	if len(a.audience) > 0 && !audienceMatches(c["aud"], a.audience) {
		return errors.New("audience mismatch")
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}

func audienceMatches(aud any, want []string) bool {
	switch v := aud.(type) {
	case string:
		return slices.Contains(want, v)
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && slices.Contains(want, s) {
				return true
			}
		}
	}
	return false
}
