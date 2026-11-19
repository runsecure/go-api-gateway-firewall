package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// APIKeyOptions configures the built-in "apikey" authenticator.
//
// Keys map an identifier (used as the principal subject) to a key value.
// Values of the form "env:NAME" are read from the environment so secrets stay
// out of config files.
type APIKeyOptions struct {
	Header string              `json:"header,omitempty"` // default X-API-Key
	Keys   map[string]string   `json:"keys"`
	Scopes map[string][]string `json:"scopes,omitempty"` // per key id
}

type apiKeyAuth struct {
	header string
	keys   []apiKey
}

type apiKey struct {
	id     string
	hash   [32]byte
	scopes []string
}

func newAPIKeyAuthenticator(name string, raw json.RawMessage) (Authenticator, error) {
	var o APIKeyOptions
	if err := decodeOptions(raw, &o); err != nil {
		return nil, err
	}
	return NewAPIKeyAuthenticator(o)
}

// NewAPIKeyAuthenticator builds an API key authenticator. Keys are compared by
// SHA-256 digest in constant time.
func NewAPIKeyAuthenticator(o APIKeyOptions) (Authenticator, error) {
	if o.Header == "" {
		o.Header = "X-API-Key"
	}
	if len(o.Keys) == 0 {
		return nil, errors.New("apikey: at least one key is required")
	}
	a := &apiKeyAuth{header: http.CanonicalHeaderKey(o.Header)}
	for id, v := range o.Keys {
		val, err := resolveSecret(v)
		if err != nil {
			return nil, fmt.Errorf("apikey key %q: %w", id, err)
		}
		if len(val) < 16 {
			return nil, fmt.Errorf("apikey key %q: must be at least 16 characters", id)
		}
		a.keys = append(a.keys, apiKey{id: id, hash: sha256.Sum256([]byte(val)), scopes: o.Scopes[id]})
	}
	return a, nil
}

func (a *apiKeyAuth) Authenticate(r *http.Request) (*Principal, error) {
	v := r.Header.Get(a.header)
	if v == "" {
		return nil, ErrNoCredentials
	}
	h := sha256.Sum256([]byte(v))
	var match *apiKey
	// Compare against every key so timing does not reveal which matched.
	for i := range a.keys {
		if subtle.ConstantTimeCompare(h[:], a.keys[i].hash[:]) == 1 {
			match = &a.keys[i]
		}
	}
	if match == nil {
		return nil, errors.New("unknown api key")
	}
	// Do not forward the credential upstream.
	r.Header.Del(a.header)
	return &Principal{Subject: match.id, Scopes: match.scopes}, nil
}

// resolveSecret expands "env:NAME" and "file:/path" references.
func resolveSecret(v string) (string, error) {
	if name, ok := strings.CutPrefix(v, "env:"); ok {
		s, ok := os.LookupEnv(name)
		if !ok || s == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return s, nil
	}
	if path, ok := strings.CutPrefix(v, "file:"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}
