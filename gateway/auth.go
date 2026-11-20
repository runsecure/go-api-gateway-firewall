package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// AnonymousAuth is the reserved authenticator name that disables
// authentication for a route.
const AnonymousAuth = "anonymous"

// ErrNoCredentials signals that a request carried no credentials for this
// authenticator, so the next configured authenticator should be tried.
var ErrNoCredentials = errors.New("no credentials")

// Principal is the authenticated identity attached to a request context.
type Principal struct {
	Subject       string
	Authenticator string
	Scopes        []string
	Claims        map[string]any
}

// HasScope reports whether the principal was granted scope.
func (p *Principal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

// Authenticator verifies request credentials.
//
// Return ErrNoCredentials (or an error wrapping it) when the request does not
// carry this authenticator's credential type, letting the gateway try the
// next one. Any other error rejects the request with 401.
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request) (*Principal, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (*Principal, error) { return f(r) }

// AuthenticatorFactory builds an Authenticator from config options. Register
// factories with WithAuthenticatorType to make custom types usable from config.
type AuthenticatorFactory func(name string, options json.RawMessage) (Authenticator, error)

var builtinAuthTypes = map[string]AuthenticatorFactory{
	"jwt":    newJWTAuthenticator,
	"apikey": newAPIKeyAuthenticator,
}

type principalKey struct{}

// PrincipalFrom returns the authenticated principal, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

type namedAuth struct {
	name string
	a    Authenticator
}

// authMiddleware tries each authenticator in order and enforces scopes.
func authMiddleware(auths []namedAuth, scopes []string, forward map[string]string, log logFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Never let clients supply identity headers the gateway injects.
			for h := range forward {
				r.Header.Del(h)
			}
			var p *Principal
			for _, na := range auths {
				got, err := na.a.Authenticate(r)
				if errors.Is(err, ErrNoCredentials) {
					continue
				}
				if err != nil || got == nil {
					log(r, "authentication failed", "authenticator", na.name, "error", err)
					w.Header().Set("WWW-Authenticate", `Bearer realm="gateway"`)
					WriteProblem(w, r, http.StatusUnauthorized, "invalid credentials")
					return
				}
				if got.Authenticator == "" {
					got.Authenticator = na.name
				}
				p = got
				break
			}
			if p == nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="gateway"`)
				WriteProblem(w, r, http.StatusUnauthorized, "authentication required")
				return
			}
			// Recorded before the scope check so 403s show who was refused.
			requestLogFrom(r.Context()).setPrincipal(p)
			for _, s := range scopes {
				if !p.HasScope(s) {
					WriteProblem(w, r, http.StatusForbidden, "insufficient scope")
					return
				}
			}
			for h, src := range forward {
				if v, ok := principalValue(p, src); ok {
					r.Header.Set(h, v)
				}
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// principalValue resolves "subject", "authenticator", "scopes" or
// "claims.<name>" against p for identity forwarding.
func principalValue(p *Principal, src string) (string, bool) {
	switch src {
	case "subject":
		return p.Subject, p.Subject != ""
	case "authenticator":
		return p.Authenticator, true
	case "scopes":
		return strings.Join(p.Scopes, " "), len(p.Scopes) > 0
	}
	name, ok := strings.CutPrefix(src, "claims.")
	if !ok || p.Claims == nil {
		return "", false
	}
	v, ok := p.Claims[name]
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number, float64, bool:
		return fmt.Sprint(t), true
	default:
		b, err := json.Marshal(t)
		return string(b), err == nil
	}
}

func validForwardSource(src string) bool {
	switch src {
	case "subject", "authenticator", "scopes":
		return true
	}
	name, ok := strings.CutPrefix(src, "claims.")
	return ok && name != ""
}

// decodeOptions strictly decodes authenticator options.
func decodeOptions(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return errors.New("options are required")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
