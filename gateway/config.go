package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// Config is the root gateway configuration. It is normally loaded from a JSON
// or YAML file with LoadConfig, but may also be constructed in code.
type Config struct {
	Server         ServerConfig                   `json:"server"`
	Defaults       RouteDefaults                  `json:"defaults"`
	Authenticators map[string]AuthenticatorConfig `json:"authenticators,omitempty"`
	Routes         []RouteConfig                  `json:"routes"`

	// BaseDir is the directory relative schema files are resolved against.
	// LoadConfig sets it to the config file's directory.
	BaseDir string `json:"-"`
}

// ServerConfig controls the HTTP listener used by the host executable.
type ServerConfig struct {
	Listen            string     `json:"listen,omitempty"`
	ReadTimeout       Duration   `json:"readTimeout,omitempty"`
	ReadHeaderTimeout Duration   `json:"readHeaderTimeout,omitempty"`
	WriteTimeout      Duration   `json:"writeTimeout,omitempty"`
	IdleTimeout       Duration   `json:"idleTimeout,omitempty"`
	ShutdownTimeout   Duration   `json:"shutdownTimeout,omitempty"`
	MaxHeaderBytes    int        `json:"maxHeaderBytes,omitempty"`
	TLS               *TLSConfig `json:"tls,omitempty"`

	// HealthPath, when set, serves a 200 liveness response at that path.
	HealthPath string `json:"healthPath,omitempty"`

	// TrustedProxies lists CIDRs whose X-Forwarded-For headers are trusted
	// when determining the client IP (used by rate limiting and logs).
	TrustedProxies []string `json:"trustedProxies,omitempty"`

	// ExposeValidationErrors includes schema error details in 400 responses.
	// Defaults to true; set false to return only a generic message.
	ExposeValidationErrors *bool `json:"exposeValidationErrors,omitempty"`

	// AccessLog enables structured per-request logging. Defaults to true.
	AccessLog *bool `json:"accessLog,omitempty"`

	// LogHeaders lists inbound request headers whose values are added to the
	// access log under "headers", e.g. a CDN client-IP header or trace IDs.
	// Values are logged as received, before any gateway processing.
	// Credential headers cannot be listed.
	LogHeaders []string `json:"logHeaders,omitempty"`
}

// Limits on server.logHeaders.
const (
	maxLogHeaders         = 32
	maxLoggedHeaderLength = 256
)

// credentialHeaders can never be logged.
var credentialHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"}

// TLSConfig enables HTTPS on the listener.
type TLSConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// RouteDefaults are applied to every route unless overridden.
type RouteDefaults struct {
	Hardening       HardeningConfig `json:"hardening"`
	Auth            []string        `json:"auth,omitempty"`
	Timeout         Duration        `json:"timeout,omitempty"`
	ResponseHeaders HeaderRules     `json:"responseHeaders"`
}

// AuthenticatorConfig declares a named authenticator instance. Type selects a
// registered factory ("jwt", "apikey", or one registered with
// WithAuthenticatorType); Options is passed to that factory verbatim.
type AuthenticatorConfig struct {
	Type    string          `json:"type"`
	Options json.RawMessage `json:"options,omitempty"`
}

// RouteConfig defines a single gateway route.
type RouteConfig struct {
	Name string `json:"name"`
	// Path is a chi route pattern, e.g. /api/orders/{id} or /static/*.
	Path    string   `json:"path"`
	Methods []string `json:"methods"`

	Upstream UpstreamConfig `json:"upstream"`

	// Auth lists authenticator names; the first that succeeds wins. An empty
	// list inherits Defaults.Auth. Use ["anonymous"] to explicitly disable.
	Auth           []string          `json:"auth,omitempty"`
	RequiredScopes []string          `json:"requiredScopes,omitempty"`
	ForwardHeaders map[string]string `json:"forwardIdentity,omitempty"`

	Validation ValidationConfig `json:"validation"`
	Hardening  *HardeningConfig `json:"hardening,omitempty"`

	RequestHeaders  HeaderRules `json:"requestHeaders"`
	ResponseHeaders HeaderRules `json:"responseHeaders"`
	// RequestHeaderMap maps upstream header names to incoming header names.
	RequestHeaderMap map[string]string `json:"requestHeaderMap,omitempty"`

	// Middleware lists names registered with WithNamedMiddleware, applied in
	// order after authentication and before validation.
	Middleware []string `json:"middleware,omitempty"`
}

// UpstreamConfig describes where a route is forwarded.
type UpstreamConfig struct {
	// Targets are base URLs; requests are balanced round-robin.
	Targets []string `json:"targets"`
	// Path optionally rewrites the upstream path. {name} placeholders are
	// replaced by route parameters and {*} by the wildcard remainder. When
	// empty the inbound path is forwarded unchanged.
	Path         string   `json:"path,omitempty"`
	PreserveHost bool     `json:"preserveHost,omitempty"`
	Timeout      Duration `json:"timeout,omitempty"`
	// MaxConcurrent caps in-flight requests to this route (0 = unlimited).
	MaxConcurrent int `json:"maxConcurrent,omitempty"`
	// AllowUpgrades lists the protocols a client may switch to with an
	// Upgrade request, e.g. ["websocket"]. An upgraded connection is a raw
	// tunnel to the upstream that bypasses validation, so it is off unless
	// listed here. "h2c" can never be listed.
	AllowUpgrades []string `json:"allowUpgrades,omitempty"`
}

// ValidationConfig declares the API contract enforced for a route.
type ValidationConfig struct {
	Body     *BodyValidation     `json:"body,omitempty"`
	Query    *SchemaRef          `json:"query,omitempty"`
	Params   *SchemaRef          `json:"params,omitempty"`
	Response *ResponseValidation `json:"response,omitempty"`
}

// SchemaRef is an inline JSON Schema or a path to a schema file.
type SchemaRef struct {
	Schema json.RawMessage `json:"schema,omitempty"`
	File   string          `json:"file,omitempty"`
}

// BodyValidation validates JSON request bodies.
type BodyValidation struct {
	SchemaRef
	// Required rejects requests with an empty body. Defaults to true.
	Required *bool `json:"required,omitempty"`
	// ContentTypes allowed for the body. Defaults to application/json and
	// any application/*+json type.
	ContentTypes []string `json:"contentTypes,omitempty"`
}

// ResponseValidation filters and validates upstream JSON responses.
// Properties the schema does not declare are stripped before the response is
// forwarded; a response that still violates the schema is replaced with 502.
type ResponseValidation struct {
	SchemaRef
	// StatusCodes the schema covers, e.g. [200, 201]. Required: there is no
	// default, so every status the upstream may answer with is a deliberate
	// choice. Entries must be 200-399; error statuses are never forwarded.
	// Any other non-error status that can carry a body is replaced with 502.
	StatusCodes []int `json:"statusCodes"`
	// MaxBytes bounds the buffered response size (default 4 MiB).
	MaxBytes int64 `json:"maxBytes,omitempty"`
}

// HeaderRules adds or strips headers.
type HeaderRules struct {
	Set    map[string]string `json:"set,omitempty"`
	Remove []string          `json:"remove,omitempty"`
	// Allow (response headers only) extends the allowlist of upstream
	// response headers forwarded to the caller. Upstream headers not on the
	// built-in list or any applicable Allow list are dropped.
	Allow []string `json:"allow,omitempty"`
}

// HardeningConfig contains request hardening limits. Zero values inherit
// from Defaults.Hardening, which in turn falls back to built-in defaults.
type HardeningConfig struct {
	MaxBodyBytes   int64 `json:"maxBodyBytes,omitempty"`
	MaxURLLength   int   `json:"maxUrlLength,omitempty"`
	MaxQueryParams int   `json:"maxQueryParams,omitempty"`
	MaxJSONDepth   int   `json:"maxJsonDepth,omitempty"`

	// RejectDuplicateKeys rejects JSON objects with repeated keys, closing a
	// parser-differential bypass between the gateway and upstreams.
	RejectDuplicateKeys *bool `json:"rejectDuplicateKeys,omitempty"`
	// AllowEncodedSlashes permits %2F and %5C in request paths.
	AllowEncodedSlashes *bool `json:"allowEncodedSlashes,omitempty"`

	RateLimit *RateLimitConfig `json:"rateLimit,omitempty"`
}

// RateLimitConfig is a per-client token bucket.
type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	Burst             int     `json:"burst"`
	// Key is "ip" (default) or "principal" (falls back to ip when anonymous).
	Key string `json:"key,omitempty"`
}

// Built-in hardening defaults.
const (
	DefaultMaxBodyBytes     int64 = 1 << 20
	DefaultMaxURLLength           = 4096
	DefaultMaxQueryParams         = 64
	DefaultMaxJSONDepth           = 32
	DefaultMaxResponseBytes int64 = 4 << 20
	DefaultTimeout                = 30 * time.Second
)

// Duration is a time.Duration that marshals as a Go duration string ("10s").
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("duration %q must not be negative", s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// LoadConfig reads a JSON (.json) or YAML (.yaml/.yml) config file. Unknown
// fields are rejected so typos in security settings fail loudly.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	cfg, err := ParseConfig(raw, ext == ".yaml" || ext == ".yml")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	cfg.BaseDir = abs
	return cfg, nil
}

// ParseConfig parses config bytes. YAML is converted to JSON first so both
// formats share one strict decoder and inline schemas become plain JSON.
func ParseConfig(raw []byte, isYAML bool) (*Config, error) {
	if isYAML {
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		j, err := json.Marshal(doc)
		if err != nil {
			return nil, fmt.Errorf("converting yaml: %w", err)
		}
		raw = j
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the configuration for structural errors.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for _, cidr := range c.Server.TrustedProxies {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			add("server.trustedProxies: %v", err)
		}
	}
	if len(c.Server.LogHeaders) > maxLogHeaders {
		add("server.logHeaders: at most %d headers", maxLogHeaders)
	}
	secret := c.credentialHeaders()
	for _, h := range c.Server.LogHeaders {
		switch {
		case !validHeaderName(h):
			add("server.logHeaders: invalid header name %q", h)
		case slices.Contains(secret, http.CanonicalHeaderKey(h)):
			add("server.logHeaders: %q carries credentials and cannot be logged", h)
		}
	}
	if t := c.Server.TLS; t != nil && (t.CertFile == "" || t.KeyFile == "") {
		add("server.tls: certFile and keyFile are both required")
	}
	for name, a := range c.Authenticators {
		if a.Type == "" {
			add("authenticators.%s: type is required", name)
		}
		if name == AnonymousAuth {
			add("authenticators.%s: name is reserved", name)
		}
	}
	if len(c.Routes) == 0 {
		add("routes: at least one route is required")
	}
	seen := map[string]bool{}
	for i, r := range c.Routes {
		id := r.Name
		if id == "" {
			id = fmt.Sprintf("#%d", i)
			add("routes[%d]: name is required", i)
		} else if seen[r.Name] {
			add("routes.%s: duplicate route name", id)
		}
		seen[r.Name] = true
		if !strings.HasPrefix(r.Path, "/") {
			add("routes.%s: path must start with /", id)
		}
		if len(r.Methods) == 0 {
			add("routes.%s: at least one method is required", id)
		}
		for _, m := range r.Methods {
			if !validMethods[strings.ToUpper(m)] {
				add("routes.%s: unsupported method %q", id, m)
			}
		}
		if len(r.Upstream.Targets) == 0 {
			add("routes.%s: upstream.targets is required", id)
		}
		for _, t := range r.Upstream.Targets {
			u, err := url.Parse(t)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				add("routes.%s: invalid upstream target %q", id, t)
			}
		}
		if len(r.RequestHeaders.Allow) > 0 {
			add("routes.%s: requestHeaders.allow is not supported", id)
		}
		for _, h := range r.ResponseHeaders.Allow {
			if !validHeaderName(h) {
				add("routes.%s: invalid responseHeaders.allow entry %q", id, h)
			}
		}
		for _, proto := range r.Upstream.AllowUpgrades {
			switch {
			case !validHeaderName(proto):
				add("routes.%s: invalid upstream.allowUpgrades entry %q", id, proto)
			case strings.EqualFold(proto, "h2c"):
				add("routes.%s: upstream.allowUpgrades cannot include h2c", id)
			}
		}
		if r.Upstream.MaxConcurrent < 0 {
			add("routes.%s: upstream.maxConcurrent must be >= 0", id)
		}
		mapped := map[string]bool{}
		for dest, source := range r.RequestHeaderMap {
			d := strings.ToLower(dest)
			if !validHeaderName(dest) || !validHeaderName(source) {
				add("routes.%s: invalid requestHeaderMap entry %q: %q", id, dest, source)
			}
			if mapped[d] {
				add("routes.%s: duplicate requestHeaderMap destination %q", id, dest)
			}
			mapped[d] = true
			if forbiddenMappedHeader(d) {
				add("routes.%s: requestHeaderMap destination %q is reserved", id, dest)
			}
			for h := range r.ForwardHeaders {
				if strings.EqualFold(dest, h) {
					add("routes.%s: requestHeaderMap destination %q conflicts with forwardIdentity", id, dest)
				}
			}
		}
		for _, s := range []*SchemaRef{r.Validation.Query, r.Validation.Params, bodyRef(r.Validation.Body), respRef(r.Validation.Response)} {
			if s != nil && (len(s.Schema) == 0) == (s.File == "") {
				add("routes.%s: each validation entry needs exactly one of schema or file", id)
			}
		}
		if resp := r.Validation.Response; resp != nil {
			if len(resp.StatusCodes) == 0 {
				add("routes.%s: validation.response.statusCodes is required", id)
			}
			for _, code := range resp.StatusCodes {
				if code < 200 || code > 399 {
					add("routes.%s: validation.response.statusCodes: %d is not a 2xx or 3xx status", id, code)
				}
			}
		}
		if h := r.Hardening; h != nil && h.RateLimit != nil {
			if err := h.RateLimit.validate(); err != nil {
				add("routes.%s: %v", id, err)
			}
		}
	}
	for _, h := range c.Defaults.ResponseHeaders.Allow {
		if !validHeaderName(h) {
			add("defaults: invalid responseHeaders.allow entry %q", h)
		}
	}
	if rl := c.Defaults.Hardening.RateLimit; rl != nil {
		if err := rl.validate(); err != nil {
			add("defaults: %v", err)
		}
	}
	return errors.Join(errs...)
}

// credentialHeaders returns the canonical names of headers that carry
// credentials: the fixed list plus any "header" option set on an
// authenticator (the built-in jwt and apikey types both use it).
func (c *Config) credentialHeaders() []string {
	out := slices.Clone(credentialHeaders)
	for i := range out {
		out[i] = http.CanonicalHeaderKey(out[i])
	}
	for _, a := range c.Authenticators {
		var o struct {
			Header string `json:"header"`
		}
		if json.Unmarshal(a.Options, &o) == nil && o.Header != "" {
			out = append(out, http.CanonicalHeaderKey(o.Header))
		}
	}
	return out
}

func (r *RateLimitConfig) validate() error {
	if r.RequestsPerSecond <= 0 || r.Burst <= 0 {
		return errors.New("rateLimit: requestsPerSecond and burst must be > 0")
	}
	if r.Key != "" && r.Key != "ip" && r.Key != "principal" {
		return fmt.Errorf("rateLimit: unknown key %q", r.Key)
	}
	return nil
}

func bodyRef(b *BodyValidation) *SchemaRef {
	if b == nil {
		return nil
	}
	return &b.SchemaRef
}

func respRef(b *ResponseValidation) *SchemaRef {
	if b == nil {
		return nil
	}
	return &b.SchemaRef
}

func (r *RouteConfig) authNames(defaults []string) []string {
	if len(r.Auth) > 0 {
		return r.Auth
	}
	return defaults
}

var validMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "OPTIONS": true,
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func forbiddenMappedHeader(s string) bool {
	switch s {
	case "host", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade", "forwarded":
		return true
	}
	return strings.HasPrefix(s, "x-forwarded-")
}

// effectiveHardening merges route overrides over defaults over built-ins.
func effectiveHardening(def HardeningConfig, route *HardeningConfig) HardeningConfig {
	h := def
	if route != nil {
		if route.MaxBodyBytes != 0 {
			h.MaxBodyBytes = route.MaxBodyBytes
		}
		if route.MaxURLLength != 0 {
			h.MaxURLLength = route.MaxURLLength
		}
		if route.MaxQueryParams != 0 {
			h.MaxQueryParams = route.MaxQueryParams
		}
		if route.MaxJSONDepth != 0 {
			h.MaxJSONDepth = route.MaxJSONDepth
		}
		if route.RejectDuplicateKeys != nil {
			h.RejectDuplicateKeys = route.RejectDuplicateKeys
		}
		if route.AllowEncodedSlashes != nil {
			h.AllowEncodedSlashes = route.AllowEncodedSlashes
		}
		if route.RateLimit != nil {
			h.RateLimit = route.RateLimit
		}
	}
	if h.MaxBodyBytes == 0 {
		h.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if h.MaxURLLength == 0 {
		h.MaxURLLength = DefaultMaxURLLength
	}
	if h.MaxQueryParams == 0 {
		h.MaxQueryParams = DefaultMaxQueryParams
	}
	if h.MaxJSONDepth == 0 {
		h.MaxJSONDepth = DefaultMaxJSONDepth
	}
	return h
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
