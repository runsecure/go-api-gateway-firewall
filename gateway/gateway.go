// Package gateway is a configuration-driven API gateway built on chi. It
// reverse-proxies routes to upstream services while enforcing request
// hardening, authentication and JSON Schema API contracts.
//
// Typical use:
//
//	cfg, _ := gateway.LoadConfig("gateway.yaml")
//	gw, err := gateway.New(cfg,
//		gateway.WithAuthenticator("internal", myAuth),
//	)
//	if err != nil { ... }
//	log.Fatal(gw.ListenAndServe(ctx))
package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
)

// Middleware is standard net/http middleware.
type Middleware = func(http.Handler) http.Handler

// Gateway is an http.Handler serving all configured routes.
type Gateway struct {
	cfg        *Config
	mux        *chi.Mux
	logger     *slog.Logger
	registered map[string]string
}

type options struct {
	logger     *slog.Logger
	transport  http.RoundTripper
	auths      map[string]Authenticator
	authTypes  map[string]AuthenticatorFactory
	named      map[string]Middleware
	global     []Middleware
	routeHooks []func(RouteConfig) Middleware
}

// Option customizes a Gateway.
type Option func(*options)

// WithLogger sets the structured logger (default slog.Default()).
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// WithTransport overrides the upstream RoundTripper.
func WithTransport(t http.RoundTripper) Option { return func(o *options) { o.transport = t } }

// WithAuthenticator registers an authenticator instance under name so routes
// can reference it in their auth list.
func WithAuthenticator(name string, a Authenticator) Option {
	return func(o *options) { o.auths[name] = a }
}

// WithAuthenticatorType registers a factory so config can declare
// authenticators of a custom type.
func WithAuthenticatorType(typ string, f AuthenticatorFactory) Option {
	return func(o *options) { o.authTypes[typ] = f }
}

// WithNamedMiddleware registers middleware routes can opt into by name.
func WithNamedMiddleware(name string, m Middleware) Option {
	return func(o *options) { o.named[name] = m }
}

// WithMiddleware adds middleware that runs for every request, after request
// ID and path hardening but before routing.
func WithMiddleware(m ...Middleware) Option {
	return func(o *options) { o.global = append(o.global, m...) }
}

// WithRouteMiddleware adds a hook called once per route at build time; the
// returned middleware (if non-nil) runs after authentication.
func WithRouteMiddleware(f func(RouteConfig) Middleware) Option {
	return func(o *options) { o.routeHooks = append(o.routeHooks, f) }
}

// New validates cfg, compiles schemas and builds the router. All schema,
// authenticator and route errors are reported up front.
func New(cfg *Config, opts ...Option) (*Gateway, error) {
	o := &options{
		auths:     map[string]Authenticator{},
		authTypes: map[string]AuthenticatorFactory{},
		named:     map[string]Middleware{},
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.logger == nil {
		o.logger = slog.Default()
	}
	if o.transport == nil {
		o.transport = NewTransport()
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	auths, err := buildAuthenticators(cfg, o)
	if err != nil {
		return nil, err
	}

	ips := &clientIPResolver{}
	for _, c := range cfg.Server.TrustedProxies {
		ips.trusted = append(ips.trusted, netip.MustParsePrefix(c))
	}

	g := &Gateway{cfg: cfg, mux: chi.NewMux(), logger: o.logger, registered: map[string]string{}}
	g.mux.Use(entryMiddleware(o.logger, ips, boolOr(cfg.Server.AccessLog, true)), pathGuard)
	g.mux.Use(o.global...)

	globalResp := compileHeaderRules(defaultResponseHeaders, cfg.Defaults.ResponseHeaders)
	g.mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		globalResp.apply(w.Header())
		WriteProblem(w, r, http.StatusNotFound, "no route matches the request")
	})
	g.mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		globalResp.apply(w.Header())
		WriteProblem(w, r, http.StatusMethodNotAllowed, "method not allowed")
	})
	if hp := cfg.Server.HealthPath; hp != "" {
		g.mux.Get(hp, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
	}

	sc := newSchemaCompiler(cfg.BaseDir)
	buffers := newBufferPool()
	var errs []error
	for i := range cfg.Routes {
		if err := g.addRoute(&cfg.Routes[i], o, auths, sc, ips, buffers); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return g, nil
}

func buildAuthenticators(cfg *Config, o *options) (map[string]Authenticator, error) {
	out := map[string]Authenticator{}
	var errs []error
	for name, ac := range cfg.Authenticators {
		f, ok := o.authTypes[ac.Type]
		if !ok {
			f, ok = builtinAuthTypes[ac.Type]
		}
		if !ok {
			errs = append(errs, fmt.Errorf("authenticator %s: unknown type %q", name, ac.Type))
			continue
		}
		a, err := f(name, ac.Options)
		if err != nil {
			errs = append(errs, fmt.Errorf("authenticator %s: %w", name, err))
			continue
		}
		out[name] = a
	}
	for name, a := range o.auths {
		if _, dup := out[name]; dup {
			errs = append(errs, fmt.Errorf("authenticator %s: defined in both config and code", name))
		}
		out[name] = a
	}
	return out, errors.Join(errs...)
}

// ServeHTTP implements http.Handler.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) { g.mux.ServeHTTP(w, r) }

// Router exposes the underlying chi router for adding custom endpoints.
// Routes added this way bypass gateway auth and validation.
func (g *Gateway) Router() chi.Router { return g.mux }

// Config returns the configuration the gateway was built from.
func (g *Gateway) Config() *Config { return g.cfg }

func (g *Gateway) addRoute(rc *RouteConfig, o *options, auths map[string]Authenticator,
	sc *schemaCompiler, ips *clientIPResolver, buffers *bufferPool) error {
	cfg := g.cfg
	fail := func(format string, a ...any) error {
		return fmt.Errorf("route %s: %s", rc.Name, fmt.Sprintf(format, a...))
	}
	h := effectiveHardening(cfg.Defaults.Hardening, rc.Hardening)

	// Upstream
	p := &routeProxy{
		name:         rc.Name,
		preserveHost: rc.Upstream.PreserveHost,
		timeout:      rc.Upstream.Timeout.D(),
		reqHeaders:   compileHeaderRules(rc.RequestHeaders),
		reqHeaderMap: rc.RequestHeaderMap,
		respHeaders:  compileHeaderRules(defaultResponseHeaders, cfg.Defaults.ResponseHeaders, rc.ResponseHeaders),
		ips:          ips,
		logger:       g.logger,
	}
	if p.timeout == 0 {
		p.timeout = cfg.Defaults.Timeout.D()
	}
	if p.timeout == 0 {
		p.timeout = DefaultTimeout
	}
	for _, t := range rc.Upstream.Targets {
		u, _ := url.Parse(t) // validated in Config.Validate
		p.targets = append(p.targets, u)
	}
	tmpl, err := parsePathTemplate(rc.Upstream.Path)
	if err != nil {
		return fail("%v", err)
	}
	if tmpl != nil {
		routeParams := chiParams(rc.Path)
		for _, name := range tmpl.params() {
			if !slices.Contains(routeParams, name) {
				return fail("upstream path references unknown parameter {%s}", name)
			}
		}
	}
	p.tmpl = tmpl

	// Contract
	rv := &requestValidator{
		maxBody:   h.MaxBodyBytes,
		maxDepth:  h.MaxJSONDepth,
		rejectDup: boolOr(h.RejectDuplicateKeys, true),
		expose:    boolOr(cfg.Server.ExposeValidationErrors, true),
	}
	v := rc.Validation
	if rv.params, err = sc.compile(v.Params, rc.Name, "params"); err != nil {
		return err
	}
	if rv.query, err = sc.compile(v.Query, rc.Name, "query"); err != nil {
		return err
	}
	if v.Body != nil {
		if rv.body, err = sc.compile(&v.Body.SchemaRef, rc.Name, "body"); err != nil {
			return err
		}
		rv.bodyRequired = boolOr(v.Body.Required, true)
		for _, ct := range v.Body.ContentTypes {
			rv.contentTypes = append(rv.contentTypes, strings.ToLower(ct))
		}
	}
	if v.Response != nil {
		s, err := sc.compile(&v.Response.SchemaRef, rc.Name, "response")
		if err != nil {
			return err
		}
		p.respValid = &responseValidator{schema: s, statuses: v.Response.StatusCodes, maxBytes: v.Response.MaxBytes}
		if p.respValid.maxBytes == 0 {
			p.respValid.maxBytes = DefaultMaxResponseBytes
		}
	}
	p.init(o.transport, buffers)

	// Middleware chain, outermost first.
	var chain []Middleware
	limits := &requestLimits{
		maxURL: h.MaxURLLength, maxQuery: h.MaxQueryParams, maxBody: h.MaxBodyBytes,
		allowEncSlash: boolOr(h.AllowEncodedSlashes, false),
	}
	chain = append(chain, limits.middleware)

	var rl *rateLimiter
	if h.RateLimit != nil {
		rl = newRateLimiter(h.RateLimit)
		if !rl.byUser {
			chain = append(chain, rl.middleware)
		}
	}
	if n := rc.Upstream.MaxConcurrent; n > 0 {
		chain = append(chain, p.concurrencyLimit(n))
	}

	names := rc.authNames(cfg.Defaults.Auth)
	anonymous := len(names) == 0 || slices.Contains(names, AnonymousAuth)
	if anonymous && len(names) > 1 {
		return fail("%q cannot be combined with other authenticators", AnonymousAuth)
	}
	if anonymous && (len(rc.RequiredScopes) > 0 || len(rc.ForwardHeaders) > 0) {
		return fail("requiredScopes and forwardIdentity need an authenticator")
	}
	if !anonymous {
		var list []namedAuth
		for _, n := range names {
			a, ok := auths[n]
			if !ok {
				return fail("unknown authenticator %q", n)
			}
			list = append(list, namedAuth{name: n, a: a})
		}
		fwd := map[string]string{}
		for hdr, src := range rc.ForwardHeaders {
			if !validForwardSource(src) {
				return fail("forwardIdentity %s: invalid source %q", hdr, src)
			}
			fwd[http.CanonicalHeaderKey(hdr)] = src
		}
		chain = append(chain, authMiddleware(list, rc.RequiredScopes, fwd, g.authLog))
	} else if len(cfg.Defaults.Auth) == 0 && len(rc.Auth) == 0 {
		g.logger.Warn("route has no authentication configured", "route", rc.Name)
	}
	if rl != nil && rl.byUser {
		chain = append(chain, rl.middleware)
	}
	for _, hook := range o.routeHooks {
		if m := hook(*rc); m != nil {
			chain = append(chain, m)
		}
	}
	for _, n := range rc.Middleware {
		m, ok := o.named[n]
		if !ok {
			return fail("unknown middleware %q", n)
		}
		chain = append(chain, m)
	}
	if rv.params != nil || rv.query != nil || rv.body != nil {
		chain = append(chain, rv.middleware)
	}

	for _, m := range rc.Methods {
		key := strings.ToUpper(m) + " " + rc.Path
		if other, dup := g.registered[key]; dup {
			return fail("%s conflicts with route %s", key, other)
		}
		g.registered[key] = rc.Name
	}
	return registerRoute(g.mux.With(chain...), rc, p)
}

// registerRoute converts chi's pattern panics into errors.
func registerRoute(r chi.Router, rc *RouteConfig, h http.Handler) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("route %s: invalid path %q: %v", rc.Name, rc.Path, v)
		}
	}()
	for _, m := range rc.Methods {
		r.Method(strings.ToUpper(m), rc.Path, h)
	}
	return nil
}

func (g *Gateway) authLog(r *http.Request, msg string, args ...any) {
	args = append(args, "request_id", RequestIDFrom(r.Context()), "client_ip", ClientIPFrom(r.Context()))
	g.logger.WarnContext(r.Context(), msg, args...)
}

// chiParams extracts parameter names from a chi pattern, including "*".
func chiParams(pattern string) []string {
	var out []string
	for seg := range strings.SplitSeq(pattern, "/") {
		if seg == "*" {
			out = append(out, "*")
			continue
		}
		for seg != "" {
			i := strings.IndexByte(seg, '{')
			if i < 0 {
				break
			}
			j := strings.IndexByte(seg[i:], '}')
			if j < 0 {
				break
			}
			name, _, _ := strings.Cut(seg[i+1:i+j], ":")
			out = append(out, name)
			seg = seg[i+j+1:]
		}
	}
	return out
}
