package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
)

// NewTransport returns the default upstream transport, tuned for high
// connection reuse. Environment proxy settings are deliberately ignored.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2048,
		MaxIdleConnsPerHost:    256,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// bufferPool implements httputil.BufferPool to avoid per-request copy buffers.
type bufferPool struct{ p sync.Pool }

func newBufferPool() *bufferPool {
	return &bufferPool{p: sync.Pool{New: func() any { b := make([]byte, 32<<10); return &b }}}
}

func (b *bufferPool) Get() []byte  { return *(b.p.Get().(*[]byte)) }
func (b *bufferPool) Put(x []byte) { b.p.Put(&x) }

// pathTemplate rewrites the upstream path from route parameters.
type pathTemplate struct {
	parts []tmplPart
}

type tmplPart struct {
	lit   string
	param string // "" for literal, "*" for wildcard
}

func parsePathTemplate(s string) (*pathTemplate, error) {
	if s == "" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("upstream path %q must start with /", s)
	}
	t := &pathTemplate{}
	for s != "" {
		i := strings.IndexByte(s, '{')
		if i < 0 {
			t.parts = append(t.parts, tmplPart{lit: s})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, tmplPart{lit: s[:i]})
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("upstream path %q: unclosed {", s)
		}
		name := s[i+1 : i+j]
		if name == "" {
			return nil, fmt.Errorf("upstream path %q: empty parameter", s)
		}
		t.parts = append(t.parts, tmplPart{param: name})
		s = s[i+j+1:]
	}
	return t, nil
}

// params returns placeholder names other than the wildcard.
func (t *pathTemplate) params() []string {
	var out []string
	for _, p := range t.parts {
		if p.param != "" {
			out = append(out, p.param)
		}
	}
	return out
}

// render returns the escaped upstream path. chi yields escaped parameter
// values when the request has a RawPath, so values are only escaped here
// when it does not.
func (t *pathTemplate) render(r *http.Request) string {
	rc := chi.RouteContext(r.Context())
	escaped := r.URL.RawPath != ""
	var sb strings.Builder
	for _, p := range t.parts {
		if p.param == "" {
			sb.WriteString(p.lit)
			continue
		}
		v := rc.URLParam(p.param)
		if escaped {
			sb.WriteString(v)
			continue
		}
		if p.param == "*" {
			for i, seg := range strings.Split(v, "/") {
				if i > 0 {
					sb.WriteByte('/')
				}
				sb.WriteString(url.PathEscape(seg))
			}
		} else {
			sb.WriteString(url.PathEscape(v))
		}
	}
	return sb.String()
}

// routeProxy forwards a route's requests to its upstream targets.
type routeProxy struct {
	name         string
	targets      []*url.URL
	next         atomic.Uint64
	tmpl         *pathTemplate
	preserveHost bool
	upgrades     []string // lower-case protocols clients may upgrade to
	timeout      time.Duration
	reqHeaders   headerRules
	reqHeaderMap map[string]string
	respHeaders  headerRules
	respValid    *responseValidator
	ips          *clientIPResolver
	logger       *slog.Logger
	rp           *httputil.ReverseProxy
}

func (p *routeProxy) init(transport http.RoundTripper, buffers httputil.BufferPool) {
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      timedTransport{transport},
		BufferPool:     buffers,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		ErrorLog:       slog.NewLogLogger(p.logger.Handler(), slog.LevelWarn),
	}
}

func (p *routeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}
	// An upgraded connection is a raw tunnel to the upstream. Without the
	// Upgrade header ReverseProxy forwards an ordinary request.
	if up := r.Header.Get("Upgrade"); up != "" && !p.upgradeAllowed(up) {
		r.Header.Del("Upgrade")
	}
	p.rp.ServeHTTP(&interimSuppressor{ResponseWriter: w, saved: w.Header().Clone()}, r)
}

// timedTransport records the upstream round trip time (until response
// headers, or until failure) in the access log. ReverseProxy calls RoundTrip
// on the request goroutine, so no synchronisation is needed.
type timedTransport struct{ http.RoundTripper }

func (t timedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.RoundTripper.RoundTrip(r)
	requestLogFrom(r.Context()).setUpstreamTime(time.Since(start))
	return resp, err
}

// interimSuppressor stops upstream 1xx interim responses (100 Continue, 103
// Early Hints) reaching the caller. ReverseProxy forwards their headers
// straight to the client, bypassing ModifyResponse and the header allowlist.
// After forwarding one, ReverseProxy clears the header map, so the gateway's
// own headers are restored on the next access.
type interimSuppressor struct {
	http.ResponseWriter
	saved   http.Header
	restore bool
}

func (w *interimSuppressor) Header() http.Header {
	h := w.ResponseWriter.Header()
	if w.restore {
		w.restore = false
		clear(h)
		for k, v := range w.saved {
			h[k] = v
		}
	}
	return h
}

func (w *interimSuppressor) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		w.restore = true
		return
	}
	w.Header()
	w.ResponseWriter.WriteHeader(code)
}

func (w *interimSuppressor) Write(b []byte) (int, error) {
	w.Header()
	return w.ResponseWriter.Write(b)
}

func (w *interimSuppressor) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// upgradeAllowed reports whether the route permits switching to proto.
func (p *routeProxy) upgradeAllowed(proto string) bool {
	return slices.Contains(p.upgrades, strings.ToLower(proto))
}

// errUpgradeRefused rejects a 101 the route did not opt into, in case an
// upstream switches protocols without having been asked to.
var errUpgradeRefused = errors.New("upstream switched protocols on a route that does not allow it")

func (p *routeProxy) pick() *url.URL {
	if len(p.targets) == 1 {
		return p.targets[0]
	}
	return p.targets[(p.next.Add(1)-1)%uint64(len(p.targets))]
}

func (p *routeProxy) rewrite(pr *httputil.ProxyRequest) {
	sourceHeaders := pr.Out.Header.Clone()
	if p.tmpl != nil {
		esc := p.tmpl.render(pr.In)
		dec, err := url.PathUnescape(esc)
		if err != nil {
			dec = esc
		}
		pr.Out.URL.Path, pr.Out.URL.RawPath = dec, esc
		if dec == esc {
			pr.Out.URL.RawPath = ""
		}
	}
	pr.SetURL(p.pick())
	if p.preserveHost {
		pr.Out.Host = pr.In.Host
	}
	// Rewrite strips inbound X-Forwarded-*; keep the chain only when the
	// immediate peer is a trusted proxy.
	if xff := pr.In.Header["X-Forwarded-For"]; len(xff) > 0 && p.peerTrusted(pr.In) {
		pr.Out.Header["X-Forwarded-For"] = xff
	}
	pr.SetXForwarded()
	if p.respValid != nil {
		// Let the transport negotiate and transparently decode gzip so the
		// body can be validated.
		pr.Out.Header.Del("Accept-Encoding")
	}
	for dest, source := range p.reqHeaderMap {
		values := sourceHeaders.Values(source)
		pr.Out.Header.Del(dest)
		for _, value := range values {
			pr.Out.Header.Add(dest, value)
		}
	}
	p.reqHeaders.apply(pr.Out.Header)
}

func (p *routeProxy) peerTrusted(r *http.Request) bool {
	if len(p.ips.trusted) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netipParse(host)
	return err == nil && p.ips.isTrusted(a)
}

// Upstream error statuses are never relayed verbatim: the status is mapped
// through the tables below and the upstream headers and body are discarded in
// favour of a gateway-authored problem response.

// upstreamStatusMap lists the upstream error statuses with an explicit
// external status. Anything absent falls back to upstreamClientErrorFallback
// (4xx) or upstreamServerErrorFallback (5xx).
var upstreamStatusMap = map[int]int{
	// Statuses a client needs in order to behave correctly.
	http.StatusConflict:            http.StatusConflict,
	http.StatusUnprocessableEntity: http.StatusUnprocessableEntity,
	// The gateway owns routing and authentication, so an upstream that
	// rejects the credentials or the path points at a gateway-to-upstream
	// fault the caller must not learn about.
	http.StatusUnauthorized:      http.StatusBadGateway,
	http.StatusForbidden:         http.StatusBadGateway,
	http.StatusNotFound:          http.StatusBadGateway,
	http.StatusProxyAuthRequired: http.StatusBadGateway,
	// Upstream throttling reflects aggregate load on the gateway's own
	// connection, not the caller's rate; the gateway's rate limiter is the
	// only source of 429s.
	http.StatusTooManyRequests: http.StatusBadGateway,
}

const (
	upstreamClientErrorFallback = http.StatusBadRequest
	upstreamServerErrorFallback = http.StatusBadGateway
)

// upstreamErrorDetails holds the only text sent for each external status.
var upstreamErrorDetails = map[int]string{
	http.StatusBadRequest:          "bad request",
	http.StatusConflict:            "request conflicts with the current state",
	http.StatusUnprocessableEntity: "request could not be processed",
	http.StatusBadGateway:          "bad gateway",
}

// mapUpstreamStatus returns the status exposed to the caller for an upstream
// error status.
func mapUpstreamStatus(status int) int {
	if mapped, ok := upstreamStatusMap[status]; ok {
		return mapped
	}
	if status >= 500 {
		return upstreamServerErrorFallback
	}
	return upstreamClientErrorFallback
}

// upstreamStatusError reports an upstream error status so errorHandler can
// replace the response.
type upstreamStatusError struct{ status int }

func (e *upstreamStatusError) Error() string {
	return fmt.Sprintf("upstream returned status %d", e.status)
}

func (p *routeProxy) modifyResponse(resp *http.Response) error {
	requestLogFrom(resp.Request.Context()).setUpstreamStatus(resp.StatusCode)
	if resp.StatusCode >= 400 {
		return &upstreamStatusError{status: resp.StatusCode}
	}
	if resp.StatusCode == http.StatusSwitchingProtocols && !p.upgradeAllowed(resp.Header.Get("Upgrade")) {
		return errUpgradeRefused
	}
	if p.respValid != nil {
		stripped, err := p.respValid.check(resp)
		if err != nil {
			return err
		}
		if stripped > 0 {
			ctx := resp.Request.Context()
			p.logger.DebugContext(ctx, "undeclared response properties stripped", "route", p.name,
				"request_id", RequestIDFrom(ctx), "count", stripped)
		}
	}
	dropped := p.respHeaders.filterUpstream(resp.Header, resp.StatusCode == http.StatusSwitchingProtocols)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Trailers bypass ModifyResponse: they are filled in once the body
		// is read, so filter them on Close, before ReverseProxy copies them.
		// A 101 body is the raw connection and must not be wrapped.
		dropped = append(dropped, p.respHeaders.filterUpstream(resp.Trailer, false)...)
		resp.Body = &trailerFilter{ReadCloser: resp.Body, resp: resp, rules: p.respHeaders}
	}
	if len(dropped) > 0 {
		ctx := resp.Request.Context()
		p.logger.DebugContext(ctx, "upstream response headers dropped", "route", p.name,
			"request_id", RequestIDFrom(ctx), "headers", dropped)
	}
	p.respHeaders.apply(resp.Header)
	return nil
}

// trailerFilter drops non-allowlisted trailers once the upstream body has
// been read and its trailers populated.
type trailerFilter struct {
	io.ReadCloser
	resp  *http.Response
	rules headerRules
}

func (t *trailerFilter) Close() error {
	err := t.ReadCloser.Close()
	t.rules.filterUpstream(t.resp.Trailer, false)
	return err
}

// errorHandler logs the real failure and answers through the same status
// mapping as upstream error responses, so the caller cannot tell the failure
// modes apart.
func (p *routeProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	var statusErr *upstreamStatusError
	var status int
	switch {
	case errors.Is(err, context.Canceled) && ctx.Err() == context.Canceled:
		// Client went away; nothing useful to send.
		return
	case errors.As(err, &statusErr):
		status = statusErr.status
		requestLogFrom(ctx).setUpstreamError(upstreamErrStatus)
		p.logger.WarnContext(ctx, "upstream error status", "route", p.name,
			"request_id", RequestIDFrom(ctx), "upstream_status", status)
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		requestLogFrom(ctx).setUpstreamError(upstreamErrTimeout)
		p.logger.WarnContext(ctx, "upstream timeout", "route", p.name,
			"request_id", RequestIDFrom(ctx), "error", err)
	case errors.Is(err, errResponseContract):
		status = http.StatusBadGateway
		requestLogFrom(ctx).setUpstreamError(upstreamErrContract)
		p.logger.ErrorContext(ctx, "upstream response rejected", "route", p.name,
			"request_id", RequestIDFrom(ctx), "error", err)
	default:
		status = http.StatusBadGateway
		requestLogFrom(ctx).setUpstreamError(upstreamErrUnreachable)
		p.logger.WarnContext(ctx, "upstream error", "route", p.name,
			"request_id", RequestIDFrom(ctx), "error", err)
	}
	p.writeUpstreamError(w, r, status)
}

// writeUpstreamError answers with the external status and detail mapped from
// an internal upstream status. Every upstream failure goes through here so
// the responses are identical whatever the cause.
func (p *routeProxy) writeUpstreamError(w http.ResponseWriter, r *http.Request, status int) {
	external := mapUpstreamStatus(status)
	p.respHeaders.apply(w.Header())
	WriteProblem(w, r, external, upstreamErrorDetails[external])
}
