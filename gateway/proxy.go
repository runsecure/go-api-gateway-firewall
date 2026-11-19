package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
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
	timeout      time.Duration
	reqHeaders   headerRules
	respHeaders  headerRules
	respValid    *responseValidator
	ips          *clientIPResolver
	logger       *slog.Logger
	rp           *httputil.ReverseProxy
}

func (p *routeProxy) init(transport http.RoundTripper, buffers httputil.BufferPool) {
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      transport,
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
	p.rp.ServeHTTP(w, r)
}

func (p *routeProxy) pick() *url.URL {
	if len(p.targets) == 1 {
		return p.targets[0]
	}
	return p.targets[(p.next.Add(1)-1)%uint64(len(p.targets))]
}

func (p *routeProxy) rewrite(pr *httputil.ProxyRequest) {
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

func (p *routeProxy) modifyResponse(resp *http.Response) error {
	if p.respValid != nil {
		if err := p.respValid.check(resp); err != nil {
			return err
		}
	}
	p.respHeaders.apply(resp.Header)
	return nil
}

func (p *routeProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	ctx := r.Context()
	switch {
	case errors.Is(err, context.Canceled) && ctx.Err() == context.Canceled:
		// Client went away; nothing useful to send.
		return
	case errors.Is(err, context.DeadlineExceeded):
		p.logger.WarnContext(ctx, "upstream timeout", "route", p.name, "request_id", RequestIDFrom(ctx))
		p.respHeaders.apply(w.Header())
		WriteProblem(w, r, http.StatusGatewayTimeout, "upstream timed out")
	case errors.Is(err, errResponseContract):
		p.logger.ErrorContext(ctx, "upstream response rejected", "route", p.name,
			"request_id", RequestIDFrom(ctx), "error", err)
		p.respHeaders.apply(w.Header())
		WriteProblem(w, r, http.StatusBadGateway, "upstream response failed contract validation")
	default:
		p.logger.WarnContext(ctx, "upstream error", "route", p.name,
			"request_id", RequestIDFrom(ctx), "error", err)
		p.respHeaders.apply(w.Header())
		WriteProblem(w, r, http.StatusBadGateway, "upstream unavailable")
	}
}
