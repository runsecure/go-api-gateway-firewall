package gateway

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// pathGuard rejects request paths that are ambiguous or commonly used to
// smuggle traversal past routing: dot segments, empty segments, backslashes,
// control characters and double-encoded sequences. It runs before routing so
// no route ever matches a path an upstream might interpret differently.
func pathGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reason := unsafePath(r.URL.Path)
		if reason == "" {
			reason = unsafeRawPath(r.URL.RawPath)
		}
		if reason != "" {
			WriteProblem(w, r, http.StatusBadRequest, reason)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func unsafePath(p string) string {
	if p == "" || p[0] != '/' {
		return "path must be absolute"
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f {
			return "control character in path"
		}
		if c == '\\' {
			return "backslash in path"
		}
	}
	if strings.Contains(p, "//") {
		return "empty path segment"
	}
	for seg := range strings.SplitSeq(p[1:], "/") {
		if seg == "." || seg == ".." {
			return "dot segment in path"
		}
	}
	// Path is already percent-decoded once; any remaining encoded dot, slash,
	// backslash or percent indicates double encoding.
	if i := strings.IndexByte(p, '%'); i >= 0 {
		l := strings.ToLower(p[i:])
		for _, s := range []string{"%2e", "%2f", "%5c", "%25", "%00"} {
			if strings.Contains(l, s) {
				return "double-encoded path"
			}
		}
	}
	return ""
}

// unsafeRawPath rejects percent-encoded unreserved characters (letters,
// digits, "-", ".", "_", "~"). RFC 3986 makes "%61" and "a" equivalent, and
// upstreams decode them, but routes are matched on the path as sent, so
// "/%61dmin" would miss a route for "/admin" and fall through to a broader
// one. raw is empty when the path was sent in canonical form.
func unsafeRawPath(raw string) string {
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		b, err := strconv.ParseUint(raw[i+1:i+3], 16, 8)
		if err != nil {
			continue
		}
		c := byte(b)
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			return "unnecessarily encoded character in path"
		}
		i += 2
	}
	return ""
}

// requestLimits enforces per-route size and shape limits.
type requestLimits struct {
	maxURL        int
	maxQuery      int
	maxBody       int64
	allowEncSlash bool
}

func (l *requestLimits) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.RequestURI) > l.maxURL {
			WriteProblem(w, r, http.StatusRequestURITooLong, "request URI too long")
			return
		}
		if !l.allowEncSlash {
			raw := strings.ToLower(r.URL.RawPath)
			if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
				WriteProblem(w, r, http.StatusBadRequest, "encoded slash in path")
				return
			}
		}
		if rq := r.URL.RawQuery; rq != "" {
			if strings.Count(rq, "&")+1 > l.maxQuery {
				WriteProblem(w, r, http.StatusBadRequest, "too many query parameters")
				return
			}
			if _, err := url.ParseQuery(rq); err != nil {
				WriteProblem(w, r, http.StatusBadRequest, "malformed query string")
				return
			}
		}
		if r.ContentLength > l.maxBody {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, l.maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

// headerRules applies set/remove rules to a header map, and for responses
// holds the allowlist of upstream headers.
type headerRules struct {
	set    [][2]string
	remove []string
	allow  map[string]bool
}

func compileHeaderRules(rules ...HeaderRules) headerRules {
	var hr headerRules
	for _, r := range rules {
		for _, h := range r.Remove {
			hr.remove = append(hr.remove, http.CanonicalHeaderKey(h))
		}
		for k, v := range r.Set {
			hr.set = append(hr.set, [2]string{http.CanonicalHeaderKey(k), v})
		}
		for _, h := range r.Allow {
			if hr.allow == nil {
				hr.allow = map[string]bool{}
			}
			hr.allow[http.CanonicalHeaderKey(h)] = true
		}
	}
	return hr
}

// filterUpstream deletes every header in h that is not allowlisted and
// returns the names removed. A 101 response also keeps the headers needed to
// complete the protocol switch.
func (hr headerRules) filterUpstream(h http.Header, switching bool) []string {
	var dropped []string
	for k := range h {
		ck := http.CanonicalHeaderKey(k)
		if hr.allow[ck] || (switching && switchingProtocolHeaders[ck]) {
			continue
		}
		delete(h, k)
		dropped = append(dropped, ck)
	}
	return dropped
}

func (hr headerRules) empty() bool { return len(hr.set) == 0 && len(hr.remove) == 0 }

func (hr headerRules) apply(h http.Header) {
	for _, k := range hr.remove {
		delete(h, k)
	}
	for _, kv := range hr.set {
		h.Set(kv[0], kv[1])
	}
}

// concurrencyLimit sheds load once max requests are in flight. A shed
// request is logged and answered exactly like any other upstream failure, so
// the caller cannot tell that the route is saturated.
func (p *routeProxy) concurrencyLimit(max int) func(http.Handler) http.Handler {
	sem := make(chan struct{}, max)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				ctx := r.Context()
				p.logger.WarnContext(ctx, "route at concurrency limit", "route", p.name,
					"request_id", RequestIDFrom(ctx), "max_concurrent", max)
				requestLogFrom(ctx).setUpstreamError(upstreamErrShed)
				p.writeUpstreamError(w, r, http.StatusServiceUnavailable)
			}
		})
	}
}

// defaultAllowedResponseHeaders are the upstream response headers forwarded
// to the caller on every route. Everything else an upstream sends is dropped
// unless a route or the defaults add it with responseHeaders.allow.
var defaultAllowedResponseHeaders = []string{
	"Content-Type",
	"Content-Length",
	"Content-Encoding",
	"Content-Language",
	"Cache-Control",
	"Expires",
	"ETag",
	"Last-Modified",
	"Vary",
	"Accept-Ranges",
	"Content-Range",
}

// switchingProtocolHeaders are kept on a 101 response so protocol upgrades
// (WebSocket) can complete on routes that allow them.
var switchingProtocolHeaders = map[string]bool{
	"Connection":               true,
	"Upgrade":                  true,
	"Sec-Websocket-Accept":     true,
	"Sec-Websocket-Protocol":   true,
	"Sec-Websocket-Extensions": true,
}

// defaultResponseHeaders hardens every response leaving the gateway.
var defaultResponseHeaders = HeaderRules{
	Allow: defaultAllowedResponseHeaders,
	Set: map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	},
	Remove: []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"},
}
