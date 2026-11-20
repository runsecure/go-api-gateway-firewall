package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	clientIPKey
)

// RequestIDHeader carries the request ID to clients and upstreams.
const RequestIDHeader = "X-Request-Id"

// RequestIDFrom returns the request ID assigned by the gateway.
func RequestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey).(string)
	return s
}

// ClientIPFrom returns the resolved client IP.
func ClientIPFrom(ctx context.Context) string {
	s, _ := ctx.Value(clientIPKey).(string)
	return s
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// validRequestID accepts short, header-safe client IDs so they can be used
// for correlation without enabling log or header injection.
func validRequestID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// clientIPResolver determines the client address, honoring X-Forwarded-For
// only when the direct peer is a trusted proxy.
type clientIPResolver struct {
	trusted []netip.Prefix
}

func (c *clientIPResolver) isTrusted(a netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (c *clientIPResolver) resolve(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if len(c.trusted) == 0 || !c.isTrusted(peer) {
		return peer.String()
	}
	// Walk right-to-left, skipping trusted hops; the first untrusted address
	// is the client. Left-most entries are client-controlled and ignored.
	xff := r.Header.Values("X-Forwarded-For")
	for i := len(xff) - 1; i >= 0; i-- {
		parts := strings.Split(xff[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				return peer.String()
			}
			a = a.Unmap()
			if !c.isTrusted(a) {
				return a.String()
			}
			peer = a
		}
	}
	return peer.String()
}

type logFunc func(r *http.Request, msg string, args ...any)

// statusRecorder captures the response status and size for access logs.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach Flush and deadlines.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush supports streaming responses through the proxy.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// entryMiddleware assigns request ID and client IP, recovers panics and
// writes the access log.
func entryMiddleware(logger *slog.Logger, ips *clientIPResolver, accessLog bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			id := r.Header.Get(RequestIDHeader)
			if !validRequestID(id) {
				id = newRequestID()
			}
			r.Header.Set(RequestIDHeader, id)
			w.Header().Set(RequestIDHeader, id)
			ip := ips.resolve(r)
			ctx := context.WithValue(r.Context(), requestIDKey, id)
			ctx = context.WithValue(ctx, clientIPKey, ip)
			r = r.WithContext(ctx)

			rec := &statusRecorder{ResponseWriter: w}
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					logger.ErrorContext(ctx, "panic", "request_id", id, "panic", v)
					if rec.status == 0 {
						WriteProblem(rec, r, http.StatusInternalServerError, "")
					}
				}
				if accessLog {
					logger.LogAttrs(ctx, slog.LevelInfo, "request",
						slog.String("request_id", id),
						slog.String("client_ip", ip),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.Int("status", rec.status),
						slog.Int64("bytes", rec.bytes),
						slog.Duration("duration", time.Since(start)),
					)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

func netipParse(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	return a.Unmap(), err
}
