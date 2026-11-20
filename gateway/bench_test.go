package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type nopUpstream struct{}

func (nopUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}
	return &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), ContentLength: 11, Request: r,
	}, nil
}

// BenchmarkGateway measures gateway overhead with an in-memory upstream.
func BenchmarkGateway(b *testing.B) {
	cfg, err := ParseConfig([]byte(fmt.Sprintf(`
server: {accessLog: false}
defaults: {auth: [anonymous]}
routes:
  - name: create-order
    path: /api/orders
    methods: [POST]
    upstream: {targets: ["http://up"], path: /v1/orders}
    validation:
      body:
        schema:%s
  - name: get-order
    path: /api/orders/{id}
    methods: [GET]
    upstream: {targets: ["http://up"]}
`, orderSchema)), true)
	if err != nil {
		b.Fatal(err)
	}
	gw, err := New(cfg, WithLogger(quietLogger()), WithTransport(nopUpstream{}))
	if err != nil {
		b.Fatal(err)
	}
	run := func(b *testing.B, method, target, body string) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				var rb io.Reader
				if body != "" {
					rb = strings.NewReader(body)
				}
				req := httptest.NewRequest(method, target, rb)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				gw.ServeHTTP(rec, req)
				if rec.Code != 200 {
					b.Fatalf("status %d: %s", rec.Code, rec.Body)
				}
			}
		})
	}
	b.Run("GET passthrough", func(b *testing.B) { run(b, "GET", "/api/orders/42", "") })
	b.Run("POST validated", func(b *testing.B) {
		run(b, "POST", "/api/orders", `{"sku":"ABC-123","qty":3,"email":"a@b.example"}`)
	})
}
