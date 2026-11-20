package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// echo is an upstream that reports what it received.
type echoed struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	RawPath string            `json:"rawPath"`
	Query   string            `json:"query"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
	Host    string            `json:"host"`
}

func newEcho(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e := echoed{Method: r.Method, Path: r.URL.Path, RawPath: r.URL.RawPath, Query: r.URL.RawQuery,
			Body: string(b), Headers: map[string]string{}, Host: r.Host}
		for k := range r.Header {
			e.Headers[k] = r.Header.Get(k)
		}
		w.Header().Set("Server", "upstream/1.0")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func quietLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func mustGateway(t *testing.T, yamlCfg string, opts ...Option) *Gateway {
	t.Helper()
	cfg, err := ParseConfig([]byte(yamlCfg), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg.BaseDir = t.TempDir()
	gw, err := New(cfg, append([]Option{WithLogger(quietLogger())}, opts...)...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return gw
}

func do(t *testing.T, h http.Handler, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rb)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeEcho(t *testing.T, rec *httptest.ResponseRecorder) echoed {
	t.Helper()
	var e echoed
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode echo (status %d): %v: %s", rec.Code, err, rec.Body.String())
	}
	return e
}

func TestRequestHeaderMap(t *testing.T) {
	var received http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
defaults: {auth: [anonymous]}
routes:
  - name: test
    path: /test
    methods: [GET]
    upstream: {targets: [%s]}
    requestHeaderMap: {X-Internal: X-External, X-Missing: X-Absent, X-Rule: X-External, X-Connection-Copy: X-Hop}
    requestHeaders: {set: {X-Rule: configured}}
`, up.URL))
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Add("x-external", "one")
	req.Header.Add("X-External", "two")
	req.Header.Set("X-Missing", "spoofed")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "secret")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d", rec.Code)
	}
	if got := received.Values("X-Internal"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("mapped values: %v", got)
	}
	if received.Get("X-Missing") != "" || received.Get("X-Connection-Copy") != "" {
		t.Fatalf("unexpected mapped headers: %v", received)
	}
	if received.Get("X-Rule") != "configured" {
		t.Fatalf("request header rule did not override mapping: %v", received)
	}
}

func TestRequestHeaderMapValidation(t *testing.T) {
	for _, mapping := range []map[string]string{
		{"Bad Header": "X-Source"}, {"X-Target": "bad source"},
		{"Connection": "X-Source"}, {"X-Forwarded-For": "X-Source"},
		{"X-Target": "A", "x-target": "B"}, {"X-User": "X-Source"},
	} {
		cfg := &Config{Routes: []RouteConfig{{Name: "test", Path: "/", Methods: []string{"GET"},
			Upstream:       UpstreamConfig{Targets: []string{"http://localhost"}},
			ForwardHeaders: map[string]string{"x-user": "subject"}, RequestHeaderMap: mapping}}}
		if err := cfg.Validate(); err == nil {
			t.Errorf("mapping %v accepted", mapping)
		}
	}
}

const orderSchema = `
          type: object
          additionalProperties: false
          required: [sku, qty]
          properties:
            sku: {type: string, pattern: "^[A-Z0-9-]{3,32}$"}
            qty: {type: integer, minimum: 1, maximum: 100}
            email: {type: string, format: email}`

func baseConfig(upstream string) string {
	return fmt.Sprintf(`
server:
  healthPath: /healthz
defaults:
  auth: [anonymous]
  hardening:
    maxBodyBytes: 1024
    maxJsonDepth: 8
routes:
  - name: create-order
    path: /api/orders
    methods: [POST]
    upstream:
      targets: [%[1]s]
      path: /v1/orders
    validation:
      body:
        schema:%[2]s
  - name: get-order
    path: /api/orders/{id}
    methods: [GET]
    upstream:
      targets: [%[1]s]
      path: /v1/orders/{id}
    validation:
      params:
        schema:
          type: object
          properties:
            id: {type: string, pattern: "^[0-9]+$"}
      query:
        schema:
          type: object
          additionalProperties: false
          properties:
            expand: {type: string, enum: [items, customer]}
  - name: files
    path: /files/*
    methods: [GET]
    upstream:
      targets: [%[1]s]
      path: /storage/{*}
`, upstream, orderSchema)
}

func TestProxyAndBodyValidation(t *testing.T) {
	up := newEcho(t)
	gw := mustGateway(t, baseConfig(up.URL))

	rec := do(t, gw, "POST", "/api/orders?x=1", `{"sku":"ABC-1","qty":2}`, nil)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	e := decodeEcho(t, rec)
	if e.Path != "/v1/orders" || e.Query != "x=1" || e.Body != `{"sku":"ABC-1","qty":2}` {
		t.Fatalf("unexpected upstream request: %+v", e)
	}
	if e.Headers["X-Request-Id"] == "" || e.Headers["X-Forwarded-For"] == "" {
		t.Fatalf("missing forwarded headers: %+v", e.Headers)
	}
	if rec.Header().Get("Server") != "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("response headers not hardened: %v", rec.Header())
	}

	cases := []struct {
		name, body string
		ct         string
		want       int
	}{
		{"schema violation", `{"sku":"abc","qty":0}`, "application/json", 400},
		{"extra property", `{"sku":"ABC-1","qty":2,"admin":true}`, "application/json", 400},
		{"bad format", `{"sku":"ABC-1","qty":2,"email":"nope"}`, "application/json", 400},
		{"malformed", `{"sku":`, "application/json", 400},
		{"trailing data", `{"sku":"ABC-1","qty":2}{}`, "application/json", 400},
		{"duplicate key", `{"sku":"ABC-1","qty":2,"qty":500}`, "application/json", 400},
		{"too deep", `{"sku":"ABC-1","qty":2,"a":[[[[[[[[[1]]]]]]]]]}`, "application/json", 400},
		{"invalid utf8", "{\"sku\":\"AB\xffC\",\"qty\":2}", "application/json", 400},
		{"wrong content type", `{"sku":"ABC-1","qty":2}`, "text/plain", 415},
		{"wrong charset", `{"sku":"ABC-1","qty":2}`, "application/json; charset=latin1", 415},
		{"too large", `{"sku":"` + strings.Repeat("A", 2000) + `","qty":2}`, "application/json", 413},
		{"vendor json", `{"sku":"ABC-1","qty":2}`, "application/vnd.api+json", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, gw, "POST", "/api/orders", c.body, map[string]string{"Content-Type": c.ct})
			if rec.Code != c.want {
				t.Fatalf("got %d want %d: %s", rec.Code, c.want, rec.Body)
			}
			if c.want >= 400 && rec.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("expected problem+json, got %q", rec.Header().Get("Content-Type"))
			}
		})
	}

	rec = do(t, gw, "POST", "/api/orders", "", nil)
	if rec.Code != 400 {
		t.Fatalf("empty body: got %d", rec.Code)
	}
}

func TestValidationErrorDetails(t *testing.T) {
	gw := mustGateway(t, baseConfig(newEcho(t).URL))
	rec := do(t, gw, "POST", "/api/orders", `{"sku":"ABC-1","qty":0}`, nil)
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Errors) == 0 || p.Errors[0].Location != "/qty" || p.Errors[0].In != "body" || p.RequestID == "" {
		t.Fatalf("unexpected problem: %+v", p)
	}
}

func TestParamsQueryAndPathRewrite(t *testing.T) {
	gw := mustGateway(t, baseConfig(newEcho(t).URL))

	rec := do(t, gw, "GET", "/api/orders/42?expand=items", "", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if e := decodeEcho(t, rec); e.Path != "/v1/orders/42" {
		t.Fatalf("path %q", e.Path)
	}
	for target, want := range map[string]int{
		"/api/orders/abc":              400, // param pattern
		"/api/orders/42?expand=nope":   400, // enum
		"/api/orders/42?unknown=1":     400, // additionalProperties
		"/api/orders/42?a=1;b=2":       400, // malformed query
		"/api/orders/42/../../admin":   400, // traversal (path guard)
		"/api/orders/%2e%2e/admin":     400,
		"/api/orders/42%2fadmin":       400, // encoded slash
		"/api/orders/%252e%252e/admin": 400, // double encoding
		"/nope":                        404,
	} {
		if rec := do(t, gw, "GET", target, "", nil); rec.Code != want {
			t.Errorf("%s: got %d want %d: %s", target, rec.Code, want, rec.Body)
		}
	}
	if rec := do(t, gw, "DELETE", "/api/orders/42", "", nil); rec.Code != 405 {
		t.Errorf("method not allowed: got %d", rec.Code)
	}

	rec = do(t, gw, "GET", "/files/a/b%20c.txt", "", nil)
	if e := decodeEcho(t, rec); e.Path != "/storage/a/b c.txt" {
		t.Fatalf("wildcard path %q", e.Path)
	}
	if rec := do(t, gw, "GET", "/healthz", "", nil); rec.Code != 200 {
		t.Fatalf("health %d", rec.Code)
	}
}

func TestAPIKeyAuthAndIdentityForwarding(t *testing.T) {
	t.Setenv("TEST_PARTNER_KEY", "partner-key-0123456789")
	up := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  partners:
    type: apikey
    options:
      keys: {acme: "env:TEST_PARTNER_KEY"}
      scopes: {acme: [orders:read]}
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [partners]
    requiredScopes: [orders:read]
    forwardIdentity: {X-Client-Id: subject}
    upstream: {targets: [%s]}
  - name: admin
    path: /admin
    methods: [GET]
    auth: [partners]
    requiredScopes: [admin]
    upstream: {targets: [%[1]s]}
`, up.URL))

	if rec := do(t, gw, "GET", "/r", "", nil); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no key: %d", rec.Code)
	}
	if rec := do(t, gw, "GET", "/r", "", map[string]string{"X-API-Key": "wrong-key-0123456789"}); rec.Code != 401 {
		t.Fatalf("bad key: %d", rec.Code)
	}
	rec := do(t, gw, "GET", "/r", "", map[string]string{"X-API-Key": "partner-key-0123456789", "X-Client-Id": "spoofed"})
	if rec.Code != 200 {
		t.Fatalf("good key: %d %s", rec.Code, rec.Body)
	}
	e := decodeEcho(t, rec)
	if e.Headers["X-Client-Id"] != "acme" || e.Headers["X-Api-Key"] != "" {
		t.Fatalf("identity forwarding wrong: %+v", e.Headers)
	}
	if rec := do(t, gw, "GET", "/admin", "", map[string]string{"X-API-Key": "partner-key-0123456789"}); rec.Code != 403 {
		t.Fatalf("scope: %d", rec.Code)
	}
}

func signHS256(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	cb, _ := json.Marshal(claims)
	in := h + "." + enc.EncodeToString(cb)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(in))
	return in + "." + enc.EncodeToString(m.Sum(nil))
}

func TestJWTAuth(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	t.Setenv("TEST_JWT_SECRET", secret)
	up := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  jwt:
    type: jwt
    options:
      algorithms: [HS256]
      secret: env:TEST_JWT_SECRET
      issuer: https://issuer.example
      audience: [gateway]
defaults:
  auth: [jwt]
routes:
  - name: r
    path: /r
    methods: [GET]
    requiredScopes: [read]
    forwardIdentity: {X-User: subject, X-Tenant: claims.tenant}
    upstream: {targets: [%s]}
`, up.URL))

	now := time.Now().Unix()
	good := map[string]any{"sub": "u1", "iss": "https://issuer.example", "aud": "gateway",
		"exp": now + 60, "scope": "read write", "tenant": "t9"}
	bearer := func(c map[string]any) map[string]string {
		return map[string]string{"Authorization": "Bearer " + signHS256(t, secret, c)}
	}
	rec := do(t, gw, "GET", "/r", "", bearer(good))
	if rec.Code != 200 {
		t.Fatalf("valid token: %d %s", rec.Code, rec.Body)
	}
	if e := decodeEcho(t, rec); e.Headers["X-User"] != "u1" || e.Headers["X-Tenant"] != "t9" {
		t.Fatalf("forwarded: %+v", e.Headers)
	}

	mut := func(k string, v any) map[string]any {
		c := map[string]any{}
		for kk, vv := range good {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	for name, hdr := range map[string]map[string]string{
		"expired":   bearer(mut("exp", now-10)),
		"no exp":    bearer(mut("exp", nil)),
		"bad iss":   bearer(mut("iss", "evil")),
		"bad aud":   bearer(mut("aud", "other")),
		"future":    bearer(mut("nbf", now+3600)),
		"wrong key": {"Authorization": "Bearer " + signHS256(t, strings.Repeat("x", 32), good)},
		"alg none": {"Authorization": "Bearer " + base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) +
			"." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x","exp":9999999999}`)) + "."},
		"garbage": {"Authorization": "Bearer abc"},
	} {
		if rec := do(t, gw, "GET", "/r", "", hdr); rec.Code != 401 {
			t.Errorf("%s: got %d", name, rec.Code)
		}
	}
	if rec := do(t, gw, "GET", "/r", "", bearer(mut("scope", "write"))); rec.Code != 403 {
		t.Errorf("missing scope: got %d", rec.Code)
	}
}

func TestCustomAuthenticatorAndMiddleware(t *testing.T) {
	up := newEcho(t)
	var hookRan bool
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  hdr:
    type: header-token
    options: {"token": "letmein"}
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [hdr]
    middleware: [tag]
    upstream: {targets: [%s]}
`, up.URL),
		WithAuthenticatorType("header-token", func(name string, raw json.RawMessage) (Authenticator, error) {
			var o struct{ Token string }
			if err := json.Unmarshal(raw, &o); err != nil {
				return nil, err
			}
			return AuthenticatorFunc(func(r *http.Request) (*Principal, error) {
				if r.Header.Get("X-Token") != o.Token {
					return nil, ErrNoCredentials
				}
				return &Principal{Subject: "svc"}, nil
			}), nil
		}),
		WithNamedMiddleware("tag", func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hookRan = PrincipalFrom(r.Context()) != nil
				r.Header.Set("X-Tag", "1")
				next.ServeHTTP(w, r)
			})
		}),
	)
	rec := do(t, gw, "GET", "/r", "", map[string]string{"X-Token": "letmein"})
	if rec.Code != 200 || !hookRan || decodeEcho(t, rec).Headers["X-Tag"] != "1" {
		t.Fatalf("custom auth/middleware: %d hook=%v", rec.Code, hookRan)
	}
	if rec := do(t, gw, "GET", "/r", "", nil); rec.Code != 401 {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
}

func TestRateLimitAndConcurrency(t *testing.T) {
	up := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [anonymous]
    hardening:
      rateLimit: {requestsPerSecond: 1, burst: 2}
    upstream: {targets: [%s]}
`, up.URL))
	codes := []int{}
	for range 3 {
		codes = append(codes, do(t, gw, "GET", "/r", "", nil).Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("rate limit codes %v", codes)
	}
}

func TestConcurrencyLimitIsIndistinguishable(t *testing.T) {
	logs := &logCapture{}
	entered, release := make(chan struct{}), make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		entered <- struct{}{}
		<-release
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
routes:
  - name: r
    path: /{p}
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s], maxConcurrent: 1}
`, up.URL), WithLogger(slog.New(slog.NewJSONHandler(logs, nil))))

	done := make(chan struct{})
	go func() {
		defer close(done)
		do(t, gw, "GET", "/hold", "", nil)
	}()
	<-entered
	shed := do(t, gw, "GET", "/hold", "", nil)
	close(release)
	<-done
	failed := do(t, gw, "GET", "/fail", "", nil)

	if shed.Code != 502 || shed.Header().Get("Retry-After") != "" {
		t.Fatalf("shed request: %d retry-after=%q %s", shed.Code, shed.Header().Get("Retry-After"), shed.Body)
	}
	if line := logs.accessLine(t, shed.Header().Get(RequestIDHeader)); line["upstream_error"] != "concurrency_limit" {
		t.Errorf("shed access log: %v", line)
	}
	strip := func(rec *httptest.ResponseRecorder) (Problem, http.Header) {
		var p Problem
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		p.RequestID = ""
		h := rec.Header().Clone()
		h.Del("X-Request-Id")
		return p, h
	}
	sp, sh := strip(shed)
	fp, fh := strip(failed)
	if fmt.Sprint(sp) != fmt.Sprint(fp) || fmt.Sprint(sh) != fmt.Sprint(fh) {
		t.Fatalf("shed and upstream-failure responses differ:\n%v %v\n%v %v", sp, sh, fp, fh)
	}
}

func TestResponseValidation(t *testing.T) {
	var body string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%[1]s]}
    validation:
      response:
        schema:
          type: object
          required: [id]
          additionalProperties: false
          properties: {id: {type: integer}}
  - name: nested
    path: /nested
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%[1]s]}
    validation:
      response:
        schema:
          $defs:
            item:
              type: object
              properties: {sku: {type: string}}
          type: object
          required: [id, kind]
          properties:
            id: {type: integer}
            owner:
              type: object
              properties: {name: {type: string}}
            items:
              type: array
              items: {$ref: "#/$defs/item"}
            meta: {type: object}
            labels:
              type: object
              additionalProperties: {type: string}
          patternProperties:
            "^x-": {type: string}
          allOf:
            - properties: {total: {type: number}}
`, up.URL))

	cases := []struct {
		name, path, upstream, want string
		code                       int
	}{
		{"conforming body is forwarded byte for byte", "/r", `{ "id": 1 }`, `{ "id": 1 }`, 200},
		{"undeclared property is stripped", "/r", `{"id":1,"passwordHash":"leak"}`, `{"id":1}`, 200},
		{"missing required property is rejected", "/r", `{"passwordHash":"leak"}`, "", 502},
		{"wrong type is rejected", "/r", `{"id":"1","passwordHash":"leak"}`, "", 502},
		{"non-object is rejected", "/r", `["leak"]`, "", 502},
		{"nested objects, arrays, refs, patterns and allOf",
			"/nested",
			`{"id":1,"kind":"k","secret":"leak","total":2.50,"x-trace":"t","y-trace":"leak",
			  "owner":{"name":"a","ssn":"leak"},
			  "items":[{"sku":"s","cost":"leak"},{"sku":"t"}],
			  "meta":{"anything":{"goes":true}},
			  "labels":{"a":"<b>"}}`,
			`{"id":1,"items":[{"sku":"s"},{"sku":"t"}],"kind":"k","labels":{"a":"<b>"},` +
				`"meta":{"anything":{"goes":true}},"owner":{"name":"a"},"total":2.50,"x-trace":"t"}`,
			200},
	}
	for _, tc := range cases {
		body = tc.upstream
		rec := do(t, gw, "GET", tc.path, "", nil)
		if rec.Code != tc.code || strings.Contains(rec.Body.String(), "leak") {
			t.Errorf("%s: %d %s", tc.name, rec.Code, rec.Body)
			continue
		}
		switch {
		case tc.code == 200 && rec.Body.String() != tc.want:
			t.Errorf("%s: got %s, want %s", tc.name, rec.Body, tc.want)
		case tc.code == 200 && rec.Header().Get("Content-Length") != fmt.Sprint(len(tc.want)):
			t.Errorf("%s: content-length %q", tc.name, rec.Header().Get("Content-Length"))
		case tc.code != 200 && !strings.Contains(rec.Body.String(), `"detail":"bad gateway"`):
			t.Errorf("%s: unexpected error body %s", tc.name, rec.Body)
		}
	}
}

func TestUpstreamFailures(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	gw := mustGateway(t, fmt.Sprintf(`
routes:
  - name: slow
    path: /slow
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s], timeout: 50ms}
  - name: down
    path: /down
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: ["http://127.0.0.1:1"]}
`, slow.URL))
	// Timeouts and connection failures are indistinguishable to the caller.
	for _, path := range []string{"/slow", "/down"} {
		rec := do(t, gw, "GET", path, "", nil)
		var p Problem
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if rec.Code != 502 || p.Detail != "bad gateway" {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestUpstreamErrorStatusMapping(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var code int
		_, _ = fmt.Sscanf(r.URL.Path, "/s/%d", &code)
		w.Header().Set("Server", "upstream/1.0")
		w.Header().Set("WWW-Authenticate", `Basic realm="internal"`)
		w.Header().Set("Retry-After", "17")
		w.Header().Set("Set-Cookie", "session=secret")
		w.Header().Set("X-Internal-Host", "db-7.internal")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, "stack trace: secret-internal-detail")
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
routes:
  - name: s
    path: /s/{code}
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s]}
`, up.URL))

	want := map[int]int{
		200: 200, 204: 204,
		400: 400, 401: 502, 402: 400, 403: 502, 404: 502, 405: 400, 407: 502,
		409: 409, 410: 400, 413: 400, 415: 400, 418: 400, 422: 422, 429: 502, 431: 400,
		500: 502, 501: 502, 502: 502, 503: 502, 504: 502, 599: 502,
	}
	for upstream, external := range want {
		rec := do(t, gw, "GET", fmt.Sprintf("/s/%d", upstream), "", nil)
		if rec.Code != external {
			t.Errorf("upstream %d: got %d, want %d", upstream, rec.Code, external)
		}
		if upstream < 400 {
			continue
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("upstream %d: body leaked: %s", upstream, rec.Body)
		}
		for _, h := range []string{"Server", "Www-Authenticate", "Retry-After", "Set-Cookie", "X-Internal-Host"} {
			if v := rec.Header().Get(h); v != "" {
				t.Errorf("upstream %d: header %s leaked: %q", upstream, h, v)
			}
		}
		var p Problem
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("upstream %d: not a problem body: %s", upstream, rec.Body)
		}
		if p.Status != external || p.Detail != upstreamErrorDetails[external] || p.Detail == "" {
			t.Errorf("upstream %d: problem %+v", upstream, p)
		}
	}
}

func TestResponseHeaderAllowlist(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if r.URL.Path == "/hints" {
			h.Set("Link", "<http://db-7.internal/x>; rel=preload")
			h.Set("X-Internal-Host", "db-7.internal")
			w.WriteHeader(http.StatusEarlyHints)
		}
		h.Set("Content-Type", "application/json")
		h.Set("ETag", `"v1"`)
		h.Set("Cache-Control", "max-age=5")
		h.Set("Set-Cookie", "session=secret")
		h.Set("Via", "1.1 internal-lb")
		h.Set("X-Backend-Server", "db-7.internal")
		h.Set("Server-Timing", "db;dur=53")
		h.Set("Location", "http://db-7.internal/orders/1")
		h.Set("X-Frame-Options", "ALLOWALL")
		h.Set("X-Route-Allowed", "yes")
		h.Set("X-Default-Allowed", "yes")
		h.Set("Trailer", "X-Checksum, X-Trace-Host")
		_, _ = io.WriteString(w, `{}`)
		h.Set("X-Checksum", "abc")
		h.Set("X-Trace-Host", "db-7.internal")
		h.Set(http.TrailerPrefix+"X-Unannounced", "db-7.internal")
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
defaults:
  responseHeaders:
    allow: [X-Default-Allowed]
routes:
  - name: r
    path: /{p}
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s]}
    responseHeaders:
      allow: [x-route-allowed, X-Checksum]
      set: {X-Route-Set: "1"}
`, up.URL))
	front := httptest.NewServer(gw)
	defer front.Close()

	for _, path := range []string{"/plain", "/hints"} {
		var interim []int
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
			Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
				interim = append(interim, code)
				return nil
			},
		})
		req, _ := http.NewRequestWithContext(ctx, "GET", front.URL+path, nil)
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode != 200 || string(body) != "{}" {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		if len(interim) > 0 {
			t.Errorf("%s: interim responses forwarded: %v", path, interim)
		}
		want := map[string]string{
			"Content-Type":      "application/json",
			"Etag":              `"v1"`,
			"Cache-Control":     "max-age=5",
			"X-Route-Allowed":   "yes",
			"X-Default-Allowed": "yes",
			"X-Route-Set":       "1",
			"X-Frame-Options":   "DENY",
			"X-Request-Id":      resp.Header.Get("X-Request-Id"),
		}
		if want["X-Request-Id"] == "" {
			t.Errorf("%s: gateway request ID lost", path)
		}
		for k, v := range want {
			if got := resp.Header.Get(k); got != v {
				t.Errorf("%s: header %s = %q, want %q", path, k, got, v)
			}
		}
		for _, k := range []string{"Set-Cookie", "Via", "X-Backend-Server", "Server-Timing", "Location", "Link", "X-Internal-Host"} {
			if v := resp.Header.Get(k); v != "" {
				t.Errorf("%s: header %s leaked: %q", path, k, v)
			}
		}
		if got := resp.Trailer.Get("X-Checksum"); got != "abc" {
			t.Errorf("%s: allowed trailer X-Checksum = %q", path, got)
		}
		for k, v := range resp.Trailer {
			if strings.Contains(strings.Join(v, ""), "internal") {
				t.Errorf("%s: trailer %s leaked: %q", path, k, v)
			}
		}
	}
}

// logCapture collects JSON log records written by the gateway.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}

// accessLine returns the access-log record for requestID.
func (c *logCapture) accessLine(t *testing.T, requestID string) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range bytes.Split(c.buf.Bytes(), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil && m["msg"] == "request" && m["request_id"] == requestID {
			return m
		}
	}
	t.Fatalf("no access log for request %s in:\n%s", requestID, c.buf.String())
	return nil
}

func TestAccessLogFields(t *testing.T) {
	t.Setenv("TEST_PARTNER_KEY", "partner-key-0123456789")
	entered := make(chan struct{}, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(http.StatusInternalServerError)
		case "/slow", "/hang":
			entered <- struct{}{}
			select {
			case <-time.After(time.Second):
			case <-r.Context().Done():
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":1}`)
		}
	}))
	defer up.Close()
	logs := &logCapture{}
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  partners:
    type: apikey
    options:
      keys: {acme: "env:TEST_PARTNER_KEY"}
      scopes: {acme: [orders:read]}
routes:
  - name: orders
    path: /{p}
    methods: [GET]
    auth: [partners]
    upstream: {targets: [%[1]s], timeout: 50ms}
  - name: admin
    path: /admin/x
    methods: [GET]
    auth: [partners]
    requiredScopes: [admin]
    upstream: {targets: [%[1]s]}
  - name: contract
    path: /contract/x
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%[1]s]}
    validation:
      response:
        schema: {type: object, required: [name]}
  - name: down
    path: /down/x
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: ["http://127.0.0.1:1"]}
`, up.URL), WithLogger(slog.New(slog.NewJSONHandler(logs, nil))))
	key := map[string]string{"X-API-Key": "partner-key-0123456789"}

	type want struct {
		status         int
		route          string
		principal      string
		upstreamStatus int
		upstreamError  string
	}
	cases := map[string]struct {
		path string
		hdr  map[string]string
		want want
	}{
		"success":        {"/ok", key, want{200, "orders", "acme", 200, ""}},
		"upstream 500":   {"/fail", key, want{502, "orders", "acme", 500, "status"}},
		"timeout":        {"/slow", key, want{502, "orders", "acme", 0, "timeout"}},
		"contract":       {"/contract/x", nil, want{502, "contract", "", 200, "contract"}},
		"unreachable":    {"/down/x", nil, want{502, "down", "", 0, "unreachable"}},
		"missing scope":  {"/admin/x", key, want{403, "admin", "acme", 0, ""}},
		"no credentials": {"/ok", nil, want{401, "orders", "", 0, ""}},
		"no route":       {"/a/b/c", nil, want{404, "", "", 0, ""}},
	}
	check := func(name string, line map[string]any, w want) {
		t.Helper()
		num := func(k string) int { f, _ := line[k].(float64); return int(f) }
		str := func(k string) string { s, _ := line[k].(string); return s }
		if num("status") != w.status || str("route") != w.route || str("principal") != w.principal ||
			num("upstream_status") != w.upstreamStatus || str("upstream_error") != w.upstreamError {
			t.Errorf("%s: access log %v, want %+v", name, line, w)
		}
		if w.principal != "" && str("authenticator") != "partners" {
			t.Errorf("%s: authenticator %q", name, str("authenticator"))
		}
	}
	for name, tc := range cases {
		rec := do(t, gw, "GET", tc.path, "", tc.hdr)
		select {
		case <-entered:
		default:
		}
		if rec.Code != tc.want.status {
			t.Errorf("%s: response %d, want %d", name, rec.Code, tc.want.status)
		}
		check(name, logs.accessLine(t, rec.Header().Get(RequestIDHeader)), tc.want)
	}

	// Client disconnects while the upstream is still working.
	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequestWithContext(ctx, "GET", "/hang", nil)
	req.Header.Set("X-API-Key", key["X-API-Key"])
	req.Header.Set(RequestIDHeader, "client-gone")
	rec := httptest.NewRecorder()
	go func() { <-entered; cancel() }()
	gw.ServeHTTP(rec, req)
	check("client disconnect", logs.accessLine(t, "client-gone"),
		want{StatusClientClosedRequest, "orders", "acme", 0, ""})
}

func TestAccessLogHeaders(t *testing.T) {
	up := newEcho(t)
	logs := &logCapture{}
	gw := mustGateway(t, fmt.Sprintf(`
server:
  logHeaders: [x-true-ip, Traceparent, X-Correlation-Id, X-Request-Id, X-Absent]
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s]}
`, up.URL), WithLogger(slog.New(slog.NewJSONHandler(logs, nil))))

	req := httptest.NewRequest("GET", "/r", nil)
	req.Header.Set("X-True-Ip", "198.51.100.9")
	req.Header.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Add("X-Correlation-Id", "a")
	req.Header.Add("X-Correlation-Id", "b")
	req.Header.Set("X-Request-Id", strings.Repeat("z", 300)) // invalid, so the gateway replaces it
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	line := logs.accessLine(t, rec.Header().Get(RequestIDHeader))
	got, _ := line["headers"].(map[string]any)
	want := map[string]any{
		"x-true-ip":        "198.51.100.9",
		"traceparent":      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"x-correlation-id": "a, b",
		// Logged as received and truncated, not the ID the gateway assigned.
		"x-request-id": strings.Repeat("z", maxLoggedHeaderLength),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("headers = %v, want %v", got, want)
	}
	if strings.Contains(fmt.Sprint(line), "secret") {
		t.Fatalf("unconfigured header logged: %v", line)
	}

	// No configured header present: no "headers" group at all.
	rec = do(t, gw, "GET", "/r", "", nil)
	if line := logs.accessLine(t, rec.Header().Get(RequestIDHeader)); line["headers"] != nil {
		t.Fatalf("empty headers group logged: %v", line)
	}
}

func TestConfigErrors(t *testing.T) {
	bad := map[string]string{
		"unknown field":      "routes: []\nbogus: 1",
		"no routes":          "routes: []",
		"bad target":         "routes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [ftp://x]}}]",
		"unknown auth":       "routes: [{name: a, path: /a, methods: [GET], auth: [nope], upstream: {targets: [http://x]}}]",
		"bad schema":         "routes: [{name: a, path: /a, methods: [POST], auth: [anonymous], upstream: {targets: [http://x]}, validation: {body: {schema: {type: 5}}}}]",
		"unknown param":      "routes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x], path: /b/{id}}}]",
		"duplicate route":    "routes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}, {name: b, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"bad pattern":        "routes: [{name: a, path: '/a/*/b', methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"bad duration":       "defaults: {timeout: 5}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log authorization":  "server: {logHeaders: [authorization]}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log cookie":         "server: {logHeaders: [Cookie]}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log default apikey": "server: {logHeaders: [x-api-key]}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log custom apikey":  "server: {logHeaders: [X-Partner-Key]}\nauthenticators: {p: {type: apikey, options: {header: x-partner-key, keys: {a: k}}}}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log custom jwt":     "server: {logHeaders: [X-Token]}\nauthenticators: {j: {type: jwt, options: {header: X-Token}}}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"log bad name":       "server: {logHeaders: ['a b']}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
		"request allow":      "routes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}, requestHeaders: {allow: [X-A]}}]",
		"bad allow name":     "routes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}, responseHeaders: {allow: ['bad header']}}]",
		"bad default allow":  "defaults: {responseHeaders: {allow: ['a:b']}}\nroutes: [{name: a, path: /a, methods: [GET], auth: [anonymous], upstream: {targets: [http://x]}}]",
	}
	for name, y := range bad {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfig([]byte(y), true)
			if err == nil {
				_, err = New(cfg, WithLogger(quietLogger()))
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestClientIPResolution(t *testing.T) {
	r := &clientIPResolver{}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.1.1:1234"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9, 10.2.2.2")
	if got := r.resolve(req); got != "10.1.1.1" {
		t.Fatalf("untrusted: %s", got)
	}
	r.trusted = append(r.trusted, netip.MustParsePrefix("10.0.0.0/8"))
	if got := r.resolve(req); got != "203.0.113.9" {
		t.Fatalf("trusted: %s", got)
	}
}
