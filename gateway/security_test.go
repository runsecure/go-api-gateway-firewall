package gateway

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testAPIKey = "0123456789abcdef-secret"

// rawRequest sends req verbatim over a new connection and returns everything
// the server writes back. It is used where the Go client would normalise or
// refuse the request under test.
func rawRequest(t *testing.T, srv *httptest.Server, req string) string {
	t.Helper()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, req)
	b, _ := io.ReadAll(c)
	return string(b)
}

func statusLine(resp string) string {
	line, _, _ := strings.Cut(resp, "\r\n")
	return line
}

// A percent-encoded, mixed-case or ;parameter variant of a protected path
// must not reach the upstream through a broader, less protected route.
func TestEncodedPathCannotSidestepRoute(t *testing.T) {
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  k: {type: apikey, options: {keys: {alice: %s}}}
routes:
  - name: admin
    path: /api/admin/*
    methods: [GET]
    auth: [k]
    upstream: {targets: [%s]}
  - name: open
    path: /api/*
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s]}
`, testAPIKey, up.URL, up.URL))

	for target, want := range map[string]int{
		"/api/admin/secret":       401,
		"/api/%61dmin/secret":     400,
		"/api/%41dmin/secret":     400,
		"/api/adm%69n/secret":     400,
		"/api/admin%2Dx/secret":   400, // every unreserved class: - . _ ~
		"/api/a%2Eb/secret":       400,
		"/api/a%5Fb/secret":       400,
		"/api/a%7eb/secret":       400,
		"/api/%61dmin%2Fsecret":   400,
		"/api/public/a%20b":       200, // escapes that are required still pass
		"/api/public/a%40b":       200,
		"/api/public/caf%C3%A9":   200,
		"/api/public/plain":       200,
		"/api/public/100%25/done": 200,
	} {
		if rec := do(t, gw, "GET", target, "", nil); rec.Code != want {
			t.Errorf("%s: got %d want %d: %s", target, rec.Code, want, rec.Body)
		}
	}
	for _, p := range seen {
		if strings.HasPrefix(strings.ToLower(p), "/api/admin") {
			t.Errorf("upstream reached with protected path %q", p)
		}
	}
}

// Params schemas see the decoded value, which is what the upstream receives.
func TestParamsValidatedAfterDecoding(t *testing.T) {
	echo := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
defaults: {auth: [anonymous]}
routes:
  - name: user
    path: /users/{id}
    methods: [GET]
    upstream: {targets: [%s]}
    validation:
      params:
        schema:
          type: object
          properties:
            id: {type: string, maxLength: 5, not: {enum: ["a@b"]}}
`, echo.URL))

	if rec := do(t, gw, "GET", "/users/a%40b", "", nil); rec.Code != 400 {
		t.Errorf("denied value in escaped form: got %d: %s", rec.Code, rec.Body)
	}
	// Five characters once decoded; nine while escaped.
	rec := do(t, gw, "GET", "/users/a%40b%40c", "", nil)
	if rec.Code != 200 {
		t.Fatalf("decoded length: got %d: %s", rec.Code, rec.Body)
	}
	if e := decodeEcho(t, rec); e.Path != "/users/a@b@c" {
		t.Errorf("upstream path %q", e.Path)
	}
}

// Headers the gateway injects survive a client naming them in Connection.
func TestConnectionHeaderCannotStripInjectedHeaders(t *testing.T) {
	echo := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  k: {type: apikey, options: {keys: {alice: %s}}}
routes:
  - name: a
    path: /a
    methods: [GET]
    auth: [k]
    forwardIdentity: {X-User-Id: subject, X-Auth: authenticator}
    requestHeaders: {set: {X-Static: configured}}
    upstream: {targets: [%s]}
`, testAPIKey, echo.URL))
	srv := httptest.NewServer(gw)
	defer srv.Close()

	for _, conn := range []string{
		"close, X-User-Id, X-Auth, X-Request-Id, X-Static",
		"x-user-id,x-auth ,  x-request-id",
	} {
		resp := rawRequest(t, srv, "GET /a HTTP/1.1\r\nHost: x\r\nX-API-Key: "+testAPIKey+
			"\r\nX-Request-Id: client-id\r\nX-Hop: secret\r\nConnection: "+conn+", X-Hop\r\n\r\n"+
			"GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		if statusLine(resp) != "HTTP/1.1 200 OK" {
			t.Fatalf("Connection %q: %s", conn, resp)
		}
		body := resp[strings.Index(resp, "\r\n\r\n")+4:]
		for _, want := range []string{`"X-User-Id":"alice"`, `"X-Auth":"k"`, `"X-Static":"configured"`, `"X-Request-Id":"`} {
			if !strings.Contains(body, want) {
				t.Errorf("Connection %q: upstream missing %s: %s", conn, want, body)
			}
		}
		// Headers the client nominated are still treated as hop-by-hop.
		for _, not := range []string{"X-Hop", "client-id"} {
			if strings.Contains(body, not) {
				t.Errorf("Connection %q: %s reached the upstream: %s", conn, not, body)
			}
		}
	}
}

// A header one route injects as identity cannot be supplied by the client on
// any other route, authenticated or not.
func TestIdentityHeadersStrippedOnEveryRoute(t *testing.T) {
	echo := newEcho(t)
	gw := mustGateway(t, fmt.Sprintf(`
authenticators:
  k: {type: apikey, options: {keys: {alice: %s}}}
routes:
  - name: both
    path: /both
    methods: [GET]
    auth: [k]
    forwardIdentity: {X-User-Id: subject, x-tenant-id: authenticator}
    upstream: {targets: [%s]}
  - name: user-only
    path: /user-only
    methods: [GET]
    auth: [k]
    forwardIdentity: {X-User-Id: subject}
    upstream: {targets: [%s]}
  - name: anon
    path: /anon
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: [%s]}
`, testAPIKey, echo.URL, echo.URL, echo.URL))

	spoof := map[string]string{"X-API-Key": testAPIKey, "X-User-Id": "admin", "X-Tenant-Id": "victim", "X-Other": "kept"}
	for target, want := range map[string]map[string]string{
		"/both":      {"X-User-Id": "alice", "X-Tenant-Id": "k"},
		"/user-only": {"X-User-Id": "alice", "X-Tenant-Id": ""},
		"/anon":      {"X-User-Id": "", "X-Tenant-Id": ""},
	} {
		rec := do(t, gw, "GET", target, "", spoof)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d: %s", target, rec.Code, rec.Body)
		}
		e := decodeEcho(t, rec)
		for h, v := range want {
			if e.Headers[h] != v {
				t.Errorf("%s: %s = %q, want %q", target, h, e.Headers[h], v)
			}
		}
		if e.Headers["X-Other"] != "kept" {
			t.Errorf("%s: unrelated header dropped", target)
		}
	}
}

// upgradeUpstream switches protocols when asked (or always, if force is set)
// and then reports the first line it reads from the raw connection.
func upgradeUpstream(t *testing.T, force bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := r.Header.Get("Upgrade")
		if proto == "" && !force {
			fmt.Fprint(w, "plain request")
			return
		}
		if proto == "" {
			proto = "h2c"
		}
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + proto + "\r\n\r\n")
		rw.Flush()
		line, _ := rw.ReadString('\n')
		fmt.Fprintf(c, "tunnelled: %s", line)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// tryUpgrade asks for an upgrade and, if granted, writes a line down the
// tunnel. It returns the status line and whatever follows the headers.
func tryUpgrade(t *testing.T, srv *httptest.Server, path, proto string) (status, rest string) {
	t.Helper()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, Upgrade, HTTP2-Settings\r\nUpgrade: %s\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n", path, proto)
	br := bufio.NewReader(c)
	status, _ = br.ReadString('\n')
	status = strings.TrimSpace(status)
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	if strings.Contains(status, " 101 ") {
		fmt.Fprint(c, "DELETE /internal/admin HTTP/1.1\n")
		rest, _ = br.ReadString('\n')
		return status, rest
	}
	c.(*net.TCPConn).CloseWrite()
	b, _ := io.ReadAll(br)
	return status, string(b)
}

// A route is not a tunnel to its upstream unless it opts in, and never for h2c.
func TestUpgradeRequiresOptIn(t *testing.T) {
	routes := func(up string) string {
		return fmt.Sprintf(`
defaults: {auth: [anonymous]}
routes:
  - name: plain
    path: /plain
    methods: [GET]
    upstream: {targets: [%s]}
  - name: ws
    path: /ws
    methods: [GET]
    upstream: {targets: [%s], allowUpgrades: [WebSocket]}
`, up, up)
	}

	t.Run("upgrade header dropped", func(t *testing.T) {
		srv := httptest.NewServer(mustGateway(t, routes(upgradeUpstream(t, false).URL)))
		defer srv.Close()
		for _, c := range []struct{ path, proto string }{
			{"/plain", "h2c"}, {"/plain", "websocket"}, {"/ws", "h2c"}, {"/ws", "websocket, h2c"},
		} {
			status, rest := tryUpgrade(t, srv, c.path, c.proto)
			if status != "HTTP/1.1 200 OK" || !strings.Contains(rest, "plain request") {
				t.Errorf("%s Upgrade: %s: got %q %q", c.path, c.proto, status, rest)
			}
		}
	})

	t.Run("allowed protocol tunnels", func(t *testing.T) {
		srv := httptest.NewServer(mustGateway(t, routes(upgradeUpstream(t, false).URL)))
		defer srv.Close()
		status, rest := tryUpgrade(t, srv, "/ws", "websocket")
		if status != "HTTP/1.1 101 Switching Protocols" || !strings.HasPrefix(rest, "tunnelled: DELETE") {
			t.Errorf("got %q %q", status, rest)
		}
	})

	t.Run("unrequested 101 refused", func(t *testing.T) {
		srv := httptest.NewServer(mustGateway(t, routes(upgradeUpstream(t, true).URL)))
		defer srv.Close()
		for _, path := range []string{"/plain", "/ws"} {
			status, rest := tryUpgrade(t, srv, path, "h2c")
			if status != "HTTP/1.1 502 Bad Gateway" || strings.Contains(rest, "tunnelled") {
				t.Errorf("%s: got %q %q", path, status, rest)
			}
		}
	})

	t.Run("h2c cannot be configured", func(t *testing.T) {
		cfg, err := ParseConfig([]byte(`
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: ["http://x"], allowUpgrades: [H2C]}
`), true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg, WithLogger(quietLogger())); err == nil || !strings.Contains(err.Error(), "h2c") {
			t.Fatalf("want h2c config error, got %v", err)
		}
	})
}

// With a response schema configured, nothing reaches the caller unfiltered:
// not a status the schema does not cover, and not a value hidden behind a
// duplicate key.
func TestResponseFilterFailsClosed(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/created":
			w.WriteHeader(http.StatusCreated)
		case "/partial":
			w.WriteHeader(http.StatusPartialContent)
		case "/redirect":
			w.WriteHeader(http.StatusFound)
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/cached":
			w.WriteHeader(http.StatusNotModified)
			return
		case "/dup":
			_, _ = io.WriteString(w, `{"id":{"ssn":"leak"},"id":"1"}`)
			return
		case "/dup-nested":
			_, _ = io.WriteString(w, `{"id":"1","tags":[{"n":"leak","n":"a"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":"1","ssn":"leak"}`)
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
defaults: {auth: [anonymous]}
routes:
  - name: only-200
    path: /a/*
    methods: [GET, HEAD]
    upstream: {targets: [%[1]s], path: "/{*}"}
    validation:
      response:
        statusCodes: [200]
        schema: &schema
          type: object
          additionalProperties: false
          properties:
            id: {type: string}
            tags: {type: array, items: {type: object, properties: {n: {type: string}}}}
  - name: several
    path: /b/*
    methods: [GET]
    upstream: {targets: [%[1]s], path: "/{*}"}
    validation:
      response: {statusCodes: [200, 201], schema: *schema}
`, up.URL))

	for _, c := range []struct {
		method, target string
		code           int
		body           string
	}{
		{"GET", "/a/ok", 200, `{"id":"1"}`},
		{"GET", "/a/created", 502, ""},
		{"GET", "/a/partial", 502, ""},
		{"GET", "/a/redirect", 502, ""},
		{"GET", "/a/dup", 502, ""},
		{"GET", "/a/dup-nested", 502, ""},
		{"GET", "/a/empty", 204, ""},
		{"GET", "/a/cached", 304, ""},
		{"HEAD", "/a/created", 201, ""},
		{"GET", "/b/created", 201, `{"id":"1"}`},
		{"GET", "/b/redirect", 502, ""},
		{"GET", "/b/dup", 502, ""},
	} {
		rec := do(t, gw, c.method, c.target, "", nil)
		if rec.Code != c.code || strings.Contains(rec.Body.String(), "leak") {
			t.Errorf("%s %s: got %d %s, want %d", c.method, c.target, rec.Code, rec.Body, c.code)
			continue
		}
		if c.code < 400 && rec.Body.String() != c.body {
			t.Errorf("%s %s: body %q, want %q", c.method, c.target, rec.Body, c.body)
		}
	}
}

// Closing a pooled body ends it: the buffer goes back to the pool once and
// is never read again.
func TestPooledBodyClose(t *testing.T) {
	pb := getPooledBody()
	pb.buf.WriteString("hello world")
	p := make([]byte, 5)
	if n, err := pb.Read(p); n != 5 || err != nil || string(p) != "hello" {
		t.Fatalf("read: %d %v %q", n, err, p)
	}
	if err := pb.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := pb.Read(p); n != 0 || err == nil {
		t.Fatalf("read after close: %d %v", n, err)
	}
	if err := pb.Close(); err != nil || pb.buf != nil {
		t.Fatalf("second close: %v, buf %v", err, pb.buf)
	}
}

// ReverseProxy closes the outbound body when the handler returns, which can
// be while the transport is still sending it: here the upstream answers
// without reading the body. Run with -race; before the fix this reported a
// race between pooledBody.Read and Close, with the buffer already recycled.
func TestPooledBodyClosedDuringRead(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	gw := mustGateway(t, fmt.Sprintf(`
defaults: {auth: [anonymous]}
routes:
  - name: p
    path: /p
    methods: [POST]
    upstream: {targets: [%s]}
    validation: {body: {schema: {type: object}}}
`, up.URL))
	srv := httptest.NewServer(gw)
	defer srv.Close()

	body := []byte(`{"a":"` + strings.Repeat("x", 900_000) + `"}`)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				resp, err := http.Post(srv.URL+"/p", "application/json", bytes.NewReader(body))
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}
	wg.Wait()
}

// A response schema must say which statuses it covers; there is no default.
func TestResponseStatusCodesRequired(t *testing.T) {
	for statusCodes, wantErr := range map[string]string{
		"":                        "statusCodes is required",
		"statusCodes: [],":        "statusCodes is required",
		"statusCodes: [200,404],": "404 is not a 2xx or 3xx status",
		"statusCodes: [101],":     "101 is not a 2xx or 3xx status",
		"statusCodes: [200,302],": "",
	} {
		cfg, err := ParseConfig(fmt.Appendf(nil, `
routes:
  - name: r
    path: /r
    methods: [GET]
    auth: [anonymous]
    upstream: {targets: ["http://x"]}
    validation:
      response: {%s schema: {type: object}}
`, statusCodes), true)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(cfg, WithLogger(quietLogger()))
		switch {
		case wantErr == "" && err != nil:
			t.Errorf("%q: unexpected error %v", statusCodes, err)
		case wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr)):
			t.Errorf("%q: got %v, want error containing %q", statusCodes, err, wantErr)
		}
	}
}
