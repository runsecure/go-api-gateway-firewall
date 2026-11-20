# go-api-gateway-firewall

A lightweight, configuration-driven API gateway for Go, built on [chi](https://github.com/go-chi/chi). It works like Ocelot for .NET, with a focus on security: every route is a reverse proxy, and it can enforce request hardening, authentication and a JSON Schema API contract before any byte reaches your services.

You can use it as a **library** (`gateway` package) inside your own Go program, or as a **ready-made executable** (`cmd/gateway`).

- **Reverse proxy routing.** Uses chi route patterns (`/orders/{id}`, `/static/*`), upstream path templates, round-robin across targets, per-route timeouts and concurrency caps.
- **Per-route JSON Schema validation (draft 2020-12).** Checks the request body, query string and path params, plus optional **response** validation so upstream data leaks are blocked with a 502.
- **Pluggable authentication.** Ships with JWT (HS/RS/PS/ES) and API-key authenticators. You can register your own types and refer to them from config.
- **Request hardening.** Body/URL/query limits, JSON depth limits, rejection of duplicate keys and invalid UTF-8, path traversal and double-encoding guards, rate limiting, header sanitization and security response headers.
- **Few dependencies.** Only `chi`, `santhosh-tekuri/jsonschema/v6` and `go.yaml.in/yaml/v3`. Everything else, including JWT verification, uses the standard library.
- **Fast.** Schemas compile once at startup, request buffers are pooled, upstream connections are reused, and the rate limiter is sharded and runs without a background goroutine.

## Quick start

```sh
go build -o bin/gateway ./cmd/gateway
bin/gateway -config examples/gateway.yaml -check   # validate config + compile schemas
bin/gateway -config examples/gateway.yaml
```

Flags (each also settable as an environment variable): `-config` (`GATEWAY_CONFIG`), `-log-level` (`GATEWAY_LOG_LEVEL`), `-log-format json|text` (`GATEWAY_LOG_FORMAT`), `-check`.

Docker:

```sh
docker build -t gateway .
docker run -p 8080:8080 -v $PWD/examples:/etc/gateway gateway
```

## Configuration

Config files can be YAML or JSON. Unknown fields are **rejected**, so a misspelled security setting stops startup instead of being silently ignored. All schemas, authenticators and routes are checked at startup, and every error is reported at once. For a complete example, see [examples/gateway.yaml](examples/gateway.yaml).

```yaml
defaults:
  auth: [users]                  # applies to routes that don't set auth
  hardening: {maxBodyBytes: 262144, maxJsonDepth: 16}

authenticators:
  users:
    type: jwt
    options:
      algorithms: [RS256]
      publicKey: file:/etc/gateway/jwt.pem
      issuer: https://auth.example.com/
      audience: [orders-api]

routes:
  - name: create-order
    path: /api/orders
    methods: [POST]
    requiredScopes: [orders:write]
    forwardIdentity: {X-User-Id: subject, X-Tenant-Id: claims.tenant}
    upstream:
      targets: [http://orders-1:8080, http://orders-2:8080]
      path: /v1/orders
    validation:
      body: {file: schemas/order.json}
```

### Routes

| Field | Description |
|---|---|
| `name` | Unique route ID, used in logs and errors. |
| `path` | chi pattern: `/a/{id}`, `/a/{id:[0-9]+}`, `/static/*`. |
| `methods` | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS. Any other method returns 405. |
| `upstream.targets` | One or more `http(s)` base URLs, balanced round-robin. |
| `upstream.path` | Optional rewrite template. `{name}` inserts a route param and `{*}` inserts the wildcard remainder. If omitted, the inbound path is forwarded unchanged. |
| `upstream.timeout` | Total upstream deadline (default `defaults.timeout`, then 30s). Returns 504 when exceeded. |
| `upstream.maxConcurrent` | Maximum in-flight requests. Requests above the cap get 503 with `Retry-After`. |
| `upstream.preserveHost` | Forward the client's `Host` header instead of the target's. |
| `auth` | Authenticator names to try in order. `[anonymous]` disables auth. |
| `requiredScopes` | The principal must have every listed scope, otherwise 403. |
| `forwardIdentity` | Maps a header name to `subject`, `authenticator`, `scopes` or `claims.<name>`. Any client-supplied copies of these headers are always stripped. |
| `middleware` | Names registered with `WithNamedMiddleware`. |
| `validation` | `body`, `query`, `params`, `response`. See below. |
| `hardening` | Per-route overrides of `defaults.hardening`. |
| `requestHeaders` / `responseHeaders` | `{set: {...}, remove: [...]}`. |
| `requestHeaderMap` | Maps an upstream header name to an incoming header name, for example `{X-Correlation-Id: X-Request-Id}`. |

Ordinary incoming headers are forwarded by default. `requestHeaderMap` copies all values from the source after authentication and hop-by-hop stripping; if the source is absent, the destination is removed. Mappings use a snapshot, so they do not chain, and `requestHeaders` rules apply afterward. Mapping destinations cannot be hop-by-hop, forwarding, framing, or `forwardIdentity` headers. Client-provided values remain untrusted; do not map them to headers that upstream services treat as authenticated identity.

### Validation (API contract)

Each validation entry takes either an inline `schema` or a `file` path (relative to the config file). Relative `$ref`s resolve against the config directory. Schema references are only loaded from local files, so a schema can never make the gateway fetch something over the network. `format` keywords are **asserted**, not just treated as annotations.

- **`body`**: validates JSON request bodies. `required` defaults to true. `contentTypes` defaults to `application/json` and `application/*+json`. A non-UTF-8 `charset` is rejected with 415.
- **`query`**: the query string is converted to an object. A parameter that appears once becomes a string, and a repeated parameter becomes an array of strings. Set `additionalProperties: false` to allowlist parameters.
- **`params`**: route params as an object of strings.
- **`response`**: buffers the upstream response (up to `maxBytes`, default 4 MiB) for the listed `statusCodes` (default: all 2xx) and validates it. If validation fails, the client gets a **502** and the response body is never forwarded. When this is enabled, the gateway negotiates encoding itself so it can decode compressed responses before validating.

A request that violates the contract gets an RFC 9457 `application/problem+json` 400 response:

```json
{"title":"Bad Request","status":400,"detail":"request does not match the API contract",
 "requestId":"a53b60fa38573df0a2c4701f",
 "errors":[{"in":"body","location":"/qty","message":"minimum: got 0, want 1"}]}
```

Set `server.exposeValidationErrors: false` to leave out the `errors` details.

### Hardening

| Control | Default |
|---|---|
| `maxBodyBytes` (checked against Content-Length up front and enforced while streaming) | 1 MiB |
| `maxUrlLength` | 4096 |
| `maxQueryParams` (malformed query strings, e.g. ones using `;`, are rejected) | 64 |
| `maxJsonDepth` | 32 |
| `rejectDuplicateKeys` | true |
| `allowEncodedSlashes` (`%2F`, `%5C`) | false |
| `rateLimit: {requestsPerSecond, burst, key: ip\|principal}` | off |

These checks always run, whatever the config:
- Paths with dot segments, empty segments, backslashes, control characters or double encoding (`%252e`) are rejected **before routing**.
- Request bodies are checked for valid UTF-8, nesting depth and trailing data. These are common causes of parser differences between the gateway and an upstream.
- Inbound `X-Forwarded-*` and `Forwarded` headers are discarded unless the direct peer is in `server.trustedProxies`.
- Hop-by-hop headers are stripped. The API key header is not forwarded upstream.
- `Server` and `X-Powered-By` are removed from responses. `nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` are added.
- Every request gets an `X-Request-Id`. A client-supplied ID is kept only if it is 64 characters or fewer and uses only safe characters.
- Server read, header and idle timeouts and `maxHeaderBytes` all have safe defaults.

### Built-in authenticators

**`jwt`**: verifies compact JWS tokens with a single static key.
- Supported algorithms are HS256/384/512 (secret of at least 32 bytes), RS*/PS* (RSA PEM) and ES256/384/512 (EC PEM).
- Every algorithm in the list must match the key type, which blocks algorithm-confusion attacks. `alg: none` and `crit` headers are always rejected.
- `exp` is required. `nbf`, `iss` and `aud` are checked (with `leeway`) when they are present or configured.
- Scopes are read from `scopeClaim` (default `scope`, either a space-separated string or an array).

**`apikey`**: `keys` maps a key ID (which becomes the principal subject) to a secret, and keys must be at least 16 characters. Keys are compared in constant time using SHA-256 digests. Optional per-key `scopes`.

Secret values in either authenticator can use `env:NAME` or `file:/path` instead of a literal.

## Library usage

```go
cfg, err := gateway.LoadConfig("gateway.yaml")
if err != nil { log.Fatal(err) }

gw, err := gateway.New(cfg,
    gateway.WithLogger(slog.Default()),

    // A custom authenticator instance, referenced by name from route `auth` lists.
    gateway.WithAuthenticator("mtls", gateway.AuthenticatorFunc(func(r *http.Request) (*gateway.Principal, error) {
        if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
            return nil, gateway.ErrNoCredentials // let the next authenticator try
        }
        return &gateway.Principal{Subject: r.TLS.PeerCertificates[0].Subject.CommonName}, nil
    })),

    // A custom authenticator *type*, configurable from YAML (`type: introspection`).
    gateway.WithAuthenticatorType("introspection", newIntrospectionAuth),

    // Middleware routes opt into with `middleware: [audit]`; runs after auth.
    gateway.WithNamedMiddleware("audit", auditMiddleware),

    // Middleware for every request (after request ID + path guard, before routing).
    gateway.WithMiddleware(metricsMiddleware),

    // Per-route hook, called once at build time with the route config.
    gateway.WithRouteMiddleware(func(rc gateway.RouteConfig) gateway.Middleware { return nil }),
)
if err != nil { log.Fatal(err) }

// Option 1: run the managed server (graceful shutdown on ctx cancel).
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()
log.Fatal(gw.ListenAndServe(ctx))

// Option 2: it's an http.Handler; mount it anywhere.
// http.ListenAndServe(":8080", gw)
```

In your handlers and middleware, `gateway.PrincipalFrom(ctx)`, `gateway.RequestIDFrom(ctx)` and `gateway.ClientIPFrom(ctx)` give you the request's identity, ID and client IP.

How an `Authenticator` signals its result:
- Return `ErrNoCredentials` when the request doesn't carry this authenticator's credential type, so the next authenticator gets a turn.
- Return any other error to reject the request with 401.

### Request pipeline

```
entry (request ID, client IP, panic recovery, access log)
  → path guard → global middleware → chi routing
  → limits (URL, query, body size) → rate limit (ip) → concurrency cap
  → authentication + scopes + identity headers → rate limit (principal)
  → route hooks → named middleware → contract validation (params, query, body)
  → reverse proxy (path rewrite, header rules) → response validation → response headers
```

## Performance

On an Apple M2, with an in-memory upstream and httptest overhead included (`go test -bench . ./gateway`):

| Scenario | ns/op | allocs/op |
|---|---|---|
| GET passthrough | ~4,000 | 71 |
| POST, JSON body schema-validated | ~5,400 | 129 |

## Not yet included

These features are planned or can be added through the extension points above:
- Active health checks and circuit breaking
- JWKS and OIDC discovery (register a custom authenticator type for now)
- Config hot reload
- Metrics export
- Header schema validation

## License

MPL-2.0
