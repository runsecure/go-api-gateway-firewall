package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const maxReportedErrors = 10

// schemaCompiler compiles schemas once at startup. Only file: URLs are
// loadable, so a schema can never trigger a network fetch.
type schemaCompiler struct {
	c       *jsonschema.Compiler
	baseDir string
}

func newSchemaCompiler(baseDir string) *schemaCompiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	return &schemaCompiler{c: c, baseDir: baseDir}
}

func (sc *schemaCompiler) compile(ref *SchemaRef, route, kind string) (*jsonschema.Schema, error) {
	if ref == nil {
		return nil, nil
	}
	if ref.File != "" {
		p := ref.File
		if !filepath.IsAbs(p) {
			p = filepath.Join(sc.baseDir, p)
		}
		s, err := sc.c.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("route %s %s schema: %w", route, kind, err)
		}
		return s, nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(ref.Schema))
	if err != nil {
		return nil, fmt.Errorf("route %s %s schema: %w", route, kind, err)
	}
	// Anchor inline schemas in baseDir so relative $refs resolve to files.
	loc := (&url.URL{Scheme: "file", Path: filepath.ToSlash(filepath.Join(sc.baseDir,
		".inline", url.PathEscape(route), kind+".json"))}).String()
	if err := sc.c.AddResource(loc, doc); err != nil {
		return nil, fmt.Errorf("route %s %s schema: %w", route, kind, err)
	}
	s, err := sc.c.Compile(loc)
	if err != nil {
		return nil, fmt.Errorf("route %s %s schema: %w", route, kind, err)
	}
	return s, nil
}

// requestValidator enforces a route's request contract.
type requestValidator struct {
	params, query, body *jsonschema.Schema
	bodyRequired        bool
	contentTypes        []string
	maxBody             int64
	maxDepth            int
	rejectDup           bool
	expose              bool
	route               string
	headers             headerRules // response headers for rejections
	logger              *slog.Logger
}

func (v *requestValidator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v.params != nil {
			rc := chi.RouteContext(r.Context())
			m := make(map[string]any, len(rc.URLParams.Keys))
			for i, k := range rc.URLParams.Keys {
				if k == "*" {
					continue
				}
				// chi yields escaped values when the request has a RawPath;
				// validate what the upstream will see after decoding.
				val := rc.URLParams.Values[i]
				if r.URL.RawPath != "" {
					dec, err := url.PathUnescape(val)
					if err != nil {
						v.refuse(w, r, "malformed path parameter", FieldError{In: "params", Location: "/" + k})
						return
					}
					val = dec
				}
				m[k] = val
			}
			if err := v.params.Validate(m); err != nil {
				v.reject(w, r, "params", err)
				return
			}
		}
		if v.query != nil {
			// Hardening has already rejected malformed query strings.
			q, _ := url.ParseQuery(r.URL.RawQuery)
			if err := v.query.Validate(queryToJSON(q)); err != nil {
				v.reject(w, r, "query", err)
				return
			}
		}
		if v.body != nil {
			buf, ok := v.validateBody(w, r)
			if !ok {
				return
			}
			if buf != nil {
				r.Body = buf
				r.ContentLength = int64(buf.Len())
				r.Header.Set("Content-Length", strconv.Itoa(buf.Len()))
				r.Header.Del("Transfer-Encoding")
				r.TransferEncoding = nil
			}
		}
		next.ServeHTTP(w, r)
	})
}

// validateBody reads, parses and validates the body. On success it returns a
// replayable body for the upstream (nil if empty).
func (v *requestValidator) validateBody(w http.ResponseWriter, r *http.Request) (*pooledBody, bool) {
	pb := getPooledBody()
	n, err := pb.buf.ReadFrom(io.LimitReader(r.Body, v.maxBody+1))
	_ = r.Body.Close()
	if err != nil {
		pb.Close()
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			v.refuse(w, r, "failed to read request body", FieldError{In: "body"})
		}
		return nil, false
	}
	if n > v.maxBody {
		pb.Close()
		WriteProblem(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	if n == 0 {
		pb.Close()
		if v.bodyRequired {
			v.refuse(w, r, "request body is required", FieldError{In: "body"})
			return nil, false
		}
		r.Body = http.NoBody
		r.ContentLength = 0
		return nil, true
	}
	if !v.contentTypeAllowed(r.Header.Get("Content-Type")) {
		pb.Close()
		WriteProblem(w, r, http.StatusUnsupportedMediaType, "unsupported content type")
		return nil, false
	}
	doc, err := parseJSON(pb.buf.Bytes(), v.maxDepth, v.rejectDup)
	if err != nil {
		pb.Close()
		v.refuse(w, r, "malformed JSON body", FieldError{In: "body", Location: "", Message: err.Error()})
		return nil, false
	}
	if err := v.body.Validate(doc); err != nil {
		pb.Close()
		v.reject(w, r, "body", err)
		return nil, false
	}
	return pb, true
}

func (v *requestValidator) contentTypeAllowed(ct string) bool {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	if cs, ok := params["charset"]; ok && !strings.EqualFold(cs, "utf-8") {
		return false
	}
	if len(v.contentTypes) == 0 {
		return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
	}
	return slices.Contains(v.contentTypes, mt)
}

func (v *requestValidator) reject(w http.ResponseWriter, r *http.Request, in string, err error) {
	v.refuse(w, r, "request does not match the API contract", schemaErrors(in, err)...)
}

// refuse answers 400. Unless validation errors are exposed, the response is
// the one an upstream 400 produces, so the caller learns nothing about the
// contract or about which side refused. The failing locations are logged;
// the messages are not, because they can quote the request.
func (v *requestValidator) refuse(w http.ResponseWriter, r *http.Request, detail string, errs ...FieldError) {
	if v.logger != nil {
		where := make([]string, len(errs))
		for i, e := range errs {
			where[i] = e.In + ":" + e.Location
		}
		ctx := r.Context()
		v.logger.InfoContext(ctx, "request rejected by contract", "route", v.route,
			"request_id", RequestIDFrom(ctx), "reason", detail, "locations", where)
	}
	v.headers.apply(w.Header())
	if !v.expose {
		WriteProblem(w, r, http.StatusBadRequest, upstreamErrorDetails[http.StatusBadRequest])
		return
	}
	WriteProblem(w, r, http.StatusBadRequest, detail, errs...)
}

// schemaErrors flattens a validation error into leaf violations.
func schemaErrors(in string, err error) []FieldError {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []FieldError{{In: in, Message: "validation failed"}}
	}
	var out []FieldError
	for _, u := range ve.BasicOutput().Errors {
		if u.Error == nil {
			continue
		}
		out = append(out, FieldError{In: in, Location: u.InstanceLocation, Message: u.Error.String()})
		if len(out) == maxReportedErrors {
			break
		}
	}
	return out
}

// queryToJSON maps a single-valued parameter to a string and a repeated
// parameter to an array of strings.
func queryToJSON(q url.Values) map[string]any {
	m := make(map[string]any, len(q))
	for k, vs := range q {
		if len(vs) == 1 {
			m[k] = vs[0]
			continue
		}
		arr := make([]any, len(vs))
		for i, s := range vs {
			arr[i] = s
		}
		m[k] = arr
	}
	return m
}

// pooledBody is a replayable request body. Its buffer comes from a pool and
// is returned when the body is closed. Each request gets its own handle so a
// late or duplicate Close can never recycle a buffer in use.
//
// Close can arrive while a Read is still running: ReverseProxy closes the
// outbound body when the handler returns, even if the transport has not
// finished sending it. The mutex makes Close wait for that Read, and later
// Reads fail, so the buffer is never read after it has been recycled.
type pooledBody struct {
	mu     sync.Mutex
	buf    *bytes.Buffer
	r      bytes.Reader
	closed bool
	primed bool
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

const maxPooledBuffer = 1 << 20

func getPooledBody() *pooledBody {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return &pooledBody{buf: b}
}

// Len is the body size. It is only valid before the body is handed on.
func (p *pooledBody) Len() int { return p.buf.Len() }

func (p *pooledBody) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, http.ErrBodyReadAfterClose
	}
	if !p.primed {
		p.r.Reset(p.buf.Bytes())
		p.primed = true
	}
	return p.r.Read(b)
}

func (p *pooledBody) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	p.r.Reset(nil)
	if p.buf.Cap() <= maxPooledBuffer {
		bufPool.Put(p.buf)
	}
	p.buf = nil
	return nil
}

// responseValidator enforces the response contract via ModifyResponse.
// Properties the schema does not declare are stripped; a response that still
// violates the schema afterwards is rejected, as is one whose status the
// schema does not cover.
type responseValidator struct {
	schema   *jsonschema.Schema
	statuses []int
	maxBytes int64
	filter   responseFilter
}

var errResponseContract = errors.New("upstream response violates contract")

func (v *responseValidator) applies(status int) bool {
	return slices.Contains(v.statuses, status)
}

// check filters and validates the response body, returning the number of
// undeclared properties stripped from it.
func (v *responseValidator) check(resp *http.Response) (stripped int, err error) {
	switch {
	case resp.Request.Method == http.MethodHead, resp.StatusCode == http.StatusNoContent,
		resp.StatusCode == http.StatusNotModified:
		// No body to check.
		return 0, nil
	case resp.StatusCode == http.StatusSwitchingProtocols:
		// The route opted into upgrades; the "body" is the raw connection.
		return 0, nil
	case !v.applies(resp.StatusCode):
		// Fail closed: a body the schema does not cover would otherwise
		// reach the caller unfiltered.
		return 0, fmt.Errorf("%w: status %d is not covered by the response schema", errResponseContract, resp.StatusCode)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return 0, fmt.Errorf("%w: cannot validate encoded response (%s)", errResponseContract, ce)
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return 0, fmt.Errorf("%w: unexpected content type %q", errResponseContract, mt)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, v.maxBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return 0, err
	}
	if int64(len(b)) > v.maxBytes {
		return 0, fmt.Errorf("%w: response exceeds %d bytes", errResponseContract, v.maxBytes)
	}
	// Duplicate keys are rejected: only the last value is validated, yet a
	// conforming body is forwarded as received, earlier values included.
	doc, err := parseJSON(b, 512, true)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errResponseContract, err)
	}
	stripped = v.filter.filter(v.schema, doc)
	if err := v.schema.Validate(doc); err != nil {
		return 0, fmt.Errorf("%w: %v", errResponseContract, err)
	}
	if stripped > 0 {
		// Re-encode only when something was removed, so conforming
		// responses are forwarded byte for byte.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(doc); err != nil {
			return 0, fmt.Errorf("%w: %v", errResponseContract, err)
		}
		b = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.TransferEncoding = nil
	return stripped, nil
}
