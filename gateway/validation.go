package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

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
}

func (v *requestValidator) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v.params != nil {
			rc := chi.RouteContext(r.Context())
			m := make(map[string]any, len(rc.URLParams.Keys))
			for i, k := range rc.URLParams.Keys {
				if k != "*" {
					m[k] = rc.URLParams.Values[i]
				}
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
			WriteProblem(w, r, http.StatusBadRequest, "failed to read request body")
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
			WriteProblem(w, r, http.StatusBadRequest, "request body is required")
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
		WriteProblem(w, r, http.StatusBadRequest, "malformed JSON body",
			FieldError{In: "body", Location: "", Message: err.Error()})
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
	if !v.expose {
		WriteProblem(w, r, http.StatusBadRequest, "request does not match the API contract")
		return
	}
	WriteProblem(w, r, http.StatusBadRequest, "request does not match the API contract", schemaErrors(in, err)...)
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
// is returned when the transport closes the body. Each request gets its own
// handle so a late or duplicate Close can never recycle a buffer in use.
type pooledBody struct {
	buf    *bytes.Buffer
	r      bytes.Reader
	closed atomic.Bool
	primed bool
}

var bufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

const maxPooledBuffer = 1 << 20

func getPooledBody() *pooledBody {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return &pooledBody{buf: b}
}

func (p *pooledBody) Len() int { return p.buf.Len() }

func (p *pooledBody) Read(b []byte) (int, error) {
	if !p.primed {
		p.r.Reset(p.buf.Bytes())
		p.primed = true
	}
	return p.r.Read(b)
}

func (p *pooledBody) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		buf := p.buf
		p.r.Reset(nil)
		if buf.Cap() <= maxPooledBuffer {
			bufPool.Put(buf)
		}
	}
	return nil
}

// responseValidator enforces the response contract via ModifyResponse.
type responseValidator struct {
	schema   *jsonschema.Schema
	statuses []int
	maxBytes int64
}

var errResponseContract = errors.New("upstream response violates contract")

func (v *responseValidator) applies(status int) bool {
	if len(v.statuses) == 0 {
		return status >= 200 && status < 300
	}
	return slices.Contains(v.statuses, status)
}

func (v *responseValidator) check(resp *http.Response) error {
	if !v.applies(resp.StatusCode) || resp.Request.Method == http.MethodHead ||
		resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Errorf("%w: cannot validate encoded response (%s)", errResponseContract, ce)
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mt != "application/json" && !strings.HasSuffix(mt, "+json") {
		return fmt.Errorf("%w: unexpected content type %q", errResponseContract, mt)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, v.maxBytes+1))
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if int64(len(b)) > v.maxBytes {
		return fmt.Errorf("%w: response exceeds %d bytes", errResponseContract, v.maxBytes)
	}
	doc, err := parseJSON(b, 512, false)
	if err != nil {
		return fmt.Errorf("%w: %v", errResponseContract, err)
	}
	if err := v.schema.Validate(doc); err != nil {
		return fmt.Errorf("%w: %v", errResponseContract, err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.TransferEncoding = nil
	return nil
}
