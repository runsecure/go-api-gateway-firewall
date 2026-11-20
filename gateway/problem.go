package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// Problem is an RFC 9457 problem details body. Gateway-generated errors never
// include upstream or internal error text.
type Problem struct {
	Type      string       `json:"type,omitempty"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	RequestID string       `json:"requestId,omitempty"`
	Errors    []FieldError `json:"errors,omitempty"`
}

// FieldError locates a single contract violation.
type FieldError struct {
	In       string `json:"in"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

// WriteProblem writes a problem+json response.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, detail string, errs ...FieldError) {
	p := Problem{
		Title:     http.StatusText(status),
		Status:    status,
		Detail:    detail,
		RequestID: RequestIDFrom(r.Context()),
		Errors:    errs,
	}
	b, err := json.Marshal(p)
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/problem+json")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
