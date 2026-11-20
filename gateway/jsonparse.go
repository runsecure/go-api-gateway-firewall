package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	errInvalidUTF8  = errors.New("body is not valid UTF-8")
	errTooDeep      = errors.New("JSON nesting exceeds limit")
	errTrailingData = errors.New("unexpected data after JSON value")
	errDuplicateKey = errors.New("duplicate object key")
)

// parseJSON strictly decodes a JSON document for schema validation.
//
// Beyond encoding/json it rejects invalid UTF-8 (which the stdlib silently
// replaces), nesting deeper than maxDepth, trailing data, and optionally
// duplicate object keys. Each of these is a known source of
// parser-differential bypasses between a gateway and its upstreams.
func parseJSON(b []byte, maxDepth int, rejectDuplicates bool) (any, error) {
	if !utf8.Valid(b) {
		return nil, errInvalidUTF8
	}
	if err := checkDepth(b, maxDepth); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	var err error
	if rejectDuplicates {
		v, err = decodeValue(dec)
	} else {
		err = dec.Decode(&v)
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty JSON document")
		}
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errTrailingData
	}
	return v, nil
}

// checkDepth scans for container nesting outside of strings without
// allocating, bounding work before the real decode.
func checkDepth(b []byte, max int) error {
	depth, inStr, esc := 0, false, false
	for _, c := range b {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > max {
				return errTooDeep
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

// decodeValue builds a value from the token stream, detecting duplicate keys.
func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch d {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k := kt.(string)
			if _, dup := obj[k]; dup {
				return nil, fmt.Errorf("%w %q", errDuplicateKey, k)
			}
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			obj[k] = v
		}
		_, err := dec.Token() // '}'
		return obj, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token() // ']'
		return arr, err
	}
	return nil, fmt.Errorf("unexpected delimiter %q", d)
}
