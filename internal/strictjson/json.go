// Package strictjson refuses ambiguous object keys before typed wire decoding.
// It does not canonicalize signed bytes or interpret opaque grant payloads.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid JSON shape")

const MaxBytes = 8 << 20

// Validate refuses duplicate and escaped key spellings recursively, including
// opaque subtrees. Ordinary string value escapes remain legal. Callers retain
// their own smaller input limits; neither key nor value text appears in errors.
func Validate(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrInvalid
		}
		token, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				start := d.InputOffset()
				token, e := d.Token()
				key, ok := token.(string)
				if e != nil || !ok || seen[key] || bytes.IndexByte(raw[start:d.InputOffset()], '\\') >= 0 {
					return ErrInvalid
				}
				seen[key] = true
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			token, e = d.Token()
			if e != nil || token != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			token, e = d.Token()
			if e != nil || token != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Unmarshal enforces exact typed field names (also in map values) before it
// populates out. Nullability and required fields remain caller schema policy.
// RawMessage is opaque to the typed schema, but Validate covers all its keys.
func Unmarshal(raw []byte, out any) error {
	if Validate(raw) != nil || out == nil {
		return ErrInvalid
	}
	if fields(raw, reflect.TypeOf(out)) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}
func fields(raw []byte, t reflect.Type) error {
	if t == reflect.TypeFor[json.RawMessage]() || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		return fields(raw, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return ErrInvalid
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name != "-" {
				known[name] = f.Type
			}
		}
		for name, value := range values {
			typ, ok := known[name]
			if !ok || fields(value, typ) != nil {
				return ErrInvalid
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return ErrInvalid
		}
		for _, value := range values {
			if fields(value, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil
		} // encoded binary, not object schema
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrInvalid
		}
		for _, value := range values {
			if fields(value, t.Elem()) != nil {
				return ErrInvalid
			}
		}
	}
	return nil
}
