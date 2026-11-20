package gateway

import (
	"slices"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// responseFilter strips object properties the response schema does not
// declare, so undeclared upstream fields never reach the caller.
//
// An object is filtered only when a schema applying to it says something
// about its properties (properties, patternProperties, additionalProperties
// or unevaluatedProperties). A property is kept when it is declared, matches
// a pattern, is listed in required, or is admitted by additionalProperties /
// unevaluatedProperties being true or a schema. Everything else is removed.
// Values whose schema is silent about object structure pass through whole.
// Array elements are filtered in place and never removed.
type responseFilter struct {
	flat sync.Map // *jsonschema.Schema -> []*jsonschema.Schema
}

// applicable returns s plus every schema applied in place to the same value
// ($ref, allOf, anyOf, oneOf, if/then/else). Branches are unioned: a property
// declared by any of them is kept.
func (f *responseFilter) applicable(s *jsonschema.Schema) []*jsonschema.Schema {
	if s == nil || (s.Bool != nil && !*s.Bool) {
		return nil
	}
	if v, ok := f.flat.Load(s); ok {
		return v.([]*jsonschema.Schema)
	}
	var out []*jsonschema.Schema
	seen := map[*jsonschema.Schema]bool{}
	var walk func(*jsonschema.Schema)
	walk = func(s *jsonschema.Schema) {
		if s == nil || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
		walk(s.Ref)
		walk(s.RecursiveRef)
		if s.DynamicRef != nil {
			walk(s.DynamicRef.Ref)
		}
		for _, group := range [][]*jsonschema.Schema{s.AllOf, s.AnyOf, s.OneOf} {
			for _, sub := range group {
				walk(sub)
			}
		}
		walk(s.If)
		walk(s.Then)
		walk(s.Else)
	}
	walk(s)
	f.flat.Store(s, out)
	return out
}

// filter removes undeclared properties from v in place and returns the
// number removed.
func (f *responseFilter) filter(root *jsonschema.Schema, v any) int {
	removed := 0
	f.prune(f.applicable(root), v, &removed)
	return removed
}

func (f *responseFilter) prune(schemas []*jsonschema.Schema, v any, removed *int) {
	if len(schemas) == 0 {
		return
	}
	switch v := v.(type) {
	case map[string]any:
		f.pruneObject(schemas, v, removed)
	case []any:
		for i, el := range v {
			f.prune(f.itemSchemas(schemas, i), el, removed)
		}
	}
}

func (f *responseFilter) pruneObject(schemas []*jsonschema.Schema, obj map[string]any, removed *int) {
	for _, s := range schemas {
		for key, dep := range s.DependentSchemas {
			if _, present := obj[key]; present {
				schemas = append(slices.Clip(schemas), f.applicable(dep)...)
			}
		}
	}
	constrained := false
	for _, s := range schemas {
		if s.Properties != nil || len(s.PatternProperties) > 0 ||
			s.AdditionalProperties != nil || s.UnevaluatedProperties != nil {
			constrained = true
			break
		}
	}
	if !constrained {
		return
	}
	for key, child := range obj {
		var subs []*jsonschema.Schema
		keep := false
		for _, s := range schemas {
			matched := false
			if ps, ok := s.Properties[key]; ok {
				matched = true
				subs = append(subs, f.applicable(ps)...)
			}
			for re, ps := range s.PatternProperties {
				if re.MatchString(key) {
					matched = true
					subs = append(subs, f.applicable(ps)...)
				}
			}
			if !matched {
				switch ap := s.AdditionalProperties.(type) {
				case bool:
					keep = keep || ap
				case *jsonschema.Schema:
					subs = append(subs, f.applicable(ap)...)
				}
			}
			if slices.Contains(s.Required, key) {
				keep = true
			}
		}
		if len(subs) == 0 && !keep {
			for _, s := range schemas {
				subs = append(subs, f.applicable(s.UnevaluatedProperties)...)
			}
		}
		if len(subs) == 0 && !keep {
			delete(obj, key)
			*removed++
			continue
		}
		f.prune(subs, child, removed)
	}
}

// itemSchemas returns the schemas applying to array element i.
func (f *responseFilter) itemSchemas(schemas []*jsonschema.Schema, i int) []*jsonschema.Schema {
	var subs []*jsonschema.Schema
	for _, s := range schemas {
		switch {
		case i < len(s.PrefixItems):
			subs = append(subs, f.applicable(s.PrefixItems[i])...)
		case s.Items2020 != nil:
			subs = append(subs, f.applicable(s.Items2020)...)
		}
		// Drafts before 2020-12.
		switch items := s.Items.(type) {
		case *jsonschema.Schema:
			subs = append(subs, f.applicable(items)...)
		case []*jsonschema.Schema:
			if i < len(items) {
				subs = append(subs, f.applicable(items[i])...)
			} else if extra, ok := s.AdditionalItems.(*jsonschema.Schema); ok {
				subs = append(subs, f.applicable(extra)...)
			}
		}
	}
	if len(subs) == 0 {
		for _, s := range schemas {
			subs = append(subs, f.applicable(s.UnevaluatedItems)...)
		}
	}
	return subs
}
