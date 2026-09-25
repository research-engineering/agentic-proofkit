package admission

import (
	"encoding"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"strings"
)

// jsonStructFields resolves exact JSON names, not Go selector visibility.
// Match encoding/json's breadth-first type discovery and name dominance;
// each embedded type is scanned once, so recursive embeddings terminate.
func jsonStructFields(target reflect.Type) (map[string]reflect.Type, error) {
	type candidate struct {
		target reflect.Type
		depth  int
		tagged bool
		count  int
	}
	selected := map[string]candidate{}
	visited := map[reflect.Type]bool{}
	level := map[reflect.Type]int{target: 1}
	for depth := 0; len(level) != 0; depth++ {
		next := map[reflect.Type]int{}
		for parent, occurrences := range level {
			if visited[parent] {
				continue
			}
			visited[parent] = true
			for index := 0; index < parent.NumField(); index++ {
				field := parent.Field(index)
				tag := field.Tag.Get("json")
				if tag == "-" || (!field.IsExported() && !field.Anonymous) {
					continue
				}
				// Only anonymous fields need type resolution for promotion.
				// Ordinary child types stay untouched until their value occurs.
				embedded := field.Type
				if field.Anonymous {
					var err error
					embedded, err = indirectJSONType(field.Type)
					if err != nil {
						return nil, err
					}
					if !field.IsExported() && embedded.Kind() != reflect.Struct {
						continue
					}
				}
				name, options, hasOptions := strings.Cut(tag, ",")
				// Reserved/quoted names are outside the supported target-tag
				// contract; do not guess a stdlib-version-specific fallback.
				if strings.ContainsAny(name, "\\'\"`") {
					return nil, errors.New("invalid JSON target schema: unsupported field tag name")
				}
				omitzero := false
				if hasOptions {
					for _, option := range strings.Split(options, ",") {
						switch option {
						case "omitzero":
							omitzero = true
						case "omitempty", "string":
						default:
							return nil, errors.New("invalid JSON target schema: unsupported field tag option")
						}
					}
				}
				if field.Anonymous && name == "" && embedded.Kind() == reflect.Struct {
					// Count repeated discoveries at this level, as encoding/json
					// does; two suffice to mark the type's own fields ambiguous.
					next[embedded] = min(2, next[embedded]+1)
					continue
				}
				// Go 1.27's normal-field branch excludes inaccessible methods;
				// its automatic struct-promotion branch still visits children.
				if !field.IsExported() && (hasJSONSerializationMethod(embedded) ||
					(omitzero && hasJSONMethod(embedded, reflect.TypeFor[interface{ IsZero() bool }]()))) {
					continue
				}
				tagged := name != ""
				if name == "" {
					name = field.Name
				}
				previous, found := selected[name]
				switch {
				case !found:
					selected[name] = candidate{field.Type, depth, tagged, occurrences}
				case previous.depth < depth:
					// Even an ambiguous shallower name hides deeper fields.
				case tagged && !previous.tagged:
					selected[name] = candidate{field.Type, depth, tagged, occurrences}
				case tagged == previous.tagged:
					previous.count = 2
					selected[name] = previous
				}
			}
		}
		level = next
	}
	fields := map[string]reflect.Type{}
	for name, field := range selected {
		if field.count == 1 {
			fields[name] = field.target
		}
	}
	return fields, nil
}

func hasJSONSerializationMethod(target reflect.Type) bool {
	return hasJSONMethod(target,
		reflect.TypeFor[json.Marshaler](), reflect.TypeFor[jsonv2.MarshalerTo](),
		reflect.TypeFor[json.Unmarshaler](), reflect.TypeFor[jsonv2.UnmarshalerFrom](),
		reflect.TypeFor[encoding.TextMarshaler](), reflect.TypeFor[encoding.TextAppender](),
		reflect.TypeFor[encoding.TextUnmarshaler]())
}

func hasJSONMethod(target reflect.Type, methods ...reflect.Type) bool {
	for _, method := range methods {
		if target.Implements(method) || reflect.PointerTo(target).Implements(method) {
			return true
		}
	}
	return false
}
