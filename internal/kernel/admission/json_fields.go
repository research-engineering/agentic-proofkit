package admission

import (
	"errors"
	"reflect"
	"strings"
)

// Resolve the reachable non-opaque field tables before inspecting input keys.
// Invalid target declarations must fail even for absent children or empty input
// containers. The tables are local to one decode and reused for repeated types.
func jsonTargetFields(target reflect.Type) (map[reflect.Type]map[string]reflect.Type, error) {
	tables := map[reflect.Type]map[string]reflect.Type{}
	seen := map[reflect.Type]bool{}
	pending := []reflect.Type{target}
	for index := 0; index < len(pending); index++ {
		current := indirectJSONType(pending[index])
		if current == nil || seen[current] || current.Kind() == reflect.Interface || isOpaqueJSONType(current) {
			continue
		}
		seen[current] = true
		switch current.Kind() {
		case reflect.Struct:
			fields, err := jsonStructFields(current)
			if err != nil {
				return nil, err
			}
			tables[current] = fields
			for _, fieldType := range fields {
				pending = append(pending, fieldType)
			}
		case reflect.Slice, reflect.Array, reflect.Map:
			pending = append(pending, current.Elem())
		}
	}
	return tables, nil
}

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
				embedded := indirectJSONType(field.Type)
				if !field.IsExported() && (!field.Anonymous || embedded.Kind() != reflect.Struct) {
					continue
				}
				tag := field.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, _, _ := strings.Cut(tag, ",")
				// Reserved/quoted names are outside the supported target-tag
				// contract; do not guess a stdlib-version-specific fallback.
				if strings.ContainsAny(name, "\\'\"`") {
					return nil, errors.New("invalid JSON target schema: unsupported field tag name")
				}
				if field.Anonymous && name == "" && embedded.Kind() == reflect.Struct {
					// Count repeated discoveries at this level, as encoding/json
					// does; two suffice to mark the type's own fields ambiguous.
					next[embedded] = min(2, next[embedded]+1)
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
