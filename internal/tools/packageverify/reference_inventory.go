package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

type referenceScope uint8

const (
	referenceRecord referenceScope = iota
	structuralFieldTree
	structuralSchema
	schemaProperties
	literalStringMap
)

func verifyClosedReferenceInventory(label string, value any, classifications map[string]string) error {
	var walk func(any, []string, referenceScope) error
	walk = func(current any, route []string, scope referenceScope) error {
		if scope == referenceRecord && classifications["/"+strings.Join(route, "/")] == "literal_string_map" {
			scope = literalStringMap
		}
		if scope == literalStringMap {
			if _, ok := current.(map[string]any); !ok {
				return fmt.Errorf("package %s literal map must be an object", label)
			}
		}
		if scope == schemaProperties {
			if _, ok := current.(map[string]any); !ok {
				return fmt.Errorf("package %s schema properties must be an object", label)
			}
		}
		switch typed := current.(type) {
		case map[string]any:
			if scope == referenceRecord && classifications["/"+strings.Join(route, "/")] == "structural_schema" && typed["kind"] == "structural_json_schema" {
				scope = structuralFieldTree
			}
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				fieldRoute := append(append([]string{}, route...), key)
				if scope == literalStringMap {
					if _, ok := typed[key].(string); !ok {
						return fmt.Errorf("package %s literal map values must be strings", label)
					}
				} else if scope == schemaProperties {
					switch typed[key].(type) {
					case map[string]any, bool:
					default:
						return fmt.Errorf("package %s property declaration must be an object or boolean schema", label)
					}
				} else if referenceBearingField(key) {
					pointer := "/" + strings.Join(fieldRoute, "/")
					if _, admitted := classifications[pointer]; !admitted {
						return fmt.Errorf("package %s contains unclassified reference-bearing field %s", label, pointer)
					}
				}
				if err := walk(typed[key], fieldRoute, referenceChildScope(scope, route, key)); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range typed {
				if err := walk(item, append(append([]string{}, route...), "*"), scope); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(value, nil, referenceRecord)
}

// Declaration names are not instance references. Only schema applicators
// propagate schema scope; arbitrary metadata objects retain ordinary checks.
func referenceChildScope(scope referenceScope, route []string, key string) referenceScope {
	switch scope {
	case structuralFieldTree:
		if key == "variants" && slices.Equal(route, []string{"contractDefinitions", "*", "fieldTree"}) {
			return structuralFieldTree
		}
		if key == "schema" && slices.Equal(route, []string{"contractDefinitions", "*", "fieldTree", "variants", "*"}) {
			return structuralSchema
		}
	case structuralSchema:
		switch key {
		case "properties":
			return schemaProperties
		case "items", "prefixItems", "anyOf", "oneOf", "allOf", "not", "contains", "if", "then", "else", "additionalProperties", "propertyNames", "unevaluatedProperties":
			return structuralSchema
		}
	case schemaProperties:
		return structuralSchema
	}
	return referenceRecord
}

func referenceBearingField(key string) bool {
	if key == "helpCatalogFormsSource" {
		return true
	}
	lower := strings.ToLower(key)
	if lower == "cwd" {
		return true
	}
	for _, suffix := range []string{"path", "paths", "ref", "refs", "selector", "selectors"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
