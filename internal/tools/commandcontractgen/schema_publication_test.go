package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/schemadefs"
	"github.com/research-engineering/agentic-proofkit/internal/tools/installedclicontract"
)

// equalPublishedSchema compares a published variant schema with its native
// owner schema after expanding the shared subtrees, canonically.
func equalPublishedSchema(published any, native map[string]any) bool {
	schema, ok := published.(map[string]any)
	if !ok {
		return false
	}
	expanded, err := schemadefs.Expand(schema)
	if err != nil {
		return false
	}
	left, leftErr := canonicalJSON(expanded)
	right, rightErr := canonicalJSON(native)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

// mutatePublishedSchema applies a drift at a native schema location and
// republishes it, so a refusal can only come from the drift itself.
func mutatePublishedSchema(t *testing.T, variant map[string]any, mutate func(schema map[string]any)) {
	t.Helper()
	expanded, err := schemadefs.Expand(variant["schema"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	mutate(expanded)
	if variant["schema"], err = schemadefs.Hoist(expanded); err != nil {
		t.Fatal(err)
	}
}

// Every published structural definition expands to the schemas its native
// owner builds (computed here without definition()), shares only when that
// saves bytes, and the whole contract stays below the installed carrier bound.
func TestPublishedDefinitionsExpandToNativeOwnersAndSaveBytes(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	content, err := os.ReadFile(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(content) > installedclicontract.MaximumContractBytes {
		t.Fatalf("published contract has %d bytes, above %d", len(content), installedclicontract.MaximumContractBytes)
	}
	published := map[string]map[string]any{}
	for _, raw := range readFixtureContract(t, root)["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		published[definition["definitionId"].(string)] = definition
	}
	saved, sharedVariants := 0, 0
	for _, owner := range nativeStructures() {
		definition, ok := published[owner.id]
		if !ok {
			t.Fatalf("native owner %s is not published", owner.id)
		}
		builders := owner.variants
		if len(builders) == 0 {
			builders = []nativeStructureVariant{{id: "01-root", schema: owner.schema}}
		}
		variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
		if len(variants) != len(builders) {
			t.Fatalf("%s publishes %d variants, owner has %d", owner.id, len(variants), len(builders))
		}
		for index, builder := range builders {
			variant := variants[index].(map[string]any)
			native, err := builder.schema()
			if err != nil {
				t.Fatal(err)
			}
			if variant["variantId"] != builder.id || !equalPublishedSchema(variant["schema"], native) {
				t.Fatalf("%s variant %s does not expand to its native owner schema", owner.id, builder.id)
			}
			publishedBytes, err := canonicalJSON(variant["schema"])
			if err != nil {
				t.Fatal(err)
			}
			nativeBytes, err := canonicalJSON(native)
			if err != nil {
				t.Fatal(err)
			}
			definitions, _ := variant["schema"].(map[string]any)["$defs"].(map[string]any)
			shared := false
			for name := range definitions {
				shared = shared || strings.HasPrefix(name, schemadefs.SharedPrefix)
			}
			switch {
			case shared && len(publishedBytes) >= len(nativeBytes):
				t.Fatalf("%s variant %s shares subtrees without saving bytes", owner.id, builder.id)
			case !shared && !bytes.Equal(publishedBytes, nativeBytes):
				t.Fatalf("%s variant %s changed without sharing", owner.id, builder.id)
			case shared:
				sharedVariants++
			}
			saved += len(nativeBytes) - len(publishedBytes)
		}
	}
	if saved <= 0 || sharedVariants == 0 {
		t.Fatalf("publication saved %d bytes in %d variants", saved, sharedVariants)
	}
	t.Logf("shared variants=%d saved bytes=%d contract bytes=%d", sharedVariants, saved, len(content))
}

// The --check path admits a published definition only when it is exactly the
// shared publication of its native owner; coherently rehashed tampering with
// the shared form itself is refused like any other drift.
func TestCheckRefusesTamperedSharedPublication(t *testing.T) {
	owner, ok := nativeStructureOwner("proofkit.capability-map-admission.output.v1.json-schema")
	if !ok {
		t.Fatal("missing owner")
	}
	for _, mutation := range []string{"valid", "changed-entry", "dropped-entry", "cycle", "unshared", "inlined-once", "renamed-entry"} {
		t.Run(mutation, func(t *testing.T) {
			definition, err := owner.definition()
			if err != nil {
				t.Fatal(err)
			}
			variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
			schema := variant["schema"].(map[string]any)
			definitions := schema["$defs"].(map[string]any)
			names := []string{}
			for _, name := range sortedKeys(definitions) {
				if strings.HasPrefix(name, schemadefs.SharedPrefix) {
					names = append(names, name)
				}
			}
			if len(names) < 2 {
				t.Fatal("fixture variant has too few shared definitions to tamper with")
			}
			first := definitions[names[0]].(map[string]any)
			switch mutation {
			case "changed-entry":
				first["description"] = "tampered shared definition"
			case "dropped-entry":
				delete(definitions, names[0])
			case "cycle":
				first["not"] = map[string]any{"$ref": schemadefs.Reference(names[0])}
			case "unshared":
				expanded, err := schemadefs.Expand(schema)
				if err != nil {
					t.Fatal(err)
				}
				variant["schema"] = expanded
			case "inlined-once":
				// Inline one reference only: equivalent, but not the canonical publication.
				inlined := false
				var walk func(any)
				walk = func(value any) {
					switch typed := value.(type) {
					case map[string]any:
						for key, member := range typed {
							if ref, ok := member.(map[string]any); ok && !inlined && len(ref) == 1 && ref["$ref"] == schemadefs.Reference(names[0]) {
								typed[key] = cloneJSONValue(first)
								inlined = true
								continue
							}
							walk(member)
						}
					case []any:
						for _, member := range typed {
							walk(member)
						}
					}
				}
				walk(schema)
				if !inlined {
					t.Fatal("no reference to inline")
				}
			case "renamed-entry":
				source := mustExpand(t, schema)
				renamed := schemadefs.SharedPrefix + "0000000000000000"
				definitions[renamed] = definitions[names[0]]
				delete(definitions, names[0])
				encoded, err := canonicalJSON(schema)
				if err != nil {
					t.Fatal(err)
				}
				var decoded map[string]any
				decoder := json.NewDecoder(bytes.NewReader(bytes.ReplaceAll(encoded, []byte(schemadefs.Reference(names[0])), []byte(schemadefs.Reference(renamed)))))
				decoder.UseNumber()
				if err := decoder.Decode(&decoded); err != nil {
					t.Fatal(err)
				}
				if !equalPublishedSchema(decoded, source) {
					t.Fatal("renamed fixture is not equivalent; the control would prove nothing")
				}
				variant["schema"] = decoded
			}
			delete(definition, "canonicalDigest")
			encoded, err := canonicalJSON(definition)
			if err != nil {
				t.Fatal(err)
			}
			definition["canonicalDigest"] = sha256Digest(encoded)
			_, err = admitDefinitions(map[string]any{"contractDefinitions": []any{definition}})
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("%s: admission error %v", mutation, err)
			}
		})
	}
}

func mustExpand(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	expanded, err := schemadefs.Expand(schema)
	if err != nil {
		t.Fatal(err)
	}
	return expanded
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, member := range typed {
			result[key] = cloneJSONValue(member)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, member := range typed {
			result[index] = cloneJSONValue(member)
		}
		return result
	default:
		return value
	}
}
