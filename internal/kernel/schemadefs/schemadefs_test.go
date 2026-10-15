package schemadefs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonpointer"
)

func decode(t *testing.T, text string) map[string]any {
	t.Helper()
	root, _, err := normalize(mustJSON(t, text))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustJSON(t *testing.T, text string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func canonical(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := canonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func sharedNames(document map[string]any) []string {
	definitions, _ := document["$defs"].(map[string]any)
	names := []string{}
	for _, name := range sortedKeys(definitions) {
		if strings.HasPrefix(name, SharedPrefix) {
			names = append(names, name)
		}
	}
	return names
}

// assertEquivalentPublication checks the published properties independently of
// Hoist's internal self-check: exact inverse, strict saving, content-addressed
// names, at least two references per shared entry, and resolvable references.
func assertEquivalentPublication(t *testing.T, source, hoisted map[string]any) {
	t.Helper()
	expanded, err := Expand(hoisted)
	if err != nil {
		t.Fatalf("Expand(Hoist(S)) failed: %v", err)
	}
	if !bytes.Equal(canonical(t, expanded), canonical(t, source)) {
		t.Fatalf("Expand(Hoist(S)) != S\nS=%s\nH=%s", canonical(t, source), canonical(t, hoisted))
	}
	names := sharedNames(hoisted)
	if len(names) == 0 {
		if !bytes.Equal(canonical(t, hoisted), canonical(t, source)) {
			t.Fatal("a publication without shared definitions changed the source")
		}
		return
	}
	if len(canonical(t, hoisted)) >= len(canonical(t, source)) {
		t.Fatalf("sharing did not save bytes: %d >= %d", len(canonical(t, hoisted)), len(canonical(t, source)))
	}
	text := string(canonical(t, hoisted))
	for _, name := range names {
		entry := hoisted["$defs"].(map[string]any)[name]
		restored, err := Expand(map[string]any{"$defs": hoisted["$defs"], "allOf": []any{entry}})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(canonical(t, restored["allOf"].([]any)[0]))
		if want := SharedPrefix + hex.EncodeToString(digest[:])[:sharedDigestHexLength]; name != want {
			t.Fatalf("shared definition %s is not addressed by its source content %s", name, want)
		}
		if count := strings.Count(text, `{"$ref":"`+Reference(name)+`"}`); count < 2 {
			t.Fatalf("shared definition %s has %d references", name, count)
		}
	}
	assertReferencesResolve(t, hoisted, hoisted, hoisted)
}

func assertReferencesResolve(t *testing.T, resource map[string]any, schema map[string]any, root map[string]any) {
	t.Helper()
	if ref, present := schema["$ref"]; present {
		if _, err := Resolve(resource, ref); err != nil {
			t.Fatalf("published reference %v does not resolve: %v", ref, err)
		}
	}
	if err := eachSubschema(schema, func(_ string, value any, _ func(any)) error {
		child, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if _, embedded := child["$id"]; embedded {
			assertReferencesResolve(t, child, child, root)
			return nil
		}
		assertReferencesResolve(t, resource, child, root)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

const record = `{"type":"object","additionalProperties":false,"required":["id","label"],"properties":{"id":{"type":"string","pattern":"^[a-z]+$","maxLength":64},"label":{"type":"string","minLength":1,"maxLength":256}}}`

func TestHoistSharesRepeatedObjectSubschemasAndExpandRestoresSource(t *testing.T) {
	source := decode(t, `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"a":`+record+`,"b":`+record+`,"c":{"type":"array","items":`+record+`}}}`)
	hoisted, err := Hoist(source)
	if err != nil {
		t.Fatal(err)
	}
	if names := sharedNames(hoisted); len(names) != 1 {
		t.Fatalf("expected one shared record definition, got %v", names)
	}
	properties := hoisted["properties"].(map[string]any)
	ref := properties["a"].(map[string]any)
	if len(ref) != 1 || ref["$ref"] != Reference(sharedNames(hoisted)[0]) {
		t.Fatalf("occurrence was not replaced by a pure reference: %v", ref)
	}
	if properties["c"].(map[string]any)["items"].(map[string]any)["$ref"] != ref["$ref"] {
		t.Fatal("array item occurrence was not shared")
	}
	assertEquivalentPublication(t, source, hoisted)
}

func TestHoistDoesNotMutateItsInputAndIsDeterministic(t *testing.T) {
	text := `{"type":"object","properties":{"a":` + record + `,"b":` + record + `,"c":` + record + `}}`
	source := decode(t, text)
	before := canonical(t, source)
	first, err := Hoist(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical(t, source), before) {
		t.Fatal("Hoist mutated its input")
	}
	for range 20 {
		again, err := Hoist(decode(t, text))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical(t, again), canonical(t, first)) {
			t.Fatal("Hoist output is not byte-identical across runs")
		}
	}
}

func TestHoistNeverMovesIdentityOrDynamicScope(t *testing.T) {
	for _, keyword := range []string{"$id", "$anchor", "$dynamicAnchor", "$dynamicRef", "$recursiveAnchor", "$recursiveRef"} {
		t.Run(keyword, func(t *testing.T) {
			value, definitions := `"urn:example:scope#x"`, ""
			if keyword == "$dynamicRef" || keyword == "$recursiveRef" {
				// Dynamic references are admitted only when they name a direct
				// definition of their own resource, here a pinned root entry.
				value, definitions = `"#/$defs/item"`, `"$defs":{"item":{"type":"string"}},`
			}
			scoped := strings.Replace(record, `"type":"object"`, `"type":"object",`+fmt.Sprintf("%q", keyword)+`:`+value, 1)
			source := decode(t, `{`+definitions+`"type":"object","properties":{"a":`+scoped+`,"b":`+scoped+`}}`)
			hoisted, err := Hoist(source)
			if err != nil {
				t.Fatal(err)
			}
			// Scoped subtrees stay in place; only their unscoped members may move
			// when they live in the root resource.
			if hoisted["properties"].(map[string]any)["a"].(map[string]any)[keyword] == nil {
				t.Fatalf("subtree carrying %s was moved", keyword)
			}
			assertEquivalentPublication(t, source, hoisted)
			if keyword == "$id" && len(sharedNames(hoisted)) != 0 {
				t.Fatal("subschemas inside embedded resources were shared into the root resource")
			}
		})
	}
}

func TestHoistNeverSharesOutOfOrAcrossEmbeddedResources(t *testing.T) {
	embedded := `{"$id":"urn:example:inner","$defs":{"item":` + record + `},"type":"object","properties":{"x":{"$ref":"#/$defs/item"},"y":` + record + `,"z":` + record + `}}`
	source := decode(t, `{"type":"object","properties":{"inner":`+embedded+`,"outer":`+record+`}}`)
	hoisted, err := Hoist(source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical(t, hoisted["properties"].(map[string]any)["inner"]), canonical(t, decode(t, embedded))) {
		t.Fatal("embedded resource content changed")
	}
	if len(sharedNames(hoisted)) != 0 {
		t.Fatal("an occurrence inside an embedded resource was counted for root sharing")
	}
	assertEquivalentPublication(t, source, hoisted)
}

// A JSON-pointer fragment in $dynamicRef or $recursiveRef resolves like $ref
// (draft 2020-12 section 8.2.3.2), so every reference keyword is admitted only
// when it names a direct definition of its own resource.
func TestHoistRefusesReferencesWhoseMeaningCouldChange(t *testing.T) {
	for _, keyword := range []string{"$ref", "$dynamicRef", "$recursiveRef"} {
		sourceWith := func(ref string) map[string]any {
			return decode(t, `{"$defs":{"item":`+record+`},"type":"object","properties":{"a":{`+fmt.Sprintf("%q", keyword)+`:"`+ref+`"},"b":`+record+`,"c":`+record+`}}`)
		}
		t.Run(keyword+"/direct definition", func(t *testing.T) {
			source := sourceWith("#/$defs/item")
			hoisted, err := Hoist(source)
			if err != nil {
				t.Fatalf("Hoist refused a direct definition reference: %v", err)
			}
			if len(sharedNames(hoisted)) != 1 {
				t.Fatalf("expected the repeated record to be shared, got %v", sharedNames(hoisted))
			}
			assertEquivalentPublication(t, source, hoisted)
		})
		for name, ref := range map[string]string{
			"pointer into properties": "#/properties/a",
			"nested definition":       "#/$defs/item/properties/id",
			"missing definition":      "#/$defs/missing",
			"escaped missing token":   "#/$defs/it~1em",
			"encoded pointer slash":   "#/$defs/it%2Fem",
			"invalid escape":          "#/$defs/it~2em",
			"invalid percent":         "#/$defs/%zz",
			"anchor":                  "#item",
			"document root":           "#",
			"absolute":                "https://example.test/schema#/$defs/item",
			"relative document":       "other.json#/$defs/item",
		} {
			t.Run(keyword+"/"+name, func(t *testing.T) {
				if _, err := Hoist(sourceWith(ref)); err == nil {
					t.Fatalf("Hoist accepted %s %s", keyword, ref)
				}
			})
		}
		t.Run(keyword+"/non-text", func(t *testing.T) {
			nonText := decode(t, `{"type":"object","properties":{"a":{`+fmt.Sprintf("%q", keyword)+`:7}}}`)
			if _, err := Hoist(nonText); err == nil {
				t.Fatalf("Hoist accepted a non-text %s", keyword)
			}
		})
	}
}

// A reference to a descendant of a shareable subtree would dangle once the
// subtree moves into $defs, whichever reference keyword names it and whether
// it sits on the root or on a sibling node.
func TestHoistRefusesReferencesToShareableDescendants(t *testing.T) {
	shareable := `{"description":"` + strings.Repeat("x", 200) + `","type":"object","properties":{"id":{"type":"string"}}}`
	for _, keyword := range []string{"$ref", "$dynamicRef", "$recursiveRef"} {
		reference := fmt.Sprintf("%q", keyword) + `:"#/properties/a/properties/id"`
		for placement, text := range map[string]string{
			"root":    `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"https://example.test/root",` + reference + `,"properties":{"a":` + shareable + `,"b":` + shareable + `}}`,
			"sibling": `{"type":"object","properties":{"a":` + shareable + `,"b":` + shareable + `,"c":{` + reference + `}}}`,
		} {
			t.Run(keyword+"/"+placement, func(t *testing.T) {
				source := decode(t, text)
				if _, err := jsonpointer.Select(source, "/properties/a/properties/id"); err != nil {
					t.Fatalf("the reference target is absent from the source: %v", err)
				}
				if hoisted, err := Hoist(source); err == nil {
					t.Fatalf("Hoist accepted %s to a shareable descendant: %s", keyword, canonical(t, hoisted))
				}
			})
		}
	}
}

// Encoded spellings of a direct definition keep naming it after a move.
func TestHoistKeepsEncodedDirectDefinitionReferences(t *testing.T) {
	refs := `{"type":"object","properties":{"p":{"$ref":"#/$defs/it%65m"},"q":{"$ref":"#/$defs/a~1b"},"note":{"type":"string","maxLength":4096}},"required":["p","q"]}`
	source := decode(t, `{"$defs":{"item":`+record+`,"a/b":true},"type":"object","properties":{"x":`+refs+`,"y":`+refs+`,"z":`+refs+`}}`)
	hoisted, err := Hoist(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(sharedNames(hoisted)) != 1 {
		t.Fatalf("encoded references blocked sharing: %v", sharedNames(hoisted))
	}
	assertEquivalentPublication(t, source, hoisted)
}

func TestHoistRefusesReservedNamesAndEmptyRootDefinitions(t *testing.T) {
	for name, text := range map[string]string{
		"reserved root definition":    `{"$defs":{"shared-0000000000000000":{"type":"string"}},"type":"object"}`,
		"reserved nested definition":  `{"type":"object","properties":{"a":{"$defs":{"shared-x":{}},"type":"object"}}}`,
		"reserved reference in data":  `{"type":"object","const":{"$ref":"#/$defs/shared-0000000000000000"}}`,
		"empty root definitions":      `{"$defs":{},"type":"object","properties":{"a":` + record + `,"b":` + record + `}}`,
		"non-object root definitions": `{"$defs":[],"type":"object"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Hoist(decode(t, text)); err == nil {
				t.Fatal("Hoist accepted a source that Expand could not invert")
			}
		})
	}
}

// Keyword containers and data are never schema positions, even when they are
// large, repeated objects or arrays.
func TestHoistNeverSharesKeywordContainersOrData(t *testing.T) {
	members := []string{}
	enum := []string{}
	for index := range 40 {
		members = append(members, fmt.Sprintf(`"field%02d":true`, index))
		enum = append(enum, fmt.Sprintf(`"value-%02d-with-a-long-literal"`, index))
	}
	properties := `{` + strings.Join(members, ",") + `}`
	literal := `{"type":"object","additionalProperties":false,"properties":` + properties + `}`
	for name, member := range map[string]string{
		"properties map":   `{"description":"%s","properties":` + properties + `}`,
		"enum array":       `{"description":"%s","enum":[` + strings.Join(enum, ",") + `]}`,
		"const object":     `{"description":"%s","const":` + literal + `}`,
		"default object":   `{"description":"%s","default":` + literal + `}`,
		"examples array":   `{"description":"%s","examples":[` + literal + `]}`,
		"required array":   `{"description":"%s","required":[` + strings.Join(enum, ",") + `]}`,
		"unknown keyword":  `{"description":"%s","x-proofkit-extension":` + literal + `}`,
		"legacy container": `{"description":"%s","definitions":{"a":` + literal + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			source := decode(t, `{"type":"object","properties":{"a":`+fmt.Sprintf(member, "first")+`,"b":`+fmt.Sprintf(member, "second")+`,"c":`+fmt.Sprintf(member, "third")+`}}`)
			hoisted, err := Hoist(source)
			if err != nil {
				t.Fatal(err)
			}
			if len(sharedNames(hoisted)) != 0 {
				t.Fatalf("a keyword container or data value was shared: %s", canonical(t, hoisted["$defs"]))
			}
			assertEquivalentPublication(t, source, hoisted)
		})
	}
}

// Sharing applies exactly when count*length > count*reference + entry, with the
// 42-byte reference and the 23-byte name used by every shared definition.
func TestHoistAppliesOnlyWhenSharingSavesBytes(t *testing.T) {
	padded := func(length int) string {
		return `{"description":"` + strings.Repeat("x", length-len(`{"description":""}`)) + `"}`
	}
	for _, test := range []struct {
		name        string
		definitions string
		count       int
		length      int
		shared      bool
	}{
		{"two copies, new $defs, break-even", "", 2, 121, false},
		{"two copies, new $defs, one byte over", "", 2, 122, true},
		{"two copies, existing $defs, break-even", `"$defs":{"keep":true},`, 2, 111, false},
		{"two copies, existing $defs, one byte over", `"$defs":{"keep":true},`, 2, 112, true},
		{"three copies, new $defs, below", "", 3, 81, false},
		{"three copies, new $defs, above", "", 3, 82, true},
		{"single copy never shares", "", 1, 4096, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			members := []string{}
			for index := range test.count {
				members = append(members, fmt.Sprintf(`"p%d":%s`, index, padded(test.length)))
			}
			source := decode(t, `{`+test.definitions+`"properties":{`+strings.Join(members, ",")+`}}`)
			hoisted, err := Hoist(source)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(sharedNames(hoisted)) == 1; got != test.shared {
				t.Fatalf("shared=%v, want %v (source %d bytes, published %d bytes)", got, test.shared, len(canonical(t, source)), len(canonical(t, hoisted)))
			}
			assertEquivalentPublication(t, source, hoisted)
		})
	}
}

func TestHoistNestedSharingIsAcyclicAndKeepsExistingReferences(t *testing.T) {
	inner := `{"type":"object","additionalProperties":false,"required":["ref"],"properties":{"ref":{"$ref":"#/$defs/item"},"note":{"type":"string","maxLength":4096,"description":"a nested shared note with enough text to be worth sharing"}}}`
	outer := `{"type":"array","maxItems":32,"items":{"type":"object","properties":{"first":` + inner + `,"second":{"type":"array","items":` + inner + `}}}}`
	source := decode(t, `{"$defs":{"item":{"type":"object","properties":{"copy":`+inner+`,"id":{"type":"string"}}}},"type":"object","properties":{"a":`+outer+`,"b":`+outer+`,"c":`+inner+`}}`)
	hoisted, err := Hoist(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(sharedNames(hoisted)) != 2 {
		t.Fatalf("expected the outer and the nested subtree to be shared, got %v", sharedNames(hoisted))
	}
	definitions := hoisted["$defs"].(map[string]any)
	if _, kept := definitions["item"]; !kept {
		t.Fatal("existing root definition was removed")
	}
	if definitions["item"].(map[string]any)["properties"].(map[string]any)["copy"].(map[string]any)["$ref"] == nil {
		t.Fatal("subschemas inside pinned root definitions were not shared")
	}
	assertEquivalentPublication(t, source, hoisted)
}

func TestExpandRefusesCyclesMissingTargetsAndImpureAliases(t *testing.T) {
	for name, text := range map[string]string{
		"cycle":         `{"$defs":{"shared-a":{"items":{"$ref":"#/$defs/shared-b"}},"shared-b":{"items":{"$ref":"#/$defs/shared-a"}}},"items":{"$ref":"#/$defs/shared-a"}}`,
		"self cycle":    `{"$defs":{"shared-a":{"not":{"$ref":"#/$defs/shared-a"}}},"items":{"$ref":"#/$defs/shared-a"}}`,
		"missing":       `{"items":{"$ref":"#/$defs/shared-missing"}}`,
		"impure alias":  `{"$defs":{"shared-a":{"type":"string"}},"items":{"$ref":"#/$defs/shared-a","maxLength":3}}`,
		"missing entry": `{"$defs":{"keep":true},"items":{"$ref":"#/$defs/shared-a"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Expand(decode(t, text)); err == nil {
				t.Fatal("Expand accepted an invalid shared reference graph")
			}
		})
	}
	// Expand leaves embedded resources alone, including their own definitions.
	resource := decode(t, `{"properties":{"r":{"$id":"urn:x","$defs":{"shared-a":{"type":"string"}},"items":{"$ref":"#/$defs/shared-a"}}}}`)
	expanded, err := Expand(resource)
	if err != nil || !bytes.Equal(canonical(t, expanded), canonical(t, resource)) {
		t.Fatalf("Expand changed an embedded resource: %v", err)
	}
}

func TestResolveAdmitsOnlyDirectLocalDefinitions(t *testing.T) {
	resource := decode(t, `{"$defs":{"item":{"type":"string"},"flag":true,"bad":3,"a/b":false}}`)
	for ref, ok := range map[any]bool{
		"#/$defs/item": true, "#/$defs/flag": true, "#/$defs/it%65m": true, "#/$defs/a~1b": true,
		"#/$defs/bad": false, "#/$defs/missing": false, "#/$defs/": false, "#/$defs/a/b": false, "#/$defs/a%2Fb": false,
		"#/$defs/a~2b": false, "#/$defs/%zz": false, "#/properties/item": false, "#item": false, "item.json": false, 7: false,
	} {
		if _, err := Resolve(resource, ref); (err == nil) != ok {
			t.Fatalf("Resolve(%v) error=%v, want ok=%v", ref, err, ok)
		}
	}
}

// Generated documents mix repeated records, embedded resources, existing
// definitions and references. Every one must publish an exact inverse.
func TestHoistRandomDocumentsPublishExactInverses(t *testing.T) {
	for seed := range int64(300) {
		random := rand.New(rand.NewSource(seed))
		source := decode(t, randomDocument(random))
		hoisted, err := Hoist(source)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		assertEquivalentPublication(t, source, hoisted)
		again, err := Hoist(decode(t, string(canonical(t, source))))
		if err != nil || !bytes.Equal(canonical(t, again), canonical(t, hoisted)) {
			t.Fatalf("seed %d: Hoist is not deterministic: %v", seed, err)
		}
	}
}

func randomDocument(random *rand.Rand) string {
	fragments := []string{
		record,
		`{"type":"string","maxLength":256,"pattern":"^[A-Za-z][A-Za-z0-9_-]*$"}`,
		`{"type":"integer","minimum":0,"maximum":9223372036854775807,"x-proofkit-number-encoding":"canonical-int64"}`,
		`{"type":"object","properties":{"ref":{"$ref":"#/$defs/base"},"tag":{"enum":["a","b","c"]}},"required":["ref"]}`,
		`{"anyOf":[{"type":"null"},` + record + `]}`,
		`{"$id":"urn:example:embedded","$defs":{"local":` + record + `},"type":"array","items":{"$ref":"#/$defs/local"}}`,
		`{"type":"object","properties":{"anchor":{"$anchor":"spot","type":"string"}}}`,
		`{"const":{"type":"object","properties":{"x":{"type":"string"}}},"description":"data, not a schema"}`,
	}
	var schema func(depth int) string
	schema = func(depth int) string {
		if depth == 0 || random.Intn(4) == 0 {
			return fragments[random.Intn(len(fragments))]
		}
		switch random.Intn(5) {
		case 0:
			return `{"type":"array","items":` + schema(depth-1) + `}`
		case 1:
			return `{"oneOf":[` + schema(depth-1) + `,` + schema(depth-1) + `]}`
		case 2:
			return `{"if":` + schema(depth-1) + `,"then":` + schema(depth-1) + `,"else":` + schema(depth-1) + `}`
		case 3:
			return `{"type":"array","prefixItems":[` + schema(depth-1) + `],"items":false}`
		default:
			members := []string{}
			for index := range 1 + random.Intn(4) {
				members = append(members, fmt.Sprintf(`"m%d":%s`, index, schema(depth-1)))
			}
			return `{"type":"object","additionalProperties":false,"properties":{` + strings.Join(members, ",") + `}}`
		}
	}
	members := []string{}
	for index := range 2 + random.Intn(5) {
		members = append(members, fmt.Sprintf(`"r%d":%s`, index, schema(3)))
	}
	return `{"$schema":"https://json-schema.org/draft/2020-12/schema","$defs":{"base":` + schema(2) + `},"type":"object","properties":{` + strings.Join(members, ",") + `}}`
}
