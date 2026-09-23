package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestInputStructureMatchesIndependentFieldManifest(t *testing.T) {
	limits := requirementsourcemodel.DefaultLimits()
	limits.MaxCollectionItems, limits.MaxDefinitions, limits.MaxDerivations = 11, 12, 13
	limits.MaxExamplesPerScenario, limits.MaxGroups, limits.MaxMembersPerGroup = 14, 15, 16
	limits.MaxProfiles, limits.MaxScenarios, limits.MaxTerms = 17, 18, 19
	// Distinct literal values expose a projection that swaps two limit owners.
	boundaries := map[string]int{
		"max_collection_items": 11, "max_definitions": 12, "max_derivations": 13,
		"max_examples_per_scenario": 14, "max_groups": 15, "max_members_per_group": 16,
		"max_profiles": 17, "max_scenarios": 18, "max_terms": 19,
	}
	manifest := readCodecFieldManifest(t)
	want := manifestInputSchema(t, manifest, boundaries)
	got, err := InputStructure(limits)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := stablejson.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wire, want) {
		t.Fatal("source schema differs from the independent complete field/limit manifest")
	}
	again, err := InputStructure(limits)
	if err != nil || !reflect.DeepEqual(again, got) {
		t.Fatalf("nondeterministic schema: %v", err)
	}
}

func TestCoordinateCanonicalIntegerUsesTheSharedDomain(t *testing.T) {
	for _, tc := range []struct {
		text  string
		valid bool
		value int64
	}{
		{"0", true, 0}, {"-1", true, -1},
		{"9223372036854775807", true, 9223372036854775807},
		{"-9223372036854775808", true, -9223372036854775808},
		{"", false, 0}, {"-0", false, 0}, {"01", false, 0}, {"+1", false, 0},
		{"1.0", false, 0}, {"1e0", false, 0}, {" 1", false, 0}, {"1 ", false, 0},
		{"\u0661", false, 0}, {"9223372036854775808", false, 0},
		{"-9223372036854775809", false, 0}, {"000000000000000000000", false, 0},
	} {
		value, valid := parseCanonicalInt64(tc.text)
		if valid != tc.valid || (valid && value != tc.value) {
			t.Fatalf("codec coordinate %q: value=%d valid=%t", tc.text, value, valid)
		}
		_, err := jsonshape.DecimalIntegerString().Admit(tc.text, "coordinate")
		if (err == nil) != tc.valid {
			t.Fatalf("shared structural coordinate %q: %v", tc.text, err)
		}
	}
}

func TestReusableInputShapePreservesNativeStructuralDomain(t *testing.T) {
	limits := requirementsourcemodel.DefaultLimits()
	declaration, err := InputShape(limits)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Format(mustModel(t))
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(map[string]any){
		"valid":            func(map[string]any) {},
		"root unknown":     func(v map[string]any) { v["unknown"] = true },
		"required missing": func(v map[string]any) { delete(v, "groups") },
		"version spelling": func(v map[string]any) { v["schemaVersion"] = json.Number("2.0") },
		"wrong kind":       func(v map[string]any) { v["kind"] = "wrong" },
		"nullable deferral": func(v map[string]any) {
			v["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)["deferral"] = nil
		},
		"semantic-only empty members": func(v map[string]any) { v["groups"].([]any)[0].(map[string]any)["members"] = []any{} },
		"nested unknown":              func(v map[string]any) { v["groups"].([]any)[0].(map[string]any)["unknown"] = true },
		"wrong member container":      func(v map[string]any) { v["groups"].([]any)[0].(map[string]any)["members"] = true },
		"decimal spelling": func(v map[string]any) {
			v["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["start"] = "01"
		},
		"decimal wrong type": func(v map[string]any) {
			v["derivations"].([]any)[0].(map[string]any)["selector"].(map[string]any)["start"] = json.Number("1")
		},
		"boolean wrong type": func(v map[string]any) {
			v["profiles"].([]any)[0].(map[string]any)["fields"].(map[string]any)["updatePolicy"].(map[string]any)["requiresImpactDeclaration"] = "true"
		},
		"map value type": func(v map[string]any) {
			v["scenarios"].([]any)[0].(map[string]any)["examples"].([]any)[0].(map[string]any)["values"].(map[string]any)["surface"] = true
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			var raw map[string]any
			if err := decoder.Decode(&raw); err != nil {
				t.Fatal(err)
			}
			change(raw)
			nativeErr := validateShape(raw, documentShape(limits), "", nil, nil)
			owned, err := declaration.Admit(raw, "source")
			if (err == nil) != (nativeErr == nil) {
				t.Fatalf("structural domain drift: native=%v projected=%v", nativeErr, err)
			}
			if err == nil && !reflect.DeepEqual(owned, raw) {
				t.Fatal("new structural visitor normalized values or presence")
			}
		})
	}
}

func manifestInputSchema(t *testing.T, manifest codecFieldManifest, boundaries map[string]int) map[string]any {
	t.Helper()
	records := map[string]manifestRecord{}
	for _, record := range manifest.Records {
		records[record.RecordID] = record
	}
	seen := map[string]bool{}
	var fieldSchema func(manifestField) map[string]any
	recordSchema := func(id string) map[string]any {
		record, ok := records[id]
		if !ok {
			t.Fatalf("missing manifest record %s", id)
		}
		seen[id] = true
		properties := map[string]any{}
		required := []string{}
		for _, field := range record.Fields {
			properties[field.Name] = fieldSchema(field)
			if field.Required {
				required = append(required, field.Name)
			}
		}
		sort.Strings(required)
		result := map[string]any{"type": "object", "additionalProperties": false, "properties": properties}
		if len(required) != 0 {
			values := make([]any, len(required))
			for i, value := range required {
				values[i] = value
			}
			result["required"] = values
		}
		return result
	}
	fieldSchema = func(field manifestField) map[string]any {
		result := map[string]any{}
		switch {
		case strings.HasPrefix(field.Type, "record:"):
			result = recordSchema(strings.TrimPrefix(field.Type, "record:"))
		case strings.HasPrefix(field.Type, "array:"):
			result["type"] = "array"
			result["items"] = fieldSchema(manifestField{Type: strings.TrimPrefix(field.Type, "array:")})
		case field.Type == "map:string":
			result["type"] = "object"
			result["additionalProperties"] = map[string]any{"type": "string"}
		case field.Type == "decimal-int64":
			result["type"], result["x-proofkit-number-encoding"] = "string", "decimal-int64"
		case field.Type == "integer":
			result["type"], result["x-proofkit-number-encoding"] = "integer", "canonical-int64"
		case field.Type == "string" || field.Type == "boolean":
			result["type"] = field.Type
		default:
			t.Fatalf("unhandled manifest field type %s", field.Type)
		}
		if field.Constant != "" {
			result["const"] = field.Constant
			if field.Type == "integer" {
				result["const"] = json.Number(field.Constant)
			}
		}
		if field.LimitOwner != "" {
			limit, ok := boundaries[field.LimitOwner]
			if !ok {
				t.Fatalf("unhandled manifest limit %s", field.LimitOwner)
			}
			key := "maxItems"
			if field.Type == "map:string" {
				key = "maxProperties"
			}
			result[key] = json.Number(strconv.Itoa(limit))
		}
		if field.Nullable {
			return map[string]any{"anyOf": []any{map[string]any{"type": "null"}, result}}
		}
		return result
	}
	result := recordSchema(manifest.RootRecordID)
	if len(seen) != len(records) {
		t.Fatal("schema did not reach every independent manifest record")
	}
	result["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return result
}

func TestInputStructureRejectsInvalidLimitsAndUnsupportedDeclarations(t *testing.T) {
	for _, change := range []func(*requirementsourcemodel.Limits){
		func(l *requirementsourcemodel.Limits) { l.MaxGroups = 0 },
		func(l *requirementsourcemodel.Limits) { l.MaxDefinitions++ },
		func(l *requirementsourcemodel.Limits) { l.MaxTotalTextBytes = -1 },
	} {
		limits := requirementsourcemodel.DefaultLimits()
		change(&limits)
		if result, err := InputStructure(limits); err == nil || result != nil {
			t.Fatal("invalid native limits produced a schema")
		}
	}
	for _, value := range []*shape{nil, {}, {kind: shapeArray}, {kind: shapeObject, maxItems: 1}, {kind: shapeObject, dynamic: scalar(shapeBoolean)}} {
		if result, err := sourceValueShape(value); err == nil || result != (jsonshape.Shape{}) {
			t.Fatal("unsupported trusted declaration produced a schema")
		}
	}
}

func TestInputStructureNestedProjectionsAreDetached(t *testing.T) {
	first, err := InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	properties := first["properties"].(map[string]any)
	profileFields := properties["profiles"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["fields"].(map[string]any)
	profileFields["properties"].(map[string]any)["ownerId"].(map[string]any)["type"] = "boolean"
	memberFields := properties["groups"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["members"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["fields"].(map[string]any)
	if memberFields["properties"].(map[string]any)["ownerId"].(map[string]any)["type"] != "string" {
		t.Fatal("two occurrences of the shared native declaration alias in the projection")
	}
	second, err := InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	secondProfile := second["properties"].(map[string]any)["profiles"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["fields"].(map[string]any)
	if secondProfile["properties"].(map[string]any)["ownerId"].(map[string]any)["type"] != "string" {
		t.Fatal("a previous projection changed the next one")
	}
}
