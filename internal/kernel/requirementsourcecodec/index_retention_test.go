package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRejectedContainerRetainsOnlyItsBoundary(t *testing.T) {
	for _, count := range []int{16, 128, 1024} {
		for _, kind := range []string{"unknown-array", "unknown-object", "wrong-array", "wrong-object"} {
			t.Run(fmt.Sprintf("%s/%d", kind, count), func(t *testing.T) {
				key, code := strings.Repeat("q", 4096), "unknown_field"
				if strings.HasPrefix(kind, "wrong-") {
					key, code = "sourceId", "invalid_type"
				}
				var value strings.Builder
				opening, closing := "[", "]"
				if strings.HasSuffix(kind, "object") {
					opening, closing = "{", "}"
				}
				value.WriteString(opening)
				for i := 0; i < count; i++ {
					if i > 0 {
						value.WriteString(",")
					}
					if opening == "{" {
						value.WriteString(strconv.Quote(strconv.Itoa(i)) + ":")
					}
					value.WriteString("0")
				}
				value.WriteString(closing)
				source := []byte(`{` + strconv.Quote(key) + `:` + value.String() + `}`)
				expected := documentShape(compactTestModelLimits())
				indexed, err := indexJSON(source, DefaultLimits(), expected)
				if err != nil {
					t.Fatal(err)
				}
				if len(indexed.locations) != 2 {
					t.Fatal("rejected descendants retained source-map paths")
				}
				if got := reflect.ValueOf(indexed.value.(map[string]any)[key]); got.Len() != 0 {
					t.Fatal("rejected container retained child values")
				}
				location := indexed.locations[joinPointer("", key)]
				if string(source[location.value.Start:location.value.End]) != value.String() {
					t.Fatal("retained boundary span changed")
				}
				if ErrorCode(validateShape(indexed.value, expected, "", indexed.locations, source)) != code {
					t.Fatal("shape rejection changed")
				}
			})
		}
	}
}

func TestDiscardedBranchesPreserveLexicalFailuresAndRecovery(t *testing.T) {
	good := mustPayload(t)
	baseline, err := Parse(good)
	if err != nil {
		t.Fatal(err)
	}
	want := baseline.Model.Atomic()
	cases := []struct {
		name, source, code, path, token string
	}{
		{"unknown duplicate", `{"unknown":{"x":0,"x":1}}`, "duplicate_field", "/<unknown>", `"x"`},
		{"wrong object duplicate", `{"sourceId":{"x":0,"x":1}}`, "duplicate_field", "/sourceId", `"x"`},
		{"unknown array duplicate", `{"unknown":[{"x":0,"x":1}]}`, "duplicate_field", "/<unknown>/0", `"x"`},
		{"wrong root duplicate", `[{"x":0,"x":1}]`, "duplicate_field", "/0", `"x"`},
		{"unknown unicode", `{"unknown":["\ud800"]}`, "invalid_unicode_escape", "/<unknown>/0", `"\ud800"`},
		{"wrong array unicode", `{"sourceId":["\ud800"]}`, "invalid_unicode_escape", "/sourceId/0", `"\ud800"`},
		{"lexical before shape", `{"sourceId":null,"unknown":{"x":0,"x":1}}`, "duplicate_field", "/<unknown>", `"x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := []byte(tc.source)
			result, err := Parse(source)
			assertDiagnostic(t, err, tc.code, tc.path)
			if !reflect.DeepEqual(result, Result{}) || string(source) != tc.source {
				t.Fatal("failure returned state or changed source")
			}
			start := int64(strings.LastIndex(tc.source, tc.token))
			if got := err.(*Error).Diagnostic().Span; got != (ByteSpan{Start: start, End: start + int64(len(tc.token))}) {
				t.Fatalf("diagnostic span = %#v", got)
			}
			recovered, recoveryErr := Parse(good)
			if recoveryErr != nil || !reflect.DeepEqual(recovered.Model.Atomic(), want) {
				t.Fatal("valid recovery changed")
			}
			assertFuzzSourceMap(t, good, recovered.SourceMap)
		})
	}
	nested := []byte(`{"unknown":` + strings.Repeat("[", defaultMaxNesting) + "0" + strings.Repeat("]", defaultMaxNesting) + "}")
	_, err = Parse(nested)
	assertDiagnostic(t, err, "nesting_limit_exceeded", "/<unknown>"+strings.Repeat("/0", defaultMaxNesting-1))
	_, err = Parse([]byte(`{"unknown":[0,]}`))
	assertDiagnostic(t, err, "invalid_syntax", "")
}

func TestDynamicMapWrongContainerKeepsDiagnosticLocation(t *testing.T) {
	source := mutateRoot(t, mustPayload(t), func(root map[string]any) {
		values := root["scenarios"].([]any)[0].(map[string]any)["examples"].([]any)[0].(map[string]any)["values"].(map[string]any)
		values["surface"] = json.RawMessage(`{"nested":["\ud800"]}`)
	})
	_, err := Parse(source)
	assertDiagnostic(t, err, "invalid_unicode_escape", "/scenarios/0/examples/0/values/<entry>/<unknown>/0")
	start := int64(bytes.Index(source, []byte(`"\ud800"`)))
	if err.(*Error).Diagnostic().Span != (ByteSpan{Start: start, End: start + 8}) {
		t.Fatal("nested dynamic-map scalar span changed")
	}
}
