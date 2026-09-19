package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestScenarioDiagnosticRolesDoNotCollide(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, role := range []string{"aggregate", "structural-position", "position", "identity"} {
			t.Run(fmt.Sprintf("%s/reverse=%t", role, reverse), func(t *testing.T) {
				payload := mutateRoot(t, mustPayload(t), func(root map[string]any) {
					first := root["scenarios"].([]any)[0].(map[string]any)
					first["scenarioId"] = "examples"
					second := make(map[string]any, len(first))
					for key, value := range first {
						second[key] = value
					}
					second["scenarioId"] = "other"
					values := []any{first, second}
					if reverse {
						slices.Reverse(values)
					}
					root["scenarios"] = values
				})
				if _, err := Parse(payload); err != nil {
					t.Fatalf("positive control: %v", err)
				}
				limits := requirementsourcemodel.DefaultLimits()
				path, code := "/scenarios/examples", "example_budget_exceeded"
				var object map[string]json.RawMessage
				if err := json.Unmarshal(payload, &object); err != nil {
					t.Fatal(err)
				}
				expected := object["scenarios"]
				occurrences := 1
				switch role {
				case "aggregate":
					limits.MaxExamples = 3
				case "structural-position":
					limits.MaxExamplesPerScenario = 1
					path, code = "/scenarios/0/examples", "collection_limit_exceeded"
					var scenarios []map[string]json.RawMessage
					if err := json.Unmarshal(expected, &scenarios); err != nil {
						t.Fatal(err)
					}
					expected = scenarios[0]["examples"]
					occurrences = 2
				case "position", "identity":
					index := 0
					if reverse {
						index = 1
					}
					payload = mutateRoot(t, payload, func(root map[string]any) {
						scenario := root["scenarios"].([]any)[index].(map[string]any)
						if role == "position" {
							scenario["actionSequence"] = []any{"FIXME position sentinel"}
						} else {
							scenario["nonClaimRefs"] = []any{"NCL-MISSING"}
						}
					})
					path, code = fmt.Sprintf("/scenarios/%d/nonClaimRefs", index), "dangling_nonclaim_ref"
					expected = []byte(`["NCL-MISSING"]`)
					if role == "position" {
						path, code = fmt.Sprintf("/scenarios/%d/actionSequence/0", index), "placeholder_text"
						expected = []byte(`"FIXME position sentinel"`)
					}
				}
				_, err := ParseWithLimits(payload, DefaultLimits(), limits)
				assertDiagnostic(t, err, code, path)
				span := err.(*Error).Diagnostic().Span
				if bytes.Count(payload, expected) != occurrences {
					t.Fatal("fixture occurrence count differs")
				}
				start := bytes.Index(payload, expected)
				want := ByteSpan{Start: int64(start), End: int64(start + len(expected))}
				if span != want {
					t.Fatalf("diagnostic span = %#v, want original occurrence %#v", span, want)
				}
			})
		}
	}
}

func TestModelPathRoleSelectsOnlyQuotedIdentities(t *testing.T) {
	// Deliberately ambiguous spellings isolate the private route protocol;
	// this wire fixture does not claim model admission for every root.
	wire := document{
		Profiles:            []profile{{ProfileID: "examples"}, {ProfileID: "0"}},
		NonClaimDefinitions: []nonClaimDefinition{{NonClaimID: "examples"}, {NonClaimID: "0"}},
		Vocabulary:          []vocabularyTerm{{TermID: "examples"}, {TermID: "0"}},
		Scenarios:           []scenario{{ScenarioID: "examples"}, {ScenarioID: "0"}},
		Derivations:         []derivation{{DerivationID: "examples"}, {DerivationID: "0"}},
	}
	for _, root := range []string{"profiles", "nonClaimDefinitions", "vocabulary", "scenarios", "derivations"} {
		for _, item := range []struct{ suffix, want string }{
			{"", ""}, {".examples", "/examples"}, {"[0].examples", "/0/examples"}, {"[1].examples", "/1/examples"},
			{`["examples"].nonClaimRefs`, "/0/nonClaimRefs"},
			{`["0"].nonClaimRefs`, "/1/nonClaimRefs"},
		} {
			t.Run(root+item.suffix, func(t *testing.T) {
				got := resolveModelPath(wire, root+item.suffix)
				want := "/" + root + item.want
				if got.lookup != want || got.reported != want {
					t.Fatalf("resolved %#v, want %s", got, want)
				}
			})
		}
	}
}
