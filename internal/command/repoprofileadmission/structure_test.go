package repoprofileadmission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestRepoProfileOutputsSelectExactlyTheirStateBranch(t *testing.T) {
	cases := []struct {
		name   string
		passed bool
		mutate func(map[string]any)
	}{
		{"passed", true, nil},
		{"root-package-mismatch", false, func(input map[string]any) { repoPath(input, "facts")["rootPackageName"] = "other-root" }},
		{"many-failures", false, func(input map[string]any) {
			repoPath(input, "facts")["trackedFiles"] = []any{}
			repoPath(input, "profile", "requirements")["idPattern"] = "("
			repoPath(input, "profile", "documents")["generatedArtifacts"] = []any{map[string]any{"generator": "gen.go", "path": "out.json", "sourceOfTruth": []any{"in.json"}}}
		}},
		{"argv-policy-failure", false, func(input map[string]any) {
			repoPath(input, "profile")["commandMatchers"].([]any)[0].(map[string]any)["allowedArgv"] = []any{" "}
		}},
		{"class-policy", true, func(input map[string]any) {
			repoPath(input, "policy", "environmentPolicy")["environmentClassPolicies"] = []any{map[string]any{"credentialClass": "none", "environmentClass": "local-go", "networkPolicy": "none"}}
			input["schemaVersion"] = json.Number("1")
		}},
		{"duplicate-builtin-claim", true, func(input map[string]any) {
			repoPath(input, "profile")["nonClaims"] = []any{boundaryNonClaims[1]}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validRepoProfileInput()
			if test.mutate != nil {
				test.mutate(input)
			}
			record, code, err := Build(input)
			if err != nil || (code == 0) != test.passed {
				t.Fatalf("native phase changed: code=%d err=%v", code, err)
			}
			value := repoWireValue(t, record.JSONValue())
			if err := OutputShape().CheckGenerated(value, "report"); err != nil {
				t.Fatal(err)
			}
			for _, passed := range []bool{true, false} {
				if (reportShape(passed).CheckGenerated(value, "branch") == nil) != (passed == test.passed) {
					t.Fatalf("branch passed=%t selection drifted", passed)
				}
			}
			if value["reportId"] != reportKind {
				t.Fatal("reportId is not the fixed structural identity")
			}
			claims := value["nonClaims"].([]any)
			if err := jsonshape.Array(canonicalTextShape(), len(boundaryNonClaims)).CheckGenerated(claims, "nonClaims"); err != nil {
				t.Fatal(err)
			}
			for index := 1; index < len(claims); index++ {
				if claims[index-1].(string) >= claims[index].(string) {
					t.Fatal("report nonClaims are not sorted unique")
				}
			}
		})
	}
}

func TestRepoProfileOutputRejectsCarrierDrift(t *testing.T) {
	input := validRepoProfileInput()
	repoPath(input, "facts")["rootPackageName"] = "other-root"
	record, _, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"passed-with-failure-rule": func(value map[string]any) { value["state"] = "passed" },
		"rule-id":                  func(value map[string]any) { repoRule(value)["ruleId"] = reportKind + ".failure.1" },
		"rule-status":              func(value map[string]any) { repoRule(value)["status"] = "passed" },
		"rule-diagnostics": func(value map[string]any) {
			repoRule(value)["diagnostics"] = []any{map[string]any{"key": "x", "value": 1}}
		},
		"root-diagnostics": func(value map[string]any) { value["diagnostics"] = []any{map[string]any{"key": "x", "value": 1}} },
		"empty-rules":      func(value map[string]any) { value["ruleResults"] = []any{} },
		"zero-environment-classes": func(value map[string]any) {
			value["summary"].(map[string]any)["environmentClassCount"] = json.Number("0")
		},
		"report-kind": func(value map[string]any) { value["reportKind"] = "proofkit.repo-profile-admission" },
	} {
		t.Run(name, func(t *testing.T) {
			value := repoWireValue(t, record.JSONValue())
			mutate(value)
			if OutputShape().CheckGenerated(value, "report") == nil {
				t.Fatal("drifted report admitted")
			}
		})
	}
}

func TestRepoProfileInputShapeAgreesWithNativeAdmission(t *testing.T) {
	type inputCase struct {
		name, class string
		mutate      func(map[string]any)
	}
	set := func(value any, path ...string) func(map[string]any) {
		return func(input map[string]any) { repoPath(input, path[:len(path)-1]...)[path[len(path)-1]] = value }
	}
	remove := func(path ...string) func(map[string]any) {
		return func(input map[string]any) { delete(repoPath(input, path[:len(path)-1]...), path[len(path)-1]) }
	}
	matcher := func(key string, value any) func(map[string]any) {
		return func(input map[string]any) {
			repoPath(input, "profile")["commandMatchers"].([]any)[0].(map[string]any)[key] = value
		}
	}
	cases := []inputCase{
		{"fixture", "accept", func(map[string]any) {}},
		{"version-one", "accept", set(json.Number("1"), "schemaVersion")},
		{"padded-vocabulary", "accept", func(input map[string]any) {
			matcher("kind", "\u3000exact_argv\t")(input)
			matcher("networkPolicy", " none")(input)
			matcher("credentialClass", "none\u0085")(input)
		}},
		{"padded-text", "accept", set(" \texample-root\u2028", "profile", "repository", "rootPackageName")},
		{"blank-argv-token", "accept", matcher("allowedArgv", []any{" "})},
		{"python-matcher", "accept", func(input map[string]any) {
			repoPath(input, "profile")["commandMatchers"] = []any{map[string]any{"id": "py", "kind": "python_pytest_contract", "allowedTestPathGlobs": []any{"tests/*.py"},
				"credentialClass": "none", "networkPolicy": "none", "parallelGroup": "local"}}
		}},
		{"null-class-policies", "accept", set(nil, "policy", "environmentPolicy", "environmentClassPolicies")},
		{"class-policies", "accept", set([]any{map[string]any{"credentialClass": " live-cloud", "environmentClass": "a", "networkPolicy": "external "}}, "policy", "environmentPolicy", "environmentClassPolicies")},
		{"absent-pattern", "accept", remove("policy", "packageNamePattern")},
		{"pattern", "accept", set("^@scope/", "policy", "packageNamePattern")},
		{"unsorted-root-scripts", "accept", set([]any{"test", "build"}, "facts", "rootScripts")},
		{"padded-tracked-file", "accept", set([]any{" docs/INDEX.md", "docs/contracts/bindings.json", "docs/docs-policy.yaml", "docs/specs/example/requirements.v1.json"}, "facts", "trackedFiles")},
		{"empty-allowed-lists", "accept", func(input map[string]any) {
			repoPath(input, "profile", "proofs")["retiredProofLikePaths"] = []any{}
			repoPath(input, "facts")["packageScripts"] = []any{map[string]any{"packageName": "pkg", "scripts": []any{}}}
		}},
		{"version-two", "structural", set(json.Number("2"), "schemaVersion")},
		{"version-null", "structural", set(nil, "schemaVersion")},
		{"version-text", "structural", set("1", "schemaVersion")},
		{"version-decimal", "structural", set(json.Number("1.0"), "schemaVersion")},
		{"profile-schema", "structural", set("proofkit.repo-profile.v2", "profile", "schema")},
		{"unknown-kind", "structural", matcher("kind", "bun_script")},
		{"unknown-network", "structural", matcher("networkPolicy", "internet")},
		{"unknown-credential", "structural", matcher("credentialClass", "token")},
		{"inner-space-kind", "structural", matcher("kind", "exact _argv")},
		{"empty-argv", "structural", matcher("allowedArgv", []any{})},
		{"empty-argv-token", "structural", matcher("allowedArgv", []any{""})},
		{"null-argv", "structural", matcher("allowedArgv", nil)},
		{"null-scripts", "structural", matcher("allowedScripts", nil)},
		{"empty-scripts", "structural", matcher("allowedScripts", []any{})},
		{"blank-matcher-id", "structural", matcher("id", " ")},
		{"blank-text", "structural", set("\u3000", "profile", "documents", "policyPath")},
		{"empty-languages", "structural", set([]any{}, "profile", "repository", "primaryLanguages")},
		{"empty-claims", "structural", set([]any{}, "profile", "nonClaims")},
		{"empty-spec-globs", "structural", set([]any{}, "profile", "requirements", "specGlobs")},
		{"empty-environment-classes", "structural", set([]any{}, "profile", "proofs", "environmentClasses")},
		{"empty-proof-paths", "structural", set([]any{}, "profile", "proofs", "proofLikePaths")},
		{"null-artifacts", "structural", set(nil, "profile", "documents", "generatedArtifacts")},
		{"blank-tracked-file", "structural", set([]any{" "}, "facts", "trackedFiles")},
		{"object-class-policies", "structural", set(map[string]any{}, "policy", "environmentPolicy", "environmentClassPolicies")},
		{"null-environment-policy", "structural", set(nil, "policy", "environmentPolicy")},
		{"null-live-classes", "structural", set(nil, "policy", "environmentPolicy", "liveGithubRequiredClasses")},
		{"blank-pattern", "structural", set(" ", "policy", "packageNamePattern")},
		{"non-object-pair", "structural", set([]any{"go test ./..."}, "facts", "commandEnvironmentPairs")},
		{"unsorted-languages", "native", set([]any{"go", "c"}, "profile", "repository", "primaryLanguages")},
		{"trimmed-duplicate-languages", "native", set([]any{" go", "go"}, "profile", "repository", "primaryLanguages")},
		{"unsorted-matcher-ids", "native", func(input map[string]any) {
			first := repoPath(input, "profile")["commandMatchers"].([]any)[0].(map[string]any)
			second := map[string]any{}
			for key, value := range first {
				second[key] = value
			}
			second["id"] = "a.matcher"
			repoPath(input, "profile")["commandMatchers"] = []any{first, second}
		}},
		{"secret-text", "native", set("Bearer abcdefghijklmnopqrstuvwxyz", "profile", "repository", "name")},
		{"unsafe-tracked-file", "native", set([]any{"../outside"}, "facts", "trackedFiles")},
		{"trimmed-duplicate-tracked-files", "native", set([]any{"a", " a"}, "facts", "trackedFiles")},
		{"shell-command", "native", set([]any{map[string]any{"command": "go test ./... && curl x", "environmentClasses": []any{"local-go"}}}, "facts", "commandEnvironmentPairs")},
		{"invalid-pattern", "native", set("(", "policy", "packageNamePattern")},
		{"unsorted-class-policies", "native", set([]any{
			map[string]any{"credentialClass": "none", "environmentClass": "b", "networkPolicy": "none"},
			map[string]any{"credentialClass": "none", "environmentClass": "a", "networkPolicy": "none"},
		}, "policy", "environmentPolicy", "environmentClassPolicies")},
	}
	required := map[string][]string{
		"":                          {"facts", "policy", "profile"},
		"profile":                   profileKeys,
		"profile/repository":        repositoryKeys,
		"profile/documents":         documentsKeys,
		"profile/requirements":      requirementsKeys,
		"profile/proofs":            proofsKeys,
		"facts":                     factsKeys,
		"policy":                    {"environmentPolicy"},
		"policy/environmentPolicy":  {"liveGithubRequiredClasses", "localSecretRequiredClasses"},
		"profile/commandMatchers/0": {"credentialClass", "id", "kind", "networkPolicy", "parallelGroup"},
	}
	for parent, keys := range required {
		for _, key := range keys {
			path := append(splitRepoPath(parent), key)
			cases = append(cases, inputCase{"missing-" + strings.Join(path, "."), "structural", remove(path...)})
		}
		cases = append(cases, inputCase{"unknown-" + parent, "structural", set(true, append(splitRepoPath(parent), "foreign")...)})
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validRepoProfileInput()
			test.mutate(input)
			_, _, nativeErr := Build(input)
			_, shapeErr := InputShape().Admit(input, "input")
			switch test.class {
			case "accept":
				if nativeErr != nil || shapeErr != nil {
					t.Fatalf("admitted input diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "structural":
				if nativeErr == nil || shapeErr == nil {
					t.Fatalf("structural refusal diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "native":
				if nativeErr == nil || shapeErr != nil {
					t.Fatalf("native-only refusal changed owner: native=%v shape=%v", nativeErr, shapeErr)
				}
			}
		})
	}
}

func TestRepoProfileTrimmedVocabulariesMatchNativeMembership(t *testing.T) {
	for _, vocabulary := range [][]string{commandMatcherKinds, networkPolicies, credentialClasses} {
		shape := trimmedEnumShape(vocabulary)
		candidates := []string{"", " ", "noneX", "Xnone", "NONE", "none none", "-"}
		for _, value := range vocabulary {
			candidates = append(candidates, value, " "+value, value+"\t", "\u3000"+value+"\u0085", value[:len(value)-1], value+"s")
		}
		for _, candidate := range candidates {
			text, err := nonEmptyString(candidate, "vocabulary")
			native := err == nil && contains(vocabulary, text)
			if native != (shape.CheckGenerated(candidate, "vocabulary") == nil) {
				t.Fatalf("vocabulary member %q diverged", candidate)
			}
		}
	}
}

func TestRepoProfileStructuresAreDetachedAndNativeOwned(t *testing.T) {
	first, second := InputStructure(), InputStructure()
	structureNode(first, "profile", "commandMatchers", "*")["required"] = []any{}
	if !reflect.DeepEqual(second, InputStructure()) || !reflect.DeepEqual(OutputStructure(), OutputStructure()) {
		t.Fatal("structure projection is not detached and deterministic")
	}
	schema := InputStructure()
	if !reflect.DeepEqual(schema["required"], []any{"facts", "policy", "profile"}) {
		t.Fatalf("root required members drifted: %v", schema["required"])
	}
	for _, path := range uniqueInputLists {
		if structureNode(schema, path...)["uniqueItems"] != true {
			t.Fatalf("%v lost unique structure", path)
		}
	}
	version := schema["properties"].(map[string]any)["schemaVersion"].(map[string]any)
	if version["const"] != json.Number("1") || version["type"] != "integer" {
		t.Fatal("optional transitional schemaVersion is not literal 1")
	}
}

func splitRepoPath(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

func repoPath(input map[string]any, path ...string) map[string]any {
	var current any = input
	for _, segment := range path {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[segment]
		case []any:
			var index int
			fmt.Sscan(segment, &index)
			current = typed[index]
		}
	}
	return current.(map[string]any)
}

func repoRule(value map[string]any) map[string]any {
	return value["ruleResults"].([]any)[0].(map[string]any)
}

func repoWireValue(t *testing.T, value any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
