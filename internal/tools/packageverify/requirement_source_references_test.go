package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralParameterMapDoesNotHideReferenceObjects(t *testing.T) {
	classes := map[string]string{"/values": "literal_string_map"}
	if err := verifyClosedReferenceInventory("fixture", map[string]any{"values": map[string]any{"request_path": "literal"}}, classes); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{nil, []any{}, map[string]any{"request_path": map[string]any{"hiddenPath": "hidden.json"}}} {
		if err := verifyClosedReferenceInventory("fixture", map[string]any{"values": value}, classes); err == nil {
			t.Fatal("literal map admitted a non-string/object shape")
		}
	}
	if err := verifyClosedReferenceInventory("fixture", map[string]any{"other": map[string]any{"request_path": "literal"}}, classes); err == nil {
		t.Fatal("literal map exemption escaped its declared coordinate")
	}
}

func TestPackagedGroupedSourceUsesArtifactOwnedAdmission(t *testing.T) {
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "docs/specs/*/requirements.v2.json"))
	if err != nil || len(paths) != 6 {
		t.Fatalf("source universe: %v count=%d", err, len(paths))
	}
	entries := map[string]struct{}{}
	for _, directory := range []string{"docs/specs", "proofkit"} {
		if err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			entries["package/"+filepath.ToSlash(relative)] = struct{}{}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		entry := "package/" + filepath.ToSlash(relative)
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			if err := verifyRequirementSourceReferences(entry, string(data), entries); err != nil {
				t.Fatalf("real grouped source: %v", err)
			}
			if _, err := admitPackagedRequirementSource("package/docs/specs/other/requirements.v2.json", string(data)); err == nil {
				t.Fatal("wrong archive source identity admitted")
			}
			value, err := decodePackageJSONObject(string(data), "source")
			if err != nil {
				t.Fatal(err)
			}
			id := value["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["requirementId"]
			value["scenarios"] = []any{map[string]any{
				"scenarioId": "package.scenario", "requirementIds": []any{id}, "parameters": []any{"request_path"},
				"preconditions": []any{"The request is available."}, "actionSequence": []any{"Inspect ${request_path}."},
				"expectedObservations": []any{"The request is accepted."}, "forbiddenObservations": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
				"examples": []any{
					map[string]any{"exampleId": "EX-FIRST", "values": map[string]any{"request_path": "first"}},
					map[string]any{"exampleId": "EX-SECOND", "values": map[string]any{"request_path": "second"}},
				},
			}}
			scenarioBytes, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyRequirementSourceReferences(entry, string(scenarioBytes), entries); err != nil {
				t.Fatalf("literal parameter name treated as repository path: %v", err)
			}
			for _, change := range []struct {
				name   string
				mutate func(map[string]any)
			}{
				{"old identity", func(value map[string]any) { value["schemaVersion"] = json.Number("1") }},
				{"unknown grouped field", func(value map[string]any) {
					value["groups"].([]any)[0].(map[string]any)["leakedPath"] = "private/source.txt"
				}},
				{"missing binding artifact", func(value map[string]any) {
					value["groups"].([]any)[0].(map[string]any)["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)["proofBindingRefs"] = []any{"proofkit/missing-binding.json"}
				}},
			} {
				t.Run(change.name, func(t *testing.T) {
					value, err := decodePackageJSONObject(string(data), "source")
					if err != nil {
						t.Fatal(err)
					}
					change.mutate(value)
					encoded, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					if err := verifyRequirementSourceReferences(entry, string(encoded), entries); err == nil {
						t.Fatal("artifact defect hidden by clean workspace or partial source read")
					}
				})
			}
			if _, err := admitPackagedRequirementSource(entry, strings.Replace(string(data), `"schemaVersion": 2`, `"schemaVersion": 2, "schemaVersion": 2`, 1)); err == nil {
				t.Fatal("duplicate source identity accepted")
			}
		})
	}
}
