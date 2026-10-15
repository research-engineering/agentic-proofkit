package scaffoldprofileplan

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestOutputStructureDescribesEveryReachablePlanShape(t *testing.T) {
	matchers := map[string]any{
		"none": []any{}, "absent": nil,
		"all": []any{
			map[string]any{"allowedArgv": []any{"go", "test", "./..."}, "credentialClass": "none", "id": "fixture.argv", "kind": "exact_argv", "networkPolicy": "none", "parallelGroup": "local"},
			map[string]any{"allowedScripts": []any{"check"}, "credentialClass": "local-secret", "id": "fixture.bun", "kind": "bun_repo_script", "networkPolicy": "loopback", "parallelGroup": "local"},
			map[string]any{"allowedScripts": []any{"test"}, "credentialClass": "live-github", "id": "fixture.workspace", "kind": "bun_workspace_package_script", "networkPolicy": "external", "parallelGroup": "remote"},
			map[string]any{"allowedTestPathGlobs": []any{"tests/**/*.py"}, "credentialClass": "live-cloud", "id": "fixture.pytest", "kind": "python_pytest_contract", "networkPolicy": "none", "parallelGroup": "python"},
		},
	}
	artifacts := map[string]any{"none": []any{}, "absent": nil, "one": []any{map[string]any{"generator": "scripts/gen.mjs", "path": "docs/generated.md", "sourceOfTruth": []any{"docs/source.md"}}}}
	presets := append([]string{""}, stackpreset.IDs()...)
	seen := map[string]bool{}
	for _, preset := range presets {
		for matcherName, matcherValue := range matchers {
			for artifactName, artifactValue := range artifacts {
				for _, defaulted := range []bool{false, true} {
					input := validScaffoldInput()
					paths := input["paths"].(map[string]any)
					setOptional(input, "commandMatcherHints", matcherValue)
					setOptional(paths, "generatedArtifacts", artifactValue)
					if preset != "" {
						input["presetId"] = preset
					}
					if defaulted {
						if preset == "" {
							continue
						}
						delete(paths, "proofLikePaths")
						delete(input, "environmentClasses")
						paths["specGlobs"] = nil
						paths["retiredProofLikePaths"] = nil
					}
					result, err := BuildResult(input)
					if err != nil {
						if preset == "generated_docs_contract_repo" && defaulted && strings.Contains(err.Error(), "specGlobs") {
							continue
						}
						t.Fatalf("%s/%s/%s/%t: %v", preset, matcherName, artifactName, defaulted, err)
					}
					if err := OutputShape().CheckGenerated(result.Plan, "scaffold plan"); err != nil {
						t.Fatalf("%s/%s/%s/%t: %v", preset, matcherName, artifactName, defaulted, err)
					}
					for _, gap := range result.Plan["callerRequiredGaps"].([]any) {
						seen[gap.(map[string]any)["gapId"].(string)] = true
					}
					for _, row := range result.Plan["provenance"].([]any) {
						seen[row.(map[string]any)["fieldPath"].(string)+"/"+row.(map[string]any)["source"].(string)] = true
					}
					seen[fmt.Sprintf("provenance/%d", len(result.Plan["provenance"].([]any)))] = true
					seen[fmt.Sprintf("gaps/%d", len(result.Plan["callerRequiredGaps"].([]any)))] = true
				}
			}
		}
	}
	for _, want := range []string{
		"proofkit.repo-profile-scaffold.gap.command-matchers", "proofkit.repo-profile-scaffold.gap.generated-artifacts",
		"proofkit.repo-profile-scaffold.gap.tracked-facts", "commandMatchers/caller_input", "documents.generatedArtifacts/caller_input",
		"requirements.specGlobs/stack_preset", "requirements.specGlobs/caller_input", "proofs.proofLikePaths/stack_preset",
		"proofs.proofLikePaths/caller_input", "proofs.environmentClasses/stack_preset", "proofs.environmentClasses/caller_input",
		"provenance/10", "provenance/12", "gaps/1", "gaps/3",
	} {
		if !seen[want] {
			t.Fatalf("reachable output domain was not exercised: %s", want)
		}
	}
	value, err := Build(validScaffoldInput())
	if err != nil {
		t.Fatal(err)
	}
	plan := value.(map[string]any)
	if !slices.Equal(slices.Sorted(maps.Keys(plan)), sortedSchemaKeys(OutputStructure())) {
		t.Fatal("native plan inventory differs from its structure")
	}
	for key := range plan {
		missing := maps.Clone(plan)
		delete(missing, key)
		if OutputShape().CheckGenerated(missing, "plan") == nil {
			t.Fatalf("accepted plan without %s", key)
		}
	}
	plan["foreign"] = true
	if OutputShape().CheckGenerated(plan, "plan") == nil {
		t.Fatal("accepted an unowned plan member")
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	type mutation struct {
		name   string
		mutate func(map[string]any)
		class  string // accepted, structural or native
	}
	set := func(path string, value any) func(map[string]any) {
		return func(input map[string]any) { setPath(input, path, value) }
	}
	drop := func(path string) func(map[string]any) {
		return func(input map[string]any) { deletePath(input, path) }
	}
	long := strings.Repeat("A", 256)
	cases := []mutation{
		{"positive", func(map[string]any) {}, "accepted"},
		{"preset", set("presetId", "typescript_workspace"), "accepted"},
		{"null preset", set("presetId", nil), "accepted"},
		{"absent optional lists", func(input map[string]any) {
			delete(input, "commandMatcherHints")
			delete(input["paths"].(map[string]any), "generatedArtifacts")
			delete(input["paths"].(map[string]any), "retiredProofLikePaths")
		}, "accepted"},
		{"null optional lists", func(input map[string]any) {
			input["commandMatcherHints"] = nil
			input["paths"].(map[string]any)["generatedArtifacts"] = nil
			input["paths"].(map[string]any)["retiredProofLikePaths"] = nil
			input["paths"].(map[string]any)["specGlobs"] = nil
		}, "accepted"},
		{"preset defaults", func(input map[string]any) {
			input["presetId"] = "python_service"
			delete(input, "environmentClasses")
			delete(input["paths"].(map[string]any), "proofLikePaths")
			delete(input["paths"].(map[string]any), "specGlobs")
		}, "accepted"},
		{"whitespace path", set("paths.routerPath", " "), "accepted"},
		{"padded text", set("repository.name", "  padded  "), "accepted"},
		{"maximum identifier", set("planId", long), "accepted"},
		{"empty matcher list", set("commandMatcherHints", []any{}), "accepted"},
		{"empty retired list", set("paths.retiredProofLikePaths", []any{}), "accepted"},
		{"unknown root", set("foreign", true), "structural"},
		{"unknown repository", set("repository.foreign", true), "structural"},
		{"unknown paths", set("paths.foreign", true), "structural"},
		{"unknown requirements", set("requirements.foreign", true), "structural"},
		{"unknown artifact", set("paths.generatedArtifacts", []any{map[string]any{"generator": "g.mjs", "path": "a.md", "sourceOfTruth": []any{"s.md"}, "foreign": true}}), "structural"},
		{"unknown matcher", set("commandMatcherHints.0.foreign", true), "structural"},
		{"missing schemaVersion", drop("schemaVersion"), "structural"},
		{"schemaVersion two", set("schemaVersion", json.Number("2")), "structural"},
		{"schemaVersion text", set("schemaVersion", "1"), "structural"},
		{"missing planId", drop("planId"), "structural"},
		{"long identifier", set("planId", long+"A"), "structural"},
		{"invalid identifier", set("planId", "1bad"), "structural"},
		{"unknown preset", set("presetId", "foreign"), "structural"},
		{"preset kind", set("presetId", false), "structural"},
		{"missing repository", drop("repository"), "structural"},
		{"null repository", set("repository", nil), "structural"},
		{"missing repository name", drop("repository.name"), "structural"},
		{"blank repository name", set("repository.name", " \u00a0"), "structural"},
		{"empty languages", set("repository.primaryLanguages", []any{}), "structural"},
		{"blank language", set("repository.primaryLanguages", []any{"\t"}), "structural"},
		{"missing profile path", drop("repository.profilePath"), "structural"},
		{"empty profile path", set("repository.profilePath", ""), "structural"},
		{"missing paths", drop("paths"), "structural"},
		{"missing router path", drop("paths.routerPath"), "structural"},
		{"router path kind", set("paths.routerPath", json.Number("1")), "structural"},
		{"empty spec globs", set("paths.specGlobs", []any{}), "structural"},
		{"empty proof paths", set("paths.proofLikePaths", []any{}), "structural"},
		{"empty source of truth", set("paths.generatedArtifacts", []any{map[string]any{"generator": "g.mjs", "path": "a.md", "sourceOfTruth": []any{}}}), "structural"},
		{"artifact without generator", set("paths.generatedArtifacts", []any{map[string]any{"path": "a.md", "sourceOfTruth": []any{"s.md"}}}), "structural"},
		{"missing requirements", drop("requirements"), "structural"},
		{"null requirements", set("requirements", nil), "structural"},
		{"missing id pattern", drop("requirements.idPattern"), "structural"},
		{"empty environment classes", set("environmentClasses", []any{}), "structural"},
		{"environment class kind", set("environmentClasses", []any{false}), "structural"},
		{"matcher kind", set("commandMatcherHints.0.kind", "foreign"), "structural"},
		{"matcher network", set("commandMatcherHints.0.networkPolicy", "foreign"), "structural"},
		{"matcher credential", set("commandMatcherHints.0.credentialClass", "foreign"), "structural"},
		{"matcher blank group", set("commandMatcherHints.0.parallelGroup", " "), "structural"},
		{"matcher null scripts", set("commandMatcherHints.0.allowedScripts", nil), "structural"},
		{"matcher empty scripts", set("commandMatcherHints.0.allowedScripts", []any{}), "structural"},
		{"matcher extra argv", set("commandMatcherHints.0.allowedArgv", []any{"go"}), "structural"},
		{"matcher hint object", set("commandMatcherHints", map[string]any{}), "structural"},
		{"missing nonClaims", drop("nonClaims"), "structural"},
		{"empty nonClaims", set("nonClaims", []any{}), "structural"},
		{"blank nonClaim", set("nonClaims", []any{" "}), "structural"},
		{"absolute path", set("paths.routerPath", "/AGENTS.md"), "native"},
		{"escaping path", set("paths.policyPath", "../profile.json"), "native"},
		{"secret text", set("repository.name", "api_"+"key=synthetic-structure-fixture"), "native"},
		{"timestamp identifier", set("planId", "proofkit.2026-01-01"), "native"},
		{"duplicate languages", set("repository.primaryLanguages", []any{"go", " go"}), "native"},
		{"duplicate artifacts", set("paths.generatedArtifacts", []any{
			map[string]any{"generator": "g.mjs", "path": "a.md", "sourceOfTruth": []any{"s.md"}},
			map[string]any{"generator": "h.mjs", "path": "a.md", "sourceOfTruth": []any{"t.md"}},
		}), "native"},
		{"duplicate matcher ids", set("commandMatcherHints", []any{
			map[string]any{"allowedScripts": []any{"a"}, "credentialClass": "none", "id": "x", "kind": "bun_repo_script", "networkPolicy": "none", "parallelGroup": "g"},
			map[string]any{"allowedScripts": []any{"b"}, "credentialClass": "none", "id": " x", "kind": "bun_repo_script", "networkPolicy": "none", "parallelGroup": "g"},
		}), "native"},
		{"shell argv", set("commandMatcherHints", []any{map[string]any{"allowedArgv": []any{"go", "&&"}, "credentialClass": "none", "id": "x", "kind": "exact_argv", "networkPolicy": "none", "parallelGroup": "g"}}), "native"},
		{"builtin nonClaim", set("nonClaims", []any{scaffoldNonClaims[0]}), "native"},
		{"proof paths require preset", func(input map[string]any) { delete(input["paths"].(map[string]any), "proofLikePaths") }, "native"},
		{"environment classes require preset", func(input map[string]any) { delete(input, "environmentClasses") }, "native"},
		{"preset without spec paths", func(input map[string]any) {
			input["presetId"] = "generated_docs_contract_repo"
			delete(input["paths"].(map[string]any), "specGlobs")
		}, "native"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validScaffoldInput()
			item.mutate(input)
			_, nativeErr := BuildResult(input)
			_, shapeErr := InputShape().Admit(input, "input")
			switch item.class {
			case "accepted":
				if nativeErr != nil || shapeErr != nil {
					t.Fatalf("accepted input diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "structural":
				if nativeErr == nil || shapeErr == nil {
					t.Fatalf("structural refusal diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			case "native":
				if nativeErr == nil || shapeErr != nil {
					t.Fatalf("native-only predicate diverged: native=%v shape=%v", nativeErr, shapeErr)
				}
			}
		})
	}
}

func TestMatcherKindsOwnExactlyOneListMember(t *testing.T) {
	lists := map[string]any{
		"allowedArgv": []any{"go", "test"}, "allowedScripts": []any{"check"}, "allowedTestPathGlobs": []any{"tests/**/*.py"},
	}
	names := slices.Sorted(maps.Keys(lists))
	for kind := range supportedMatcherKinds {
		for mask := range 1 << len(names) {
			matcher := map[string]any{"credentialClass": "none", "id": "fixture.matcher", "kind": kind, "networkPolicy": "none", "parallelGroup": "local"}
			for index, name := range names {
				if mask&(1<<index) != 0 {
					matcher[name] = lists[name]
				}
			}
			input := validScaffoldInput()
			input["commandMatcherHints"] = []any{matcher}
			_, nativeErr := BuildResult(input)
			_, shapeErr := InputShape().Admit(input, "input")
			if (nativeErr == nil) != (shapeErr == nil) {
				t.Fatalf("%s/%03b: native=%v shape=%v", kind, mask, nativeErr, shapeErr)
			}
		}
	}
}

// Selecting a preset must not relabel caller-supplied environment classes.
func TestEnvironmentClassProvenanceFollowsSuppliedOperand(t *testing.T) {
	for _, row := range []struct {
		name, source, evidence string
		mutate                 func(map[string]any)
	}{
		{"caller with preset", "caller_input", "environmentClasses", func(input map[string]any) { input["presetId"] = "python_service" }},
		{"caller without preset", "caller_input", "environmentClasses", func(map[string]any) {}},
		{"preset default", "stack_preset", "stack-preset:python_service.starterEnvironmentClasses", func(input map[string]any) {
			input["presetId"] = "python_service"
			input["environmentClasses"] = nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			input := validScaffoldInput()
			row.mutate(input)
			result, err := BuildResult(input)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, raw := range result.Plan["provenance"].([]any) {
				provenance := raw.(map[string]any)
				if provenance["fieldPath"] == "proofs.environmentClasses" {
					found = provenance["source"] == row.source && provenance["evidenceRef"] == row.evidence
				}
			}
			if !found {
				t.Fatalf("environment class provenance misattributed: %#v", result.Plan["provenance"])
			}
		})
	}
}

func TestStructuresAreDetachedProjections(t *testing.T) {
	for _, build := range []func() map[string]any{InputStructure, OutputStructure} {
		first := build()
		first["properties"].(map[string]any)["schemaVersion"].(map[string]any)["const"] = json.Number("2")
		if reflect.DeepEqual(first, build()) {
			t.Fatal("structure projection aliases a prior caller")
		}
	}
	if !slices.Equal(sortedSchemaKeys(InputStructure()), slices.Sorted(slices.Values(inputKeys))) {
		t.Fatal("input structure differs from the native member inventory")
	}
	union := map[string]bool{}
	for _, raw := range commandMatcherShape(nonemptyText()).JSONSchema()["oneOf"].([]any) {
		for key := range raw.(map[string]any)["properties"].(map[string]any) {
			if !slices.Contains(commandMatcherKeys, key) {
				t.Fatalf("matcher branch declares an unadmitted member %s", key)
			}
			union[key] = true
		}
	}
	if len(union) != len(commandMatcherKeys) {
		t.Fatal("matcher branches omit a native matcher member")
	}
}

func setOptional(record map[string]any, key string, value any) {
	if value == nil {
		delete(record, key)
		return
	}
	record[key] = value
}

func sortedSchemaKeys(schema map[string]any) []string {
	return slices.Sorted(maps.Keys(schema["properties"].(map[string]any)))
}

func setPath(record map[string]any, path string, value any) {
	parent, key := walk(record, path)
	switch typed := parent.(type) {
	case map[string]any:
		typed[key] = value
	case []any:
		index := int(key[0] - '0')
		typed[index] = value
	}
}

func deletePath(record map[string]any, path string) {
	parent, key := walk(record, path)
	delete(parent.(map[string]any), key)
}

func walk(record map[string]any, path string) (any, string) {
	parts := strings.Split(path, ".")
	var current any = record
	for _, part := range parts[:len(parts)-1] {
		switch typed := current.(type) {
		case map[string]any:
			current = typed[part]
		case []any:
			current = typed[int(part[0]-'0')]
		}
	}
	return current, parts[len(parts)-1]
}

// Owner decision C-05: a preset without a docs/specs/ starter path supplies no
// specGlobs default, so the caller must provide them. The published input
// schema and native admission agree on every preset and specGlobs operand.
func TestCallerSpecGlobPresetsAgreeWithNativeAdmission(t *testing.T) {
	if !slices.Contains(callerSpecGlobPresets(), "generated_docs_contract_repo") || slices.Contains(callerSpecGlobPresets(), "python_service") {
		t.Fatalf("caller spec-glob presets = %v", callerSpecGlobPresets())
	}
	schema := InputStructure()
	for _, presetID := range stackpreset.IDs() {
		for _, operand := range []string{"omitted", "null", "explicit"} {
			t.Run(presetID+"/"+operand, func(t *testing.T) {
				input := validScaffoldInput()
				input["presetId"] = presetID
				paths := input["paths"].(map[string]any)
				switch operand {
				case "omitted":
					delete(paths, "specGlobs")
				case "null":
					paths["specGlobs"] = nil
				}
				result, nativeErr := BuildResult(input)
				schemaErr := schemacheck.Validate(schema, input)
				callerRequired := operand != "explicit" && slices.Contains(callerSpecGlobPresets(), presetID)
				if (nativeErr != nil) != callerRequired || (schemaErr != nil) != callerRequired {
					t.Fatalf("callerRequired=%v native=%v schema=%v", callerRequired, nativeErr, schemaErr)
				}
				if callerRequired {
					if !strings.Contains(nativeErr.Error(), "paths.specGlobs must be caller-provided") {
						t.Fatalf("refusal does not name the caller obligation: %v", nativeErr)
					}
					return
				}
				want := "caller_input"
				if operand != "explicit" {
					want = "stack_preset"
				}
				for _, raw := range result.Plan["provenance"].([]any) {
					row := raw.(map[string]any)
					if row["fieldPath"] == "requirements.specGlobs" && row["source"] != want {
						t.Fatalf("specGlobs provenance %v, want %s", row["source"], want)
					}
				}
			})
		}
	}
}
