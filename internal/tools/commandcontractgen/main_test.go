package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIFlagConditionModelRejectsAmbiguity(t *testing.T) {
	valid := []rootShapeConditionCase{
		{
			Dimensions: mustParseCLIFlagCondition(t, "--agent-envelope=absent --mode=bootstrap"),
			Raw:        "--agent-envelope=absent --mode=bootstrap",
			VariantID:  "01-bootstrap",
		},
		{
			Dimensions: mustParseCLIFlagCondition(t, "--agent-envelope=present --mode=bootstrap"),
			Raw:        "--agent-envelope=present --mode=bootstrap",
			VariantID:  "02-bootstrap-agent",
		},
	}
	if err := admitCLIFlagConditionCases("proofkit.valid", valid); err != nil {
		t.Fatalf("valid disjoint condition cases rejected: %v", err)
	}

	for _, item := range []struct {
		name      string
		condition string
	}{
		{name: "natural language is not machine authority", condition: "--mode bootstrap"},
		{name: "whitespace is canonical", condition: "--agent-envelope=absent  --mode=bootstrap"},
		{name: "atoms are sorted", condition: "--mode=bootstrap --agent-envelope=absent"},
		{name: "dimensions are unique", condition: "--mode=bootstrap --mode=guidance"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := parseCLIFlagCondition(item.condition); err == nil {
				t.Fatalf("parseCLIFlagCondition(%q) succeeded", item.condition)
			}
		})
	}

	t.Run("every case closes the same dimensions", func(t *testing.T) {
		mutant := append([]rootShapeConditionCase(nil), valid...)
		mutant[1] = rootShapeConditionCase{
			Dimensions: mustParseCLIFlagCondition(t, "--mode=bootstrap"),
			Raw:        "--mode=bootstrap",
			VariantID:  mutant[1].VariantID,
		}
		if err := admitCLIFlagConditionCases("proofkit.dimension-drift", mutant); err == nil || !strings.Contains(err.Error(), "dimensions=") {
			t.Fatalf("dimension-drift error=%v", err)
		}
	})

	t.Run("boolean state cannot overlap literal values", func(t *testing.T) {
		mutant := []rootShapeConditionCase{
			{
				Dimensions: mustParseCLIFlagCondition(t, "--mode=present"),
				Raw:        "--mode=present",
				VariantID:  "01-present",
			},
			{
				Dimensions: mustParseCLIFlagCondition(t, "--mode=bootstrap"),
				Raw:        "--mode=bootstrap",
				VariantID:  "02-literal",
			},
		}
		if err := admitCLIFlagConditionCases("proofkit.state-mix", mutant); err == nil || !strings.Contains(err.Error(), "mixes present with literal values") {
			t.Fatalf("state-mix error=%v", err)
		}
	})

	t.Run("different variants cannot own the same assignment", func(t *testing.T) {
		mutant := append([]rootShapeConditionCase(nil), valid...)
		mutant[1] = rootShapeConditionCase{
			Dimensions: maps.Clone(mutant[0].Dimensions),
			Raw:        "syntactically-distinct-test-fixture",
			VariantID:  mutant[1].VariantID,
		}
		if err := admitCLIFlagConditionCases("proofkit.overlap", mutant); err == nil || !strings.Contains(err.Error(), "overlap across variants") {
			t.Fatalf("overlap error=%v", err)
		}
	})

	t.Run("condition dimension must be an allowed command flag", func(t *testing.T) {
		definition := map[string]any{
			"fieldTree": map[string]any{
				"conditionModel": "cli_flag_conjunction_v1",
				"variants": []any{
					map[string]any{"when": []any{"--undeclared=present"}},
				},
			},
		}
		err := admitConditionModelFlags(
			cliFlagConditionModelCommand,
			cliFlagConditionModelDirection,
			cliFlagConditionModelDefinitionID,
			definition,
			[]string{"--mode"},
		)
		if err == nil || !strings.Contains(err.Error(), "condition model dimension --undeclared is not an allowed flag") {
			t.Fatalf("allowed-flag linkage error=%v", err)
		}
	})

	t.Run("condition model is bound to its admitted command and direction", func(t *testing.T) {
		definition := map[string]any{
			"fieldTree": map[string]any{
				"conditionModel": "cli_flag_conjunction_v1",
				"variants": []any{
					map[string]any{"when": []any{"--mode=adoption"}},
				},
			},
		}
		for _, item := range []struct {
			name         string
			command      string
			direction    string
			definitionID string
		}{
			{name: "command alias", command: "alias", direction: cliFlagConditionModelDirection, definitionID: cliFlagConditionModelDefinitionID},
			{name: "direction alias", command: cliFlagConditionModelCommand, direction: "input", definitionID: cliFlagConditionModelDefinitionID},
			{name: "definition alias", command: cliFlagConditionModelCommand, direction: cliFlagConditionModelDirection, definitionID: "proofkit.alias.output.v1.root-shape"},
		} {
			t.Run(item.name, func(t *testing.T) {
				err := admitConditionModelFlags(item.command, item.direction, item.definitionID, definition, []string{"--mode"})
				if err == nil || !strings.Contains(err.Error(), "is not bound to its admitted command and direction") {
					t.Fatalf("owner-binding error=%v", err)
				}
			})
		}
	})
}

func TestCommandRoutesAreBoundedSafeAndUnambiguous(t *testing.T) {
	routes := map[string]string{}
	if err := admitCommandRoute("adopt-plan", []string{"adopt", "plan"}, routes); err != nil {
		t.Fatalf("admitCommandRoute(valid) error = %v", err)
	}
	if err := admitCommandRoute("change-plan", []string{"change", "plan"}, routes); err != nil {
		t.Fatalf("admitCommandRoute(disjoint) error = %v", err)
	}
	if err := admitCommandRoute("three-token", []string{"three", "route", "tokens"}, routes); err != nil {
		t.Fatalf("admitCommandRoute(max-1) error = %v", err)
	}
	if err := admitCommandRoute("four-token", []string{"four", "route", "tokens", "exactly"}, routes); err != nil {
		t.Fatalf("admitCommandRoute(max) error = %v", err)
	}
	for _, test := range []struct {
		name  string
		route []string
		want  string
	}{
		{name: "empty", route: nil, want: "between one and four"},
		{name: "flag token", route: []string{"--adopt"}, want: "invalid token"},
		{name: "duplicate", route: []string{"adopt", "plan"}, want: "same route"},
		{name: "prefix", route: []string{"adopt"}, want: "ambiguous prefix"},
		{name: "extended prefix", route: []string{"change", "plan", "now"}, want: "ambiguous prefix"},
		{name: "five tokens", route: []string{"five", "route", "tokens", "are", "invalid"}, want: "between one and four"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copyOfRoutes := maps.Clone(routes)
			if err := admitCommandRoute("mutant", test.route, copyOfRoutes); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("admitCommandRoute(%v) error = %v, want %q", test.route, err, test.want)
			}
		})
	}
}

func mustParseCLIFlagCondition(t *testing.T, condition string) map[string]string {
	t.Helper()
	dimensions, err := parseCLIFlagCondition(condition)
	if err != nil {
		t.Fatalf("parse condition %q: %v", condition, err)
	}
	return dimensions
}

func TestRenderRejectsIncompleteAndStaleCommandContracts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "required input contract missing",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["inputContract"] = nil
			},
			want: "required-input command sample is missing inputContract",
		},
		{
			name: "JSON output contract missing",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["outputContract"] = nil
			},
			want: "JSON-output command sample is missing outputContract",
		},
		{
			name: "duplicate command contract id",
			mutate: func(contract map[string]any) {
				command := commandAt(contract, "sample")
				output := command["outputContract"].(map[string]any)
				output["contractId"] = command["inputContract"].(map[string]any)["contractId"]
			},
			want: "duplicate command contract id",
		},
		{
			name: "dangling definition",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootDefinitionRef"] = "proofkit.missing.v1"
			},
			want: "references unknown definition",
		},
		{
			name: "nested definition reference",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["definitionRefs"] = []any{"proofkit.output.v1"}
				refreshDefinitionDigests(contract)
			},
			want: "must not reference nested definitions",
		},
		{
			name: "definition digest mismatch",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootDefinitionDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
			want: "definition digest mismatch",
		},
		{
			name: "misspelled structural field",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["requireFields"] = variant["requiredFields"]
				refreshDefinitionDigests(contract)
			},
			want: "unknown field requireFields",
		},
		{
			name: "open structural escape hatch",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["openFields"] = true
				refreshDefinitionDigests(contract)
			},
			want: "unknown field openFields",
		},
		{
			name: "required root field is not allowed",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["requiredFields"] = []any{"missing"}
				refreshDefinitionDigests(contract)
			},
			want: "required field missing is not allowed",
		},
		{
			name: "variant condition is empty",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["when"] = []any{}
				refreshDefinitionDigests(contract)
			},
			want: "when must be non-empty",
		},
		{
			name: "unknown condition model",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["fieldTree"].(map[string]any)["conditionModel"] = "free_text"
				refreshDefinitionDigests(contract)
			},
			want: "invalid conditionModel",
		},
		{
			name: "condition model without admitted native closure owner",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["fieldTree"].(map[string]any)["conditionModel"] = "cli_flag_conjunction_v1"
				refreshDefinitionDigests(contract)
			},
			want: "conditionModel has no admitted native closure owner",
		},
		{
			name: "variant condition is duplicated across variants",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
				variants = append(variants, map[string]any{
					"allowedFields":  []any{"mode", "schemaVersion"},
					"requiredFields": []any{"mode", "schemaVersion"},
					"rootKind":       "object",
					"variantId":      "z-duplicate-condition",
					"when":           []any{"default"},
				})
				definition["fieldTree"].(map[string]any)["variants"] = variants
				refreshDefinitionDigests(contract)
			},
			want: "is duplicated across variants",
		},
		{
			name: "root fields are not sorted",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["allowedFields"] = []any{"schemaVersion", "mode"}
				refreshDefinitionDigests(contract)
			},
			want: "allowedFields must be sorted and unique",
		},
		{
			name: "object definition declares array variant",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				variant := definition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
				variant["allowedFields"] = []any{}
				variant["requiredFields"] = []any{}
				variant["rootKind"] = "array"
				refreshDefinitionDigests(contract)
			},
			want: "object root cannot declare array",
		},
		{
			name: "union has only one root kind",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["rootType"] = "union"
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootType"] = "union"
				refreshDefinitionDigests(contract)
				refreshRootDefinitionDigests(contract)
			},
			want: "union must enumerate at least two distinct root kinds",
		},
		{
			name: "json value disguises bounded object",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["rootType"] = "json_value"
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootType"] = "json_value"
				refreshDefinitionDigests(contract)
				refreshRootDefinitionDigests(contract)
			},
			want: "json_value root cannot declare bounded object",
		},
		{
			name: "root-shape non-claims drift",
			mutate: func(contract map[string]any) {
				definition := contract["contractDefinitions"].([]any)[0].(map[string]any)
				definition["fieldTree"].(map[string]any)["nonClaims"] = []any{"Nested shape is not claimed."}
				refreshDefinitionDigests(contract)
			},
			want: "exact root-shape non-claims",
		},
		{
			name: "contract schema version is invalid",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["inputContract"].(map[string]any)["schemaVersion"] = 0
			},
			want: "invalid schemaVersion",
		},
		{
			name: "root type drifts from definition",
			mutate: func(contract map[string]any) {
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootType"] = "json_value"
			},
			want: "rootType does not match definition",
		},
		{
			name: "deleted root definition",
			mutate: func(contract map[string]any) {
				contract["contractDefinitions"] = contract["contractDefinitions"].([]any)[1:]
			},
			want: "references unknown definition",
		},
		{
			name: "native source digest mismatch",
			mutate: func(contract map[string]any) {
				source := commandAt(contract, "sample")["inputContract"].(map[string]any)["nativeSource"].(map[string]any)
				source["canonicalDigest"] = "sha256:" + strings.Repeat("0", 64)
			},
			want: "native source digest mismatch",
		},
		{
			name: "native source forms are both present",
			mutate: func(contract map[string]any) {
				input := commandAt(contract, "sample")["inputContract"].(map[string]any)
				input["nativeSources"] = []any{input["nativeSource"]}
			},
			want: "must declare exactly one of nativeSource or nativeSources",
		},
		{
			name: "native source forms are both absent",
			mutate: func(contract map[string]any) {
				delete(commandAt(contract, "sample")["inputContract"].(map[string]any), "nativeSource")
			},
			want: "must declare exactly one of nativeSource or nativeSources",
		},
		{
			name: "native sources are empty",
			mutate: func(contract map[string]any) {
				input := commandAt(contract, "sample")["inputContract"].(map[string]any)
				delete(input, "nativeSource")
				input["nativeSources"] = []any{}
			},
			want: "nativeSources must be non-empty",
		},
		{
			name: "native sources are duplicate",
			mutate: func(contract map[string]any) {
				input := commandAt(contract, "sample")["inputContract"].(map[string]any)
				source := input["nativeSource"]
				delete(input, "nativeSource")
				input["nativeSources"] = []any{source, source}
			},
			want: "nativeSources must be sorted and unique by path",
		},
		{
			name: "stale selector",
			mutate: func(contract map[string]any) {
				selector := commandAt(contract, "sample")["inputContract"].(map[string]any)["nativeAdmissionWitnessSelector"].(map[string]any)
				selector["test"] = "TestMissing"
				selector["command"] = "go test ./internal/command/sample -run '^TestMissing$'"
			},
			want: "test function TestMissing does not exist",
		},
		{
			name: "selector name is not discoverable by go test",
			mutate: func(contract map[string]any) {
				selector := commandAt(contract, "sample")["inputContract"].(map[string]any)["nativeAdmissionWitnessSelector"].(map[string]any)
				selector["test"] = "Testlowercase"
				selector["command"] = "go test ./internal/command/sample -run '^Testlowercase$'"
			},
			want: "selector test is invalid",
		},
		{
			name: "unselectable selector command",
			mutate: func(contract map[string]any) {
				selector := commandAt(contract, "sample")["inputContract"].(map[string]any)["nativeAdmissionWitnessSelector"].(map[string]any)
				selector["command"] = "go test ./internal/command/sample"
			},
			want: "selector command must select exactly",
		},
		{
			name: "tracked selector is inactive in current build",
			mutate: func(contract map[string]any) {
				for _, direction := range []string{"inputContract", "outputContract"} {
					value, _ := commandAt(contract, "sample")[direction].(map[string]any)
					selectorKey := "nativeAdmissionWitnessSelector"
					if direction == "outputContract" {
						selectorKey = "nativeOutputWitnessSelector"
					}
					selector := value[selectorKey].(map[string]any)
					selector["path"] = "internal/command/sample/inactive_test.go"
					selector["test"] = "TestInactive"
					selector["command"] = "go test ./internal/command/sample -run '^TestInactive$'"
				}
			},
			want: "not active in the current Go build",
		},
		{
			name: "untracked selector",
			mutate: func(contract map[string]any) {
				source := []byte("package sample\n\nimport \"testing\"\n\nfunc TestUntracked(t *testing.T) {}\n")
				_ = os.WriteFile(filepath.Join(fixtureRoot(contract), "internal/command/sample/untracked_test.go"), source, 0o644)
				for _, direction := range []string{"inputContract", "outputContract"} {
					value, _ := commandAt(contract, "sample")[direction].(map[string]any)
					selectorKey := "nativeAdmissionWitnessSelector"
					if direction == "outputContract" {
						selectorKey = "nativeOutputWitnessSelector"
					}
					selector := value[selectorKey].(map[string]any)
					selector["path"] = "internal/command/sample/untracked_test.go"
					selector["test"] = "TestUntracked"
					selector["command"] = "go test ./internal/command/sample -run '^TestUntracked$'"
				}
			},
			want: "Git-index-tracked",
		},
		{
			name: "deleted tracked selector",
			mutate: func(contract map[string]any) {
				_ = os.Remove(filepath.Join(fixtureRoot(contract), "internal/command/sample/sample_test.go"))
			},
			want: "selector path is unavailable",
		},
		{
			name: "tracked selector replaced by symlink",
			mutate: func(contract map[string]any) {
				path := filepath.Join(fixtureRoot(contract), "internal/command/sample/sample_test.go")
				_ = os.Remove(path)
				_ = os.Symlink("sample.go", path)
			},
			want: "regular non-symlink file",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := writeFixture(t)
			contract := readFixtureContract(t, root)
			contract["__fixtureRoot"] = root
			test.mutate(contract)
			delete(contract, "__fixtureRoot")
			writeFixtureContract(t, root, contract)
			_, _, err := render(root)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("render() error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestRunGeneratesAndChecksBothProjections(t *testing.T) {
	root := writeFixture(t)
	if err := run(root, false); err != nil {
		t.Fatalf("run(generate): %v", err)
	}
	for _, path := range []string{appGeneratedPath, presetGeneratedPath} {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(content), "Code generated by internal/tools/commandcontractgen") {
			t.Fatalf("%s lacks generated-file marker", path)
		}
	}
	if err := run(root, true); err != nil {
		t.Fatalf("run(check): %v", err)
	}
	appPath := filepath.Join(root, filepath.FromSlash(appGeneratedPath))
	if err := os.WriteFile(appPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "application projection is stale") {
		t.Fatalf("run(check stale app) error=%v", err)
	}
	if err := run(root, false); err != nil {
		t.Fatal(err)
	}
	presetPath := filepath.Join(root, filepath.FromSlash(presetGeneratedPath))
	if err := os.WriteFile(presetPath, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err == nil || !strings.Contains(err.Error(), "preset projection is stale") {
		t.Fatalf("run(check stale preset) error=%v", err)
	}
}

func TestRenderedMetadataDigestIncludesRootShapeVariants(t *testing.T) {
	root := writeFixture(t)
	contract := readFixtureContract(t, root)
	definitions := contract["contractDefinitions"].([]any)
	inputDefinition := definitions[0].(map[string]any)
	refreshDefinitionDigests(contract)
	refreshRootDefinitionDigests(contract)
	writeFixtureContract(t, root, contract)

	before, _, err := render(root)
	if err != nil {
		t.Fatalf("render before root-shape mutation: %v", err)
	}
	inputVariant := inputDefinition["fieldTree"].(map[string]any)["variants"].([]any)[0].(map[string]any)
	inputVariant["allowedFields"] = []any{"mode", "note", "schemaVersion"}
	refreshDefinitionDigests(contract)
	refreshRootDefinitionDigests(contract)
	writeFixtureContract(t, root, contract)

	after, _, err := render(root)
	if err != nil {
		t.Fatalf("render after root-shape mutation: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Fatal("generated metadata did not change after a root-shape variant changed")
	}
}

func writeFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{
		"proofkit",
		"internal/app",
		"internal/command/sample",
		"internal/command/stackpreset",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	source := []byte("package sample\n\nfunc Build() {}\n")
	testSource := []byte("package sample\n\nimport testpkg \"testing\"\n\nfunc TestBuildRejectsInvalidInput(*testpkg.T) {}\n")
	inactiveTestSource := []byte("//go:build never\n\npackage sample\n\nimport \"testing\"\n\nfunc TestInactive(t *testing.T) {}\n")
	if err := os.WriteFile(filepath.Join(root, "internal/command/sample/sample.go"), source, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal/command/sample/sample_test.go"), testSource, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal/command/sample/inactive_test.go"), inactiveTestSource, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture.invalid/sample\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sourceDigest := digestFiles(t, root, []string{"internal/command/sample/sample.go"})
	definitions := []any{
		structuralFixtureDefinition("proofkit.input.v1"),
		structuralFixtureDefinition("proofkit.output.v1"),
	}
	contract := map[string]any{
		"schemaVersion":       2,
		"contractId":          "proofkit.cli-contract.v2",
		"packageName":         "@research-engineering/agentic-proofkit",
		"processContract":     map[string]any{},
		"contractDefinitions": definitions,
		"commands": []any{
			map[string]any{
				"command":      "sample",
				"input":        "required",
				"stdin":        true,
				"inputPointer": true,
				"scopeClass":   "explicit_caller_input",
				"outputModes":  []any{"json"},
				"allowedFlags": []any{"--input", "--input-pointer"},
				"inputContract": contractFixture(
					"proofkit.sample.input.v1",
					"proofkit.input.v1",
					sourceDigest,
					"nativeAdmissionWitnessSelector",
				),
				"outputContract": contractFixture(
					"proofkit.sample.output.v1",
					"proofkit.output.v1",
					sourceDigest,
					"nativeOutputWitnessSelector",
				),
			},
			map[string]any{
				"command":       "stack-preset",
				"input":         "none",
				"stdin":         false,
				"inputPointer":  false,
				"scopeClass":    "built_in_package_catalog",
				"outputModes":   []any{"json"},
				"allowedFlags":  []any{"--preset"},
				"requiredFlags": []any{"--preset"},
				"outputContract": func() map[string]any {
					value := contractFixture(
						"proofkit.stack-preset.output.v1",
						"proofkit.output.v1",
						sourceDigest,
						"nativeOutputWitnessSelector",
					)
					value["flagChoices"] = map[string]any{"--preset": []any{"alpha", "beta"}}
					return value
				}(),
			},
		},
	}
	refreshDefinitionDigests(contract)
	refreshRootDefinitionDigests(contract)
	writeFixtureContract(t, root, contract)
	runGit(t, root, "init")
	runGit(t, root, "add", ".")
	return root
}

func refreshRootDefinitionDigests(contract map[string]any) {
	definitions := contract["contractDefinitions"].([]any)
	for _, command := range contract["commands"].([]any) {
		record := command.(map[string]any)
		for _, key := range []string{"inputContract", "outputContract"} {
			value, ok := record[key].(map[string]any)
			if !ok {
				continue
			}
			ref := value["rootDefinitionRef"].(string)
			for _, raw := range definitions {
				definition := raw.(map[string]any)
				if definition["definitionId"] == ref {
					value["rootDefinitionDigest"] = definition["canonicalDigest"]
				}
			}
		}
	}
}

func structuralFixtureDefinition(id string) map[string]any {
	return map[string]any{
		"definitionId":   id,
		"schemaVersion":  1,
		"rootType":       "object",
		"closed":         true,
		"definitionRefs": []any{},
		"fieldTree": map[string]any{
			"kind": "root_shape_only",
			"nonClaims": []any{
				"Root-shape definitions do not claim nested field shapes, leaf types, cardinalities, or semantic validity.",
				"Root-shape definitions do not replace direct public-CLI runtime witnesses for variant selection.",
			},
			"variants": []any{
				map[string]any{
					"allowedFields":  []any{"mode", "schemaVersion"},
					"requiredFields": []any{"mode", "schemaVersion"},
					"rootKind":       "object",
					"variantId":      "default",
					"when":           []any{"default"},
				},
			},
		},
	}
}

func fixtureRoot(contract map[string]any) string {
	root, _ := contract["__fixtureRoot"].(string)
	return root
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}

func contractFixture(contractID string, definitionID string, sourceDigest string, selectorKey string) map[string]any {
	return map[string]any{
		"contractId":           contractID,
		"schemaVersion":        1,
		"rootType":             "object",
		"closed":               true,
		"rootDefinitionRef":    definitionID,
		"rootDefinitionDigest": "",
		"ownerRequirementRefs": []any{"REQ-PROOFKIT-PACKAGE-002"},
		"nativeSource": map[string]any{
			"path":            "internal/command/sample",
			"canonicalDigest": sourceDigest,
			"evidenceClass":   "source_checkout",
		},
		selectorKey: map[string]any{
			"path":          "internal/command/sample/sample_test.go",
			"test":          "TestBuildRejectsInvalidInput",
			"command":       "go test ./internal/command/sample -run '^TestBuildRejectsInvalidInput$'",
			"evidenceClass": "source_checkout",
		},
		"compatibilitySummary": []any{"schemaVersion=1", "closed native admission contract"},
	}
}

func commandAt(contract map[string]any, name string) map[string]any {
	for _, raw := range contract["commands"].([]any) {
		command := raw.(map[string]any)
		if command["command"] == name {
			return command
		}
	}
	panic("missing fixture command")
}

func refreshDefinitionDigests(contract map[string]any) {
	for _, raw := range contract["contractDefinitions"].([]any) {
		definition := raw.(map[string]any)
		delete(definition, "canonicalDigest")
		encoded, err := canonicalJSON(definition)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(encoded)
		definition["canonicalDigest"] = "sha256:" + hex.EncodeToString(sum[:])
	}
}

func readFixtureContract(t *testing.T, root string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writeFixtureContract(t *testing.T, root string, contract map[string]any) {
	t.Helper()
	content, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if err := os.WriteFile(filepath.Join(root, cliContractPath), content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func digestFiles(t *testing.T, root string, paths []string) string {
	t.Helper()
	hash := sha256.New()
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		hash.Write(content)
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
