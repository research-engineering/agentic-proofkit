package gradualadoption

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestBootstrapManifestCommandsPreserveDistinctExactPaths(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		input := validBootstrapInput()
		paths := input["paths"].(map[string]any)
		paths["adoptionGuidancePath"] = "inputs/shared.json"
		paths["witnessPlanInputPath"] = "inputs/shared.json "
		build := BuildBootstrapMaterializationManifest
		if wrapped {
			build = BuildBootstrapMaterializationManifestFromContractEnvelope
			input = bootstrapContractInput(input)
		}
		manifest, code, err := build(input)
		if err != nil || code != 0 {
			t.Fatalf("wrapped=%t: exact distinct paths refused: exit=%d err=%v", wrapped, code, err)
		}
		for _, item := range []struct{ key, path, command string }{
			{"adoptionGuidance", "inputs/shared.json", "agentic-proofkit gradual-adoption-guidance --input inputs/shared.json"},
			{"witnessPlanInput", "inputs/shared.json ", "agentic-proofkit witness-plan --input 'inputs/shared.json '"},
		} {
			matches := 0
			for _, raw := range manifest["files"].([]any) {
				file := raw.(map[string]any)
				if file["payloadKey"] != item.key {
					continue
				}
				matches++
				if file["path"] != item.path || !slices.Contains(manifest["nextCommands"].([]any), any(item.command)) {
					t.Fatalf("wrapped=%t: %s manifest/command path identity changed", wrapped, item.key)
				}
				content := file["content"].(string)
				payload, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
				if err != nil {
					t.Fatal(err)
				}
				childCode := 0
				if item.key == "witnessPlanInput" {
					_, err = witnessplan.Build(payload)
				} else {
					_, childCode, err = BuildGuidance(payload, GuidanceOptions{})
				}
				if err != nil || childCode != 0 {
					t.Fatalf("wrapped=%t: %s materialized payload refused: exit=%d err=%v", wrapped, item.key, childCode, err)
				}
			}
			if matches != 1 {
				t.Fatalf("wrapped=%t: %s manifest entries=%d, want 1", wrapped, item.key, matches)
			}
		}
	}
}

func TestBootstrapMaterializedPathsAreUniqueAcrossOutputModes(t *testing.T) {
	fields := []string{
		"paths.adoptionGuidancePath", "paths.adoptionProfilePath", "paths.witnessPlanInputPath",
		"proofBindingPath", "module.specPath", "repository.profilePath",
	}
	pairs := []struct {
		name, left, right string
		collision         bool
	}{
		{"distinct", "inputs/shared.json", "inputs/distinct.json", false},
		{"equal", "inputs/shared.json", "inputs/shared.json", true},
		{"ancestor", "inputs/guide", "inputs/guide/witness.json", true},
		{"descendant", "inputs/guide/witness.json", "inputs/guide", true},
		{"component boundary", "inputs/guide", "inputs/guidebook/witness.json", false},
		{"case sensitive", "inputs/Guide", "inputs/guide/witness.json", false},
		{"exact space ancestor", "inputs/guide ", "inputs/guide /witness.json", true},
		{"distinct space component", "inputs/guide", "inputs/guide /witness.json", false},
		{"untrimmed parent", "inputs/guide ", "inputs/guide/witness.json", false},
		{"literal glob", "inputs/*", "inputs/guide/witness.json", false},
		{"long ancestor", strings.Repeat("segment/", 150) + "guide", strings.Repeat("segment/", 150) + "guide/witness.json", true},
	}
	builders := []struct {
		name  string
		build func(any) (map[string]any, int, error)
		wrap  bool
	}{
		{"report", BuildBootstrap, false},
		{"manifest", BuildBootstrapMaterializationManifest, false},
		{"envelope", BuildBootstrapEnvelope, false},
		{"wrapped-report", BuildBootstrapFromContractEnvelope, true},
		{"wrapped-manifest", BuildBootstrapMaterializationManifestFromContractEnvelope, true},
		{"wrapped-envelope", BuildBootstrapEnvelopeFromContractEnvelope, true},
	}
	for _, builder := range builders {
		t.Run(builder.name, func(t *testing.T) {
			for left := range fields {
				for right := left + 1; right < len(fields); right++ {
					t.Run(fields[left]+"/"+fields[right], func(t *testing.T) {
						for _, pair := range pairs {
							input := validBootstrapInput()
							setBootstrapFilePath(input, fields[left], pair.left)
							setBootstrapFilePath(input, fields[right], pair.right)
							if builder.wrap {
								input = bootstrapContractInput(input)
							}
							output, code, err := builder.build(input)
							if err != nil {
								t.Fatalf("%s changed collected-failure phase: %v", pair.name, err)
							}
							state := "passed"
							wantCode := 0
							if pair.collision {
								state, wantCode = "failed", 1
							}
							record, ok := output["report"].(map[string]any)
							if !ok {
								record = output["sourceReport"].(map[string]any)
							}
							if code != wantCode || record["state"] != state {
								t.Fatalf("%s: exit=%d state=%v, want %d %s", pair.name, code, record["state"], wantCode, state)
							}
						}
					})
				}
			}
		})
	}
}

func TestBootstrapPathCollisionCollectsOtherFailures(t *testing.T) {
	for _, descendant := range []bool{false, true} {
		input := validBootstrapInput()
		paths := input["paths"].(map[string]any)
		paths["adoptionGuidancePath"] = paths["witnessPlanInputPath"]
		if descendant {
			paths["witnessPlanInputPath"] = paths["adoptionGuidancePath"].(string) + "/witness.json"
		}
		input["guidanceMode"] = "warn"
		result, err := BuildBootstrapResult(input)
		if err != nil || result.ExitCode != 1 || result.Record.State != "failed" {
			t.Fatalf("collision must retain collected failure report: exit=%d err=%v", result.ExitCode, err)
		}
		for _, message := range []string{"bootstrap planned file paths must be unique", "bootstrap guidanceMode must be observe"} {
			found := false
			for _, rule := range result.Record.RuleResults {
				found = found || strings.Contains(rule.Message, message)
			}
			if !found {
				t.Fatalf("missing collected failure %q: %#v", message, result.Record.RuleResults)
			}
		}
	}
	input := validBootstrapInput()
	input["paths"] = map[string]any{}
	result, err := BuildBootstrapResult(input)
	if err != nil || result.ExitCode != 1 || result.Record.State != "failed" {
		t.Fatal("empty paths changed their existing collected failure phase")
	}
	for _, rule := range result.Record.RuleResults {
		if strings.Contains(rule.Message, "non-overlapping") {
			t.Fatal("empty prior-invalid paths acquired an overlap obligation")
		}
	}
}

func TestBootstrapNonMaterializedOutputsDoNotReserveFilePaths(t *testing.T) {
	input := validBootstrapInput()
	paths := input["paths"].(map[string]any)
	paths["adoptionReportArtifactPath"] = paths["witnessPlanInputPath"]
	paths["guidanceReportArtifactPath"] = paths["witnessPlanInputPath"]
	result, err := BuildBootstrapResult(input)
	if err != nil || result.ExitCode != 0 || result.Record.State != "passed" {
		t.Fatalf("non-materialized output collision narrowed bootstrap: exit=%d err=%v", result.ExitCode, err)
	}
	manifest, err := BootstrapMaterializationManifest(result)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[any]bool{}
	for _, raw := range manifest["files"].([]any) {
		file := raw.(map[string]any)
		if seen[file["path"]] {
			t.Fatalf("passed manifest repeats a materialized path: %v", file["path"])
		}
		seen[file["path"]] = true
	}
	if len(seen) != 6 {
		t.Fatalf("planned file count=%d, want 6", len(seen))
	}
}

func TestBootstrapMaterializedPathsRemainDetachedFromCaller(t *testing.T) {
	input := validBootstrapInput()
	paths := input["paths"].(map[string]any)
	paths["adoptionGuidancePath"] = "inputs/guidance.json "
	paths["witnessPlanInputPath"] = "inputs/witness.json "
	result, err := BuildBootstrapResult(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("exact path control: exit=%d err=%v", result.ExitCode, err)
	}
	before, err := BootstrapMaterializationManifest(result)
	if err != nil {
		t.Fatal(err)
	}
	paths["adoptionGuidancePath"] = "inputs/changed.json"
	paths["witnessPlanInputPath"] = "inputs/changed.json"
	after, err := BootstrapMaterializationManifest(result)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("caller path mutation changed the admitted manifest")
	}
}

func setBootstrapFilePath(input map[string]any, field, path string) {
	parts := strings.Split(field, ".")
	if len(parts) == 2 {
		input[parts[0]].(map[string]any)[parts[1]] = path
		return
	}
	input[field] = path
}
