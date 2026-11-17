package projectstructure

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestScaffoldPersistedGuidanceRetainsLiteralSpecPaths(t *testing.T) {
	for _, paths := range [][]any{{"docs/specs/p1.json "}, {"docs/specs/p1.json", "docs/specs/p1.json "}} {
		input := validProjectStructureInput()
		bootstrap := input["bootstrap"].(map[string]any)
		bootstrap["module"].(map[string]any)["specPath"] = "docs/specs/p1.json "
		bootstrap["ownerRoute"].(map[string]any)["specPaths"] = paths
		result, err := BuildResult(input)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("literal spec paths did not produce a valid scaffold: %v", err)
		}
		guidancePath := bootstrap["paths"].(map[string]any)["adoptionGuidancePath"]
		guidanceCount, specCount := 0, 0
		for _, raw := range result.Manifest["files"].([]any) {
			file := raw.(map[string]any)
			if file["path"] == "docs/specs/p1.json " {
				specCount++
			}
			if file["path"] != guidancePath {
				continue
			}
			guidanceCount++
			content := []byte(file["content"].(string))
			decoded, err := admission.DecodeJSON(bytes.NewReader(content), int64(len(content)))
			if err != nil {
				t.Fatal(err)
			}
			guidance := decoded.(map[string]any)
			if !reflect.DeepEqual(guidance["ownerRoute"].(map[string]any)["specPaths"], paths) {
				t.Fatal("persisted guidance routes to a different literal spec filename")
			}
			if _, exit, err := gradualadoption.BuildGuidance(guidance, gradualadoption.GuidanceOptions{}); err != nil || exit != 0 {
				t.Fatalf("saved guidance did not remain child-valid: exit=%d error=%v", exit, err)
			}
		}
		if guidanceCount != 1 || specCount != 1 {
			t.Fatal("the oracle did not identify exactly one saved guidance and literal spec target")
		}
	}
}

func TestScaffoldSnapshotPreservesNativeRefusals(t *testing.T) {
	type namedObject map[string]any
	for _, field := range []string{"repository", "paths"} {
		input := validProjectStructureInput()
		profile := input["repoProfileScaffold"].(map[string]any)
		profile[field] = namedObject(profile[field].(map[string]any))
		if _, err := scaffoldprofileplan.BuildResult(profile); err == nil {
			t.Fatal("control must be refused by the child owner")
		}
		if _, err := BuildResult(input); err == nil {
			t.Errorf("snapshot widened child admission for a named %s map", field)
		}
	}
}

func TestScaffoldChildAdmissionOwnsConsistencyAndPersistenceInputs(t *testing.T) {
	for _, source := range []string{"bootstrap", "repoProfileScaffold"} {
		t.Run(source, func(t *testing.T) {
			input := validProjectStructureInput()
			children, err := buildScaffoldChildren(input, cliexec.PathRenderer())
			if err != nil || children.bootstrap.Record.State != "passed" || children.repoProfile.Record.State != "passed" {
				t.Fatalf("child admission failed: %v", err)
			}
			beforeConsistency := pathConsistencyFailures(children.bootstrapInput, children.repoProfile.Plan)
			beforeBootstrap, err := stablejson.Marshal(children.bootstrapInput)
			if err != nil {
				t.Fatal(err)
			}
			beforeProfile, err := stablejson.Marshal(children.repoProfileInput)
			if err != nil {
				t.Fatal(err)
			}
			manifestBefore := g1ChildManifest(t, input, children)
			original := input[source].(map[string]any)
			original["repository"].(map[string]any)["profilePath"] = "inputs/changed-profile.json"
			if source == "bootstrap" {
				original["module"].(map[string]any)["specPath"] = "docs/specs/changed.json"
				original["ownerRoute"].(map[string]any)["specPaths"].([]any)[0] = "docs/specs/other.json"
				original["proofBindingPath"] = "inputs/changed-binding.json"
			} else {
				original["paths"].(map[string]any)["bindingPath"] = "inputs/changed-binding.json"
				original["repository"].(map[string]any)["primaryLanguages"].([]any)[0] = "changed"
			}
			afterBootstrap, err := stablejson.Marshal(children.bootstrapInput)
			if err != nil {
				t.Fatal(err)
			}
			afterProfile, err := stablejson.Marshal(children.repoProfileInput)
			if err != nil {
				t.Fatal(err)
			}
			if string(beforeBootstrap) != string(afterBootstrap) || string(beforeProfile) != string(afterProfile) {
				t.Error("caller changed parent persistence input after child admission")
			}
			if !reflect.DeepEqual(beforeConsistency, pathConsistencyFailures(children.bootstrapInput, children.repoProfile.Plan)) {
				t.Error("caller changed parent consistency after child admission")
			}
			if !reflect.DeepEqual(manifestBefore, g1ChildManifest(t, input, children)) {
				t.Error("caller changed parent manifest after child admission")
			}
		})
	}
}

func g1ChildManifest(t *testing.T, input map[string]any, children scaffoldChildren) map[string]any {
	t.Helper()
	paths, err := projectPaths(input["paths"])
	if err != nil {
		t.Fatal(err)
	}
	bootstrapManifest, err := gradualadoption.BootstrapMaterializationManifest(children.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	workflowInput, err := adoptionWorkflowInput(children.bootstrap, bootstrapManifest, children.repoProfile.Plan, paths, input["workflow"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildMaterializationManifest(materializationInput{
		adoptionWorkflowInput: workflowInput,
		bootstrapInput:        children.bootstrapInput,
		bootstrapManifest:     bootstrapManifest,
		bootstrapProfilePath:  children.bootstrap.RepositoryProfilePath(),
		paths:                 paths,
		repoProfileInput:      children.repoProfileInput,
		repoProfilePlan:       children.repoProfile.Plan,
		scaffoldID:            "proofkit.test.project-structure",
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
