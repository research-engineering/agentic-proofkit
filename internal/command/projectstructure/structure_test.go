package projectstructure

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func TestScaffoldOutputStructuresDescribeReachableStates(t *testing.T) {
	seen := map[string]bool{}
	renderers := map[string]cliexec.Renderer{"path": cliexec.PathRenderer()}
	for _, profile := range []struct{ name, python string }{{cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/tmp/proofkit venv/bin/python"}} {
		renderer, err := cliexec.AdmitLauncherProfile(profile.name, profile.python)
		if err != nil {
			t.Fatal(err)
		}
		renderers[profile.name] = renderer
	}
	shapes := outputMemberShapes()
	for name, input := range scaffoldStateFixtures() {
		for rendererName, renderer := range renderers {
			t.Run(name+"/"+rendererName, func(t *testing.T) {
				result, err := BuildResultWithRenderer(input, renderer)
				if err != nil {
					t.Fatal(err)
				}
				value := result.JSONValue()
				if !slices.Equal(slices.Sorted(maps.Keys(value)), schemaKeys(OutputStructure())) {
					t.Fatal("native scaffold inventory differs from its structure")
				}
				for key, shape := range shapes {
					if err := shape.CheckGenerated(value[key], key); err != nil {
						t.Fatal(err)
					}
				}
				if err := scaffoldprofileplan.OutputShape().CheckGenerated(value["repoProfileScaffoldPlan"], "repo profile plan"); err != nil {
					t.Fatal(err)
				}
				bootstrap, err := gradualadoption.BuildBootstrapResultWithRenderer(input["bootstrap"], renderer)
				if err != nil || !reflect.DeepEqual(bootstrap.JSONValue(), value["bootstrapReport"]) {
					t.Fatalf("embedded bootstrap is not the bootstrap command carrier: %v", err)
				}
				envelope, exit, err := BuildEnvelopeFromResult(result)
				if err != nil || exit != result.ExitCode {
					t.Fatalf("envelope phase drift: %v", err)
				}
				envelopeID := input["scaffoldId"].(string) + ".agent-envelope"
				if envelope["envelopeId"] != envelopeID {
					envelopeID = admit.DiagnosticRedactionMarker
					seen["envelope/redacted"] = true
				}
				if err := EnvelopeShape(envelopeID).CheckGenerated(envelope, "scaffold envelope"); err != nil {
					t.Fatal(err)
				}
				seen["state/"+result.Record.State] = true
				seen["plan/"+result.AdoptionWorkflowPlan["planState"].(string)] = true
				seen["bootstrap/"+result.Bootstrap.Record.State] = true
				seen[fmt.Sprintf("payload/%v", result.Manifest["payloadFileCount"])] = true
				seen[fmt.Sprintf("omitted/%d", len(envelope["omitted"].([]any)))] = true
				for _, raw := range result.Manifest["files"].([]any) {
					seen["source/"+raw.(map[string]any)["source"].(string)] = true
				}
			})
		}
	}
	for _, want := range []string{"state/passed", "state/failed", "plan/blocked", "plan/ready_for_caller_review", "bootstrap/failed",
		"payload/7", "payload/8", "source/repo_profile_scaffold", "omitted/0", "omitted/1", "envelope/redacted"} {
		if !seen[want] {
			t.Fatalf("reachable output domain was not exercised: %s", want)
		}
	}
}

func TestInputStructureAgreesWithNativeAdmission(t *testing.T) {
	set := func(path string, value any) func(map[string]any) {
		return func(input map[string]any) { setPath(input, path, value) }
	}
	drop := func(path string) func(map[string]any) {
		return func(input map[string]any) { deletePath(input, path) }
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		class  string
	}{
		{"positive", func(map[string]any) {}, "accepted"},
		{"open scaffold paths", set("paths.foreign", true), "accepted"},
		{"open workflow", set("workflow.foreign", []any{}), "accepted"},
		{"duplicate claims merge", set("nonClaims", []any{"claim", " claim"}), "accepted"},
		{"padded scaffold path", set("paths.workflowInputPath", " proofkit/workflow.json "), "accepted"},
		{"open bootstrap paths", set("bootstrap.paths.foreign", true), "accepted"},
		{"open bootstrap module", set("bootstrap.module.foreign", true), "accepted"},
		{"whitespace profile path", set("bootstrap.paths.adoptionProfilePath", " "), "accepted"},
		{"failed bootstrap", set("bootstrap.guidanceMode", "warn"), "accepted"},
		{"failed bootstrap module", set("bootstrap.module.requirementIds", false), "accepted"},
		{"unknown root", set("foreign", true), "structural"},
		{"missing schemaVersion", drop("schemaVersion"), "structural"},
		{"schemaVersion two", set("schemaVersion", json.Number("2")), "structural"},
		{"missing scaffoldId", drop("scaffoldId"), "structural"},
		{"invalid scaffoldId", set("scaffoldId", "1bad"), "structural"},
		{"missing nonClaims", drop("nonClaims"), "structural"},
		{"empty nonClaims", set("nonClaims", []any{}), "structural"},
		{"blank nonClaim", set("nonClaims", []any{" "}), "structural"},
		{"missing paths", drop("paths"), "structural"},
		{"paths array", set("paths", []any{}), "structural"},
		{"missing workflow path", drop("paths.workflowInputPath"), "structural"},
		{"blank bootstrap path", set("paths.bootstrapInputPath", " "), "structural"},
		{"missing workflow", drop("workflow"), "structural"},
		{"other scenario", set("workflow.scenario", "release_channel"), "structural"},
		{"missing scenario", drop("workflow.scenario"), "structural"},
		{"invalid workflowId", set("workflow.workflowId", "bad id"), "structural"},
		{"empty workflow nonClaims", set("workflow.nonClaims", []any{}), "structural"},
		{"missing repo profile", drop("repoProfileScaffold"), "structural"},
		{"repo profile unknown", set("repoProfileScaffold.foreign", true), "structural"},
		{"missing bootstrap", drop("bootstrap"), "structural"},
		{"bootstrap unknown", set("bootstrap.foreign", true), "structural"},
		{"bootstrap paths missing", drop("bootstrap.paths"), "structural"},
		{"bootstrap paths kind", set("bootstrap.paths", "paths"), "structural"},
		{"bootstrap guidance path", drop("bootstrap.paths.adoptionGuidancePath"), "structural"},
		{"bootstrap witness path blank", set("bootstrap.paths.witnessPlanInputPath", "\u2003"), "structural"},
		{"bootstrap profile path", drop("bootstrap.paths.adoptionProfilePath"), "structural"},
		{"bootstrap profile path empty", set("bootstrap.paths.adoptionProfilePath", ""), "structural"},
		{"bootstrap binding path", drop("bootstrap.proofBindingPath"), "structural"},
		{"bootstrap binding path blank", set("bootstrap.proofBindingPath", " "), "structural"},
		{"bootstrap module missing", drop("bootstrap.module"), "structural"},
		{"bootstrap spec path", drop("bootstrap.module.specPath"), "structural"},
		{"bootstrap repository profile", drop("bootstrap.repository.profilePath"), "structural"},
		{"secret nonClaim", set("nonClaims", []any{"api_" + "key=synthetic-scaffold-structure"}), "native"},
		{"escaping scaffold path", set("paths.bootstrapInputPath", "../bootstrap.json"), "native"},
		{"duplicate materialized path", set("paths.workflowInputPath", "proofkit/bootstrap.v1.json"), "native"},
		{"builtin workflow claim", set("workflow.nonClaims", []any{"Adoption workflow plans do not scan repository state."}), "native"},
		{"escaping bootstrap path", set("bootstrap.paths.adoptionProfilePath", "../adoption.json"), "native"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			input := validProjectStructureInput()
			item.mutate(input)
			_, nativeErr := BuildResult(input)
			structuralErr := scaffoldStructuralCheck(input)
			switch item.class {
			case "accepted":
				if nativeErr != nil || structuralErr != nil {
					t.Fatalf("accepted input diverged: native=%v structure=%v", nativeErr, structuralErr)
				}
			case "structural":
				if nativeErr == nil || structuralErr == nil {
					t.Fatalf("structural refusal diverged: native=%v structure=%v", nativeErr, structuralErr)
				}
			case "native":
				if nativeErr == nil || structuralErr != nil {
					t.Fatalf("native-only predicate diverged: native=%v structure=%v", nativeErr, structuralErr)
				}
			}
		})
	}
}

func TestInputStructureReusesAndNarrowsOwners(t *testing.T) {
	schema := InputStructure()
	properties := schema["properties"].(map[string]any)
	if !reflect.DeepEqual(properties["repoProfileScaffold"], scaffoldprofileplan.InputStructure()) {
		t.Fatal("repo profile scaffold input is not the standalone owner")
	}
	bootstrap := properties["bootstrap"].(map[string]any)
	base := gradualadoption.BootstrapInputStructure()
	for key, value := range base["properties"].(map[string]any) {
		if slices.Contains([]string{"module", "paths", "proofBindingPath", "repository"}, key) {
			continue
		}
		if !reflect.DeepEqual(bootstrap["properties"].(map[string]any)[key], value) {
			t.Fatalf("bootstrap member %s is not the standalone owner", key)
		}
	}
	want := []any{"bootstrapId", "budget", "guidanceMode", "module", "nativeWitnesses", "packageVersionRef", "paths", "proofBindingPath", "repository", "rollback", "schemaVersion"}
	if !reflect.DeepEqual(bootstrap["required"], want) {
		t.Fatalf("bootstrap composition requirements changed: %v", bootstrap["required"])
	}
	for _, path := range [][]string{{"paths"}, {"workflow"}, {"bootstrap", "paths"}, {"bootstrap", "module"}, {"bootstrap", "repository"}} {
		node := schema
		for _, key := range path {
			node = node["properties"].(map[string]any)[key].(map[string]any)
		}
		if node["additionalProperties"] != true {
			t.Fatalf("%v must stay open because native admission ignores extra members", path)
		}
	}
	if !reflect.DeepEqual(schema["required"], []any{"bootstrap", "nonClaims", "paths", "repoProfileScaffold", "scaffoldId", "schemaVersion", "workflow"}) || schema["additionalProperties"] != false {
		t.Fatal("root inventory changed")
	}
}

func TestScaffoldStructuresAreDetachedProjections(t *testing.T) {
	for _, build := range []func() map[string]any{InputStructure, OutputStructure, EnvelopeStructure} {
		first := build()
		first["properties"].(map[string]any)["foreign"] = true
		if reflect.DeepEqual(first, build()) {
			t.Fatal("structure projection aliases a prior caller")
		}
	}
	invalid, exit, err := BuildEnvelope(map[string]any{})
	if invalid != nil || exit != 1 || err == nil {
		t.Fatal("refused scaffold input must reach the CLI invalid-input envelope boundary")
	}
}

func scaffoldStateFixtures() map[string]map[string]any {
	fixtures := map[string]map[string]any{"passed": validProjectStructureInput()}
	drift := validProjectStructureInput()
	drift["repoProfileScaffold"].(map[string]any)["paths"].(map[string]any)["bindingPath"] = "proofkit/other.json"
	fixtures["drift"] = drift
	noPreset := validProjectStructureInput()
	delete(noPreset["repoProfileScaffold"].(map[string]any), "presetId")
	fixtures["no-preset"] = noPreset
	failedBootstrap := validProjectStructureInput()
	failedBootstrap["bootstrap"].(map[string]any)["guidanceMode"] = "warn"
	fixtures["failed-bootstrap"] = failedBootstrap
	otherProfile := validProjectStructureInput()
	otherProfile["repoProfileScaffold"].(map[string]any)["repository"].(map[string]any)["profilePath"] = "proofkit/other-profile.json"
	fixtures["other-profile"] = otherProfile
	replacedPayload := validProjectStructureInput()
	replacedPayload["repoProfileScaffold"].(map[string]any)["repository"].(map[string]any)["profilePath"] = "proofkit/adoption-profile.v1.json"
	fixtures["replaced-payload"] = replacedPayload
	unsafe := validProjectStructureInput()
	bootstrap := unsafe["bootstrap"].(map[string]any)
	bootstrap["module"].(map[string]any)["specPath"] = "docs/spec\u202e.md"
	bootstrap["ownerRoute"].(map[string]any)["specPaths"] = []any{"docs/spec\u202e.md"}
	fixtures["unsafe-reference"] = unsafe
	redacted := validProjectStructureInput()
	redacted["scaffoldId"] = "eyJfixture.owner"
	fixtures["redacted"] = redacted
	return fixtures
}

// This test-only restatement of the scaffold-owned schema clauses is checked
// against native admission; reused bootstrap and repo-profile owners keep
// their own oracles, and the public schema is exercised by the Node oracle.
func scaffoldStructuralCheck(input map[string]any) error {
	text, path := jsonshape.NonBlankString(), jsonshape.StringGrammar(`[\s\S]+`)
	for key := range input {
		if !slices.Contains(inputKeys, key) {
			return errors.New("unknown root member")
		}
	}
	checks := []struct {
		path  string
		shape jsonshape.Shape
	}{
		{"nonClaims", jsonshape.Array(text, 1)}, {"scaffoldId", identifierShape()}, {"schemaVersion", jsonshape.IntegerLiteral(1)},
		{"paths.bootstrapInputPath", text}, {"paths.repoProfileScaffoldInputPath", text}, {"paths.workflowInputPath", text},
		{"workflow.nonClaims", jsonshape.Array(text, 1)}, {"workflow.scenario", jsonshape.StringLiteral("new_repository")}, {"workflow.workflowId", identifierShape()},
		{"bootstrap.paths.adoptionGuidancePath", text}, {"bootstrap.paths.adoptionProfilePath", path}, {"bootstrap.paths.witnessPlanInputPath", text},
		{"bootstrap.proofBindingPath", text}, {"bootstrap.module.specPath", path}, {"bootstrap.repository.profilePath", path},
	}
	for _, check := range checks {
		value, ok := lookup(input, check.path)
		if !ok {
			return fmt.Errorf("missing %s", check.path)
		}
		if err := check.shape.CheckGenerated(value, check.path); err != nil {
			return err
		}
	}
	if _, err := scaffoldprofileplan.InputShape().Admit(input["repoProfileScaffold"], "repo profile"); err != nil {
		return err
	}
	bootstrap, _ := input["bootstrap"].(map[string]any)
	for key := range bootstrap {
		if !slices.Contains(schemaKeys(gradualadoption.BootstrapInputStructure()), key) {
			return errors.New("unknown bootstrap member")
		}
	}
	return nil
}

func lookup(record map[string]any, path string) (any, bool) {
	var current any = record
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		if current, ok = object[part]; !ok {
			return nil, false
		}
	}
	return current, true
}

func schemaKeys(schema map[string]any) []string {
	return slices.Sorted(maps.Keys(schema["properties"].(map[string]any)))
}

func setPath(record map[string]any, path string, value any) {
	parts := strings.Split(path, ".")
	current := record
	for _, part := range parts[:len(parts)-1] {
		current = current[part].(map[string]any)
	}
	current[parts[len(parts)-1]] = value
}

func deletePath(record map[string]any, path string) {
	parts := strings.Split(path, ".")
	current := record
	for _, part := range parts[:len(parts)-1] {
		current = current[part].(map[string]any)
	}
	delete(current, parts[len(parts)-1])
}
