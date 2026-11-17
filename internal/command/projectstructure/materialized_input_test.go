package projectstructure

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/schemacheck"
)

func TestScaffoldPreparedInputPathsDistinguishStdin(t *testing.T) {
	for _, field := range []string{
		"paths.bootstrapInputPath", "paths.repoProfileScaffoldInputPath", "paths.workflowInputPath",
		"bootstrap.paths.adoptionGuidancePath", "bootstrap.paths.adoptionProfilePath", "bootstrap.paths.witnessPlanInputPath",
	} {
		for _, path := range []string{"-", "inputs/-.json", "inputs/-", "input-with-hyphens.json"} {
			t.Run(field+"/"+path, func(t *testing.T) {
				input := validProjectStructureInput()
				setPath(input, field, path)
				refused := path == "-"
				for _, build := range []func(any) (map[string]any, int, error){Build, BuildEnvelope} {
					output, exit, err := build(input)
					if refused {
						if err == nil || output != nil || exit != 1 || !strings.Contains(err.Error(), "materialized file, not stdin") {
							t.Fatalf("prepared stdin did not refuse before output: exit=%d err=%v", exit, err)
						}
					} else if err != nil || exit != 0 {
						t.Fatalf("ordinary prepared path refused: exit=%d err=%v", exit, err)
					}
				}
				schema := InputStructure()
				node := schema
				for _, key := range strings.Split(field, ".") {
					node = node["properties"].(map[string]any)[key].(map[string]any)
				}
				if !reflect.DeepEqual(node["not"], map[string]any{"const": "-"}) {
					t.Fatal("prepared path lacks the exact not-const stdin exclusion")
				}
				if err := schemacheck.Validate(schema, input); (err != nil) != refused {
					t.Fatalf("prepared path structure disagrees: refused=%t err=%v", refused, err)
				}
			})
		}
	}
	for _, field := range []string{"paths.bootstrapInputPath", "paths.repoProfileScaffoldInputPath", "paths.workflowInputPath"} {
		input := validProjectStructureInput()
		setPath(input, field, " - ")
		if _, err := BuildResult(input); err == nil {
			t.Fatalf("%s trimmed stdin sentinel was accepted", field)
		}
	}
	for _, field := range []string{"bootstrap.paths.adoptionGuidancePath", "bootstrap.paths.witnessPlanInputPath"} {
		input := validProjectStructureInput()
		setPath(input, field, " - ")
		result, err := BuildResult(input)
		if err != nil || result.ExitCode != 0 {
			t.Fatalf("%s exact non-sentinel path refused: exit=%d err=%v", field, result.ExitCode, err)
		}
	}
}

func TestScaffoldPreparedInputsRoundTripThroughChildren(t *testing.T) {
	input := validProjectStructureInput()
	paths := []struct{ field, route string }{
		{"paths.repoProfileScaffoldInputPath", "scaffold-profile-plan"},
		{"paths.bootstrapInputPath", "gradual-adoption-bootstrap"},
		{"paths.workflowInputPath", "adoption-workflow-plan"},
		{"bootstrap.paths.adoptionProfilePath", "gradual-adoption"},
		{"bootstrap.paths.adoptionGuidancePath", "gradual-adoption-guidance"},
		{"bootstrap.paths.witnessPlanInputPath", "witness-plan"},
	}
	for _, item := range paths {
		setPath(input, item.field, "inputs/"+item.route+" input-.json")
	}
	result, err := BuildResult(input)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("scaffold control: exit=%d err=%v", result.ExitCode, err)
	}
	commands := result.Manifest["nextCommands"].([]any)
	files := map[string]any{}
	for _, raw := range result.Manifest["files"].([]any) {
		file := raw.(map[string]any)
		if file["materializationStatus"] != "payload_available" {
			continue
		}
		content := file["content"].(string)
		payload, err := admission.DecodeJSON(strings.NewReader(content), int64(len(content)))
		if err != nil {
			t.Fatal(err)
		}
		files[file["path"].(string)] = payload
	}
	for _, item := range paths {
		path, _ := lookup(input, item.field)
		if !slices.Contains(commands, any(cliexec.PathRenderer().DisplayCommand(item.route, "--input", path.(string)))) {
			t.Fatalf("%s command does not name its prepared file", item.route)
		}
		payload, ok := files[path.(string)]
		if !ok {
			t.Fatalf("%s has no prepared payload at %s", item.route, path)
		}
		var code int
		switch item.route {
		case "scaffold-profile-plan":
			var child scaffoldprofileplan.Result
			child, err = scaffoldprofileplan.BuildResult(payload)
			code = child.ExitCode
		case "gradual-adoption-bootstrap":
			_, code, err = gradualadoption.BuildBootstrap(payload)
		case "adoption-workflow-plan":
			if schemaErr := schemacheck.Validate(adoptionworkflow.InputStructure(), payload); schemaErr != nil {
				t.Fatal(schemaErr)
			}
			_, code, err = adoptionworkflow.Build(payload)
		case "gradual-adoption":
			_, code, err = gradualadoption.Build(payload)
		case "gradual-adoption-guidance":
			_, code, err = gradualadoption.BuildGuidance(payload, gradualadoption.GuidanceOptions{})
		case "witness-plan":
			_, err = witnessplan.Build(payload)
		default:
			t.Fatal("unexercised child")
		}
		if err != nil || code != 0 {
			t.Fatalf("%s refused its prepared payload: exit=%d err=%v", item.route, code, err)
		}
	}
	refs := result.AdoptionWorkflowInput["inputRefs"].([]any)
	if len(refs) != 4 {
		t.Fatalf("workflow ref count=%d, want 4", len(refs))
	}
	refRoutes := map[string]string{
		"bootstrap_witness_plan": "witness-plan", "gradual_adoption_bootstrap": "gradual-adoption-bootstrap",
		"gradual_adoption_guidance": "gradual-adoption-guidance", "repo_profile_scaffold": "scaffold-profile-plan",
	}
	for _, raw := range refs {
		ref := raw.(map[string]any)
		route, ok := refRoutes[ref["inputKind"].(string)]
		if !ok || ref["path"] != "inputs/"+route+" input-.json" {
			t.Fatalf("workflow ref %s does not name its child input", ref["refId"])
		}
		delete(refRoutes, ref["inputKind"].(string))
		if _, ok := files[ref["path"].(string)]; !ok {
			t.Fatalf("workflow ref %s does not resolve to a prepared child input", ref["refId"])
		}
	}
	if len(refRoutes) != 0 {
		t.Fatal("workflow omitted a prepared child input kind")
	}
}

func TestScaffoldPreservesNonInputDashTargets(t *testing.T) {
	for _, field := range []string{
		"bootstrap.paths.adoptionReportArtifactPath", "bootstrap.paths.guidanceReportArtifactPath",
		"bootstrap.module.specPath", "bootstrap.proofBindingPath", "bootstrap.repository.profilePath",
	} {
		t.Run(field, func(t *testing.T) {
			input := validProjectStructureInput()
			setPath(input, field, "-")
			switch field {
			case "bootstrap.module.specPath":
				setPath(input, "bootstrap.ownerRoute.specPaths", []any{"-"})
			case "bootstrap.proofBindingPath":
				setPath(input, "repoProfileScaffold.paths.bindingPath", "-")
				setPath(input, "bootstrap.ownerRoute.proofBindingPaths", []any{"-"})
			case "bootstrap.repository.profilePath":
				setPath(input, "repoProfileScaffold.repository.profilePath", "-")
			}
			if result, err := BuildResult(input); err != nil || result.ExitCode != 0 {
				t.Fatalf("non-input target was narrowed: exit=%d err=%v", result.ExitCode, err)
			}
			if err := schemacheck.Validate(InputStructure(), input); err != nil {
				t.Fatal(err)
			}
		})
	}
}
