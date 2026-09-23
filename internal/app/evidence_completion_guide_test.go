package app

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestEvidenceCompletionGuidesAreLazyAndCarrierBound(t *testing.T) {
	for _, item := range []struct {
		command, marker string
		commands        [][]string
	}{
		{"requirement-coverage-input-compose", "Declaration coverage input guide:", [][]string{
			{"requirement-coverage-input-compose", "--input", "<coverage-input>"},
			{"requirement-coverage-view", "--input", "<view-input>", "--format", "json"},
		}},
		{"receipt-currentness-scope", "Receipt currentness input guide:", [][]string{
			{"receipt-currentness-scope", "--input", "<currentness-input>"},
		}},
	} {
		t.Run(item.command, func(t *testing.T) {
			packet, _ := receiptHelpTemplate(t, item.command)
			code, output, diagnostic := executeAgentWorkflowCLI(t, []string{item.command, "--input", "-"}, bytes.NewReader(adoptionHelpJSON(t, packet)), PresentationCapabilities{})
			if code != 1 || output != "" || diagnostic == "" {
				t.Fatal("unfilled template must not invent admissible evidence")
			}
			for _, carrier := range []struct{ profile, python string }{
				{cliexec.ProfilePath, ""}, {cliexec.ProfileNPMOffline, ""}, {cliexec.ProfilePythonModule, "/example/python 3"},
			} {
				renderer, err := cliexec.AdmitLauncherProfile(carrier.profile, carrier.python)
				if err != nil {
					t.Fatal(err)
				}
				descriptor, _ := commandDescriptorFor(item.command)
				if got := guideCommands(t, commandUsageWithRenderer(descriptor, renderer), item.marker, renderer); !reflect.DeepEqual(got, item.commands) {
					t.Fatalf("guide argv differs: %v", got)
				}
			}
			for _, args := range [][]string{{"help"}, {"help", "families"}, {"native-evidence-guidance"}, {"native-evidence-guidance", "--help"}, {"changed-path-set", "--help"}} {
				_, output, _ := executeAgentWorkflowCLI(t, args, panicReader{}, PresentationCapabilities{})
				if strings.Contains(output, item.marker) {
					t.Fatalf("nested recipe must stay lazy: %v", args)
				}
			}
		})
	}
}

func TestCoverageGuideComposesActualInputsAndRetainsGaps(t *testing.T) {
	input, help := receiptHelpTemplate(t, "requirement-coverage-input-compose")
	materialization := adoptionHelpPacket(t, t.TempDir(), "fresh")
	input["composerInputId"], input["viewInputId"] = "example.compose", "example.view"
	input["selectedOwnerIds"] = []any{"example.backend"}
	input["requirementSource"] = materialization["requirementSources"].([]any)[0]
	sourceResult, err := requirementsourceadmission.Evaluate(input["requirementSource"])
	if err != nil || sourceResult.ExitCode != 0 {
		t.Fatalf("source premise: %v", err)
	}
	expectedSource, err := requirementsourceadmission.SourceValue(sourceResult.Source)
	if err != nil {
		t.Fatal(err)
	}
	input["requirementProofBinding"] = materialization["requirementProofBinding"].(map[string]any)["record"]
	input["testEvidenceInventory"] = materialization["testEvidenceInventory"].(map[string]any)["record"]
	universe := input["coverageUniverse"].(map[string]any)
	universe["universeId"], universe["completenessDeclaration"] = "example.universe", "selected_owner_surfaces"
	universe["ownerIds"] = []any{"example.backend"}
	universe["commandRefs"] = []any{"example.test.requests"}
	universe["codeSurfaces"] = []any{map[string]any{"surfaceId": "example.code", "ownerId": "example.backend", "path": "src"}}
	universe["specSurfaces"] = []any{map[string]any{"surfaceId": "example.spec", "ownerId": "example.backend", "path": "docs/specs/requests/requirements.v2.json"}}
	universe["testSurfaces"] = []any{map[string]any{"surfaceId": "example.test", "ownerId": "example.backend", "path": "src/request_test.go"}}
	commands := guideCommands(t, help, "Declaration coverage input guide:", cliexec.PathRenderer())
	composeArgs := fillGuideOperands(t, commands[0], map[string]string{"<coverage-input>": "-"})
	viewArgs := fillGuideOperands(t, commands[1], map[string]string{"<view-input>": "-"})
	for _, variant := range []string{"complete", "missing", "unmapped", "restored"} {
		t.Run(variant, func(t *testing.T) {
			candidate := decodeCLIJSON(t, string(adoptionHelpJSON(t, input))).(map[string]any)
			inventory := candidate["testEvidenceInventory"].(map[string]any)
			if variant == "missing" {
				inventory["entries"] = []any{}
			}
			if variant == "unmapped" {
				inventory["entries"] = append(inventory["entries"].([]any), map[string]any{
					"testId": "example.test.unmapped", "ownerId": "example.backend", "sourcePath": "src/unmapped_test.go",
					"selector": "src/unmapped_test.go::TestUnmapped", "evidenceClass": "helper_or_testkit",
					"requirementRefs": []any{}, "ownerInvariantRefs": []any{}, "commandRefs": []any{}, "witnessRefs": []any{},
					"falsifier": nil, "oracle": nil, "nonClaims": []any{"Unmapped fixture is not a declared semantic test."},
				})
			}
			code, wire, diagnostic := executeAgentWorkflowCLI(t, composeArgs, bytes.NewReader(adoptionHelpJSON(t, candidate)), PresentationCapabilities{})
			if code != 0 || diagnostic != "" {
				t.Fatalf("compose failed before downstream: %d %s", code, diagnostic)
			}
			composed := decodeCLIJSON(t, wire).(map[string]any)
			if !equalCLIJSON(t, composed["requirementSource"], expectedSource) {
				t.Fatal("composer lost source operands")
			}
			binding := composed["requirementProofBinding"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
			for field, want := range map[string]any{
				"requirementId": "REQ-EXAMPLE-001", "scenarioId": "example.requests.empty", "witnessId": "example.witness.empty",
				"witnessPath": "src/request_test.go", "commandIds": []any{"example.test.requests"}, "environmentClasses": []any{"local-go"},
			} {
				if !reflect.DeepEqual(binding[field], want) {
					t.Fatalf("composer changed qualified %s: %v", field, binding[field])
				}
			}
			composedUniverse := composed["coverageUniverse"].(map[string]any)
			for _, field := range []string{"ownerIds", "codeSurfaces", "specSurfaces", "commandRefs", "completenessDeclaration", "nonClaims"} {
				if !reflect.DeepEqual(composedUniverse[field], universe[field]) {
					t.Fatalf("composer changed declared universe %s", field)
				}
			}
			// Consume the actual wire bytes, not a manually rebuilt view input.
			code, output, diagnostic := executeAgentWorkflowCLI(t, viewArgs, strings.NewReader(wire), PresentationCapabilities{})
			if diagnostic != "" {
				t.Fatalf("view input did not round trip: %s", diagnostic)
			}
			view := decodeCLIJSON(t, output).(map[string]any)
			wantCode, wantState := 0, "passed"
			if variant == "missing" {
				wantCode, wantState = 1, "failed"
			}
			if code != wantCode || view["state"] != wantState || view["authority"] != "lookup_only" || view["viewKind"] != "proofkit.requirement-coverage-view" {
				t.Fatalf("view outcome differs: %d %v", code, view)
			}
			row := view["requirementCoverage"].([]any)[0].(map[string]any)
			wantIDs := []any{"example.test.empty"}
			if variant == "missing" {
				wantIDs = []any{}
			}
			if row["requirementId"] != "REQ-EXAMPLE-001" || row["ownerId"] != "example.backend" || row["specPath"] != "docs/specs/requests/requirements.v2.json" || !reflect.DeepEqual(row["testIds"], wantIDs) {
				t.Fatalf("view changed identity or test linkage: %v", row)
			}
			if variant == "missing" && !reflect.DeepEqual(view["deadZones"], []any{map[string]any{
				"deadZoneKind": "unbound_test_surface", "ownerId": "example.backend", "path": "src/request_test.go", "surfaceId": "example.test",
			}}) {
				t.Fatalf("missing test lost its declared coordinates: %v", view["deadZones"])
			}
			unmapped := view["unmappedTests"].([]any)
			if variant == "unmapped" {
				if len(unmapped) != 1 || unmapped[0].(map[string]any)["testId"] != "example.test.unmapped" {
					t.Fatalf("unmapped test disappeared: %v", unmapped)
				}
			} else if len(unmapped) != 0 {
				t.Fatalf("unexpected unmapped tests: %v", unmapped)
			}
		})
	}
	for _, field := range []string{"compactProofContract", "normalizedTestEvidenceInventory"} {
		candidate := cloneMap(t, input)
		candidate[field] = nil
		code, output, diagnostic := executeAgentWorkflowCLI(t, composeArgs, bytes.NewReader(adoptionHelpJSON(t, candidate)), PresentationCapabilities{})
		if code != 1 || output != "" || diagnostic == "" {
			t.Fatal("direct-mode foreign key must be absent, not null: " + field)
		}
	}
}

func currentnessGuideReport(t *testing.T, args []string, input map[string]any, wantCode int) map[string]any {
	t.Helper()
	code, output, diagnostic := executeAgentWorkflowCLI(t, args, bytes.NewReader(adoptionHelpJSON(t, input)), PresentationCapabilities{})
	if code != wantCode || diagnostic != "" {
		t.Fatalf("currentness result differs: %d %q", code, diagnostic)
	}
	result := decodeCLIJSON(t, output).(map[string]any)
	if result["reportKind"] != "proofkit.receipt-currentness-scope-admission" || result["reportId"] != "example.currentness" {
		t.Fatalf("currentness report identity differs: %v", result)
	}
	wantState := "passed"
	if wantCode != 0 {
		wantState = "failed"
	}
	if result["state"] != wantState {
		t.Fatalf("currentness state differs: %v", result["state"])
	}
	return result
}

func assertGuideCount(t *testing.T, result map[string]any, field string, want int) {
	t.Helper()
	if got := fmt.Sprint(result["summary"].(map[string]any)[field]); got != fmt.Sprint(want) {
		t.Fatalf("%s=%s, want %d", field, got, want)
	}
}
