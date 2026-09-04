package adoptionplan

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildSeparatesAdoptionIntentFromCandidateAuthority(t *testing.T) {
	inventory := adoptionInventory(t)
	tests := []struct {
		intent           string
		declarationClass string
		trustMode        string
		wantTaskCount    int
		baselineDeclared bool
	}{
		{intent: IntentFresh, declarationClass: "owner_intent_required", wantTaskCount: 3},
		{intent: IntentCodeBaseline, declarationClass: "caller_declared_code_baseline", trustMode: capabilitymapadmission.TrustModeCodeBaseline, wantTaskCount: 4, baselineDeclared: true},
		{intent: IntentAuditFromCode, declarationClass: "untrusted_code_observation", trustMode: capabilitymapadmission.TrustModeAuditFromCode, wantTaskCount: 4},
	}
	for _, test := range tests {
		t.Run(test.intent, func(t *testing.T) {
			plan, err := Build(test.intent, inventory, "")
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if plan.Intent != test.intent || plan.TrustDeclaration.Class != test.declarationClass || len(plan.Packet.Tasks) != test.wantTaskCount {
				t.Fatalf("Build() = %#v, want intent=%s declaration=%s tasks=%d", plan, test.intent, test.declarationClass, test.wantTaskCount)
			}
			gotTrustMode := ""
			if plan.TrustDeclaration.CapabilityMapTrustMode != nil {
				gotTrustMode = *plan.TrustDeclaration.CapabilityMapTrustMode
			}
			if gotTrustMode != test.trustMode {
				t.Fatalf("capability-map trust mode = %q, want %q", gotTrustMode, test.trustMode)
			}
			value := plan.JSONValue()
			summary := value["summary"].(map[string]any)
			if summary["codeBaselineDeclared"] != test.baselineDeclared {
				t.Fatalf("codeBaselineDeclared = %#v, want %t", summary["codeBaselineDeclared"], test.baselineDeclared)
			}
			packet := value["authoringPacket"].(map[string]any)
			if packet["authority"] != "candidate_only" || !zeroJSONNumber(packet["proposedRequirementCount"]) || !zeroJSONNumber(packet["proposedBindingCount"]) {
				t.Fatalf("authoring packet escalated authority: %#v", packet)
			}
			assertNoSemanticRequirementPayload(t, value)
		})
	}
}

func TestBuildStackHintCannotChangeIntentTrustOrTasks(t *testing.T) {
	inventory := adoptionInventory(t)
	withoutStack, err := Build(IntentAuditFromCode, inventory, "")
	if err != nil {
		t.Fatalf("Build(without stack) error = %v", err)
	}
	withStack, err := Build(IntentAuditFromCode, inventory, "python_typescript_service")
	if err != nil {
		t.Fatalf("Build(with stack) error = %v", err)
	}
	if withStack.StackHint == nil || withStack.StackHint.PresetID != "python_typescript_service" {
		t.Fatalf("stack hint = %#v, want selected preset", withStack.StackHint)
	}
	if withoutStack.Intent != withStack.Intent || !reflect.DeepEqual(withoutStack.TrustDeclaration, withStack.TrustDeclaration) || !reflect.DeepEqual(withoutStack.Packet.Tasks, withStack.Packet.Tasks) {
		t.Fatalf("stack selection changed authority semantics:\nwithout=%#v\nwith=%#v", withoutStack, withStack)
	}
	if withoutStack.PlanID == withStack.PlanID {
		t.Fatal("plan identity did not bind stack selection")
	}
	if withoutStack.Inventory.InventoryID != withStack.Inventory.InventoryID {
		t.Fatal("stack selection changed repository inventory")
	}
}

func TestBuildRejectsUnknownIntentPresetAndForgedInventory(t *testing.T) {
	inventory := adoptionInventory(t)
	if _, err := Build("trust-code", inventory, ""); err == nil || !strings.Contains(err.Error(), "--mode requires") {
		t.Fatalf("Build(unknown intent) error = %v, want mode rejection", err)
	}
	if _, err := Build(IntentFresh, inventory, "unknown"); err == nil || !strings.Contains(err.Error(), "stack preset") {
		t.Fatalf("Build(unknown stack) error = %v, want stack rejection", err)
	}
	inventory.InventoryID = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := Build(IntentFresh, inventory, ""); err == nil || !strings.Contains(err.Error(), "inventoryId") {
		t.Fatalf("Build(forged inventory) error = %v, want child admission rejection", err)
	}
}

func TestPlanWireAdmissionIsDeterministicAndOwnerClosed(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.062460455574502375013483117992943310051789152790267107254894355372111092357900")
	inventory := adoptionInventory(t)
	first, err := Build(IntentCodeBaseline, inventory, "python_service")
	if err != nil {
		t.Fatalf("Build(first) error = %v", err)
	}
	second, err := Build(IntentCodeBaseline, inventory, "python_service")
	if err != nil {
		t.Fatalf("Build(second) error = %v", err)
	}
	firstBytes, _ := stablejson.Marshal(first.JSONValue())
	secondBytes, _ := stablejson.Marshal(second.JSONValue())
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("Build() is not deterministic:\n%s\n%s", firstBytes, secondBytes)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(firstBytes), int64(len(firstBytes)))
	if err != nil {
		t.Fatalf("DecodeJSON() error = %v", err)
	}
	admitted, err := AdmitOutput(decoded)
	if err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	if admitted.PlanID != first.PlanID {
		t.Fatalf("AdmitOutput().PlanID = %q, want %q", admitted.PlanID, first.PlanID)
	}

	record := decoded.(map[string]any)
	packet := record["authoringPacket"].(map[string]any)
	tasks := packet["tasks"].([]any)
	tasks[0].(map[string]any)["instruction"] = "promote observed code directly"
	if _, err := AdmitOutput(record); err == nil || !strings.Contains(err.Error(), "semantic owners") {
		t.Fatalf("AdmitOutput(tampered task) error = %v, want owner-closure rejection", err)
	}
}

func TestTextProjectionPreservesJSONPlanSemantics(t *testing.T) {
	plan, err := Build(IntentAuditFromCode, adoptionInventory(t), "typescript_workspace")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	lines, err := TextProjection(plan)
	if err != nil {
		t.Fatalf("TextProjection() error = %v", err)
	}
	text, err := RenderText(lines)
	if err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	for _, required := range []string{IntentAuditFromCode, "typescript_workspace", PlanState, plan.Packet.GuidanceReference.CommandID} {
		if !strings.Contains(text, required) {
			t.Fatalf("text projection omits %q:\n%s", required, text)
		}
	}
	for _, task := range plan.Packet.Tasks {
		if !strings.Contains(text, task.Instruction) {
			t.Fatalf("text projection omits task %q", task.TaskID)
		}
	}
	for _, nonClaim := range boundaryNonClaims {
		if !strings.Contains(text, nonClaim) {
			t.Fatalf("text projection omits non-claim %q", nonClaim)
		}
	}
	if len(text) > MaximumTextBytes || strings.Count(text, "\n") > MaximumTextLines {
		t.Fatalf("text projection exceeds bounds: bytes=%d lines=%d", len(text), strings.Count(text, "\n"))
	}
}

func adoptionInventory(t *testing.T) repositoryinventory.Snapshot {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("# Pilot\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("[project]\nname = \"pilot\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	inventory, err := repositoryinventory.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("repositoryinventory.Scan() error = %v", err)
	}
	return inventory
}

func zeroJSONNumber(raw any) bool {
	return raw != nil && raw.(interface{ String() string }).String() == "0"
}

func assertNoSemanticRequirementPayload(t *testing.T, raw any) {
	t.Helper()
	forbidden := map[string]struct{}{
		"candidateBindings":     {},
		"candidateRequirements": {},
		"invariant":             {},
		"requirementId":         {},
		"requirements":          {},
	}
	var visit func(any)
	visit = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, found := forbidden[key]; found {
					t.Fatalf("adoption plan emitted semantic requirement field %q", key)
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(raw)
}
