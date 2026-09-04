package adoptionplan

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
)

// Build composes a read-only adoption plan from explicit caller intent and an
// already observed bounded repository inventory.
func Build(intent string, inventory repositoryinventory.Snapshot, stackPresetID string) (Plan, error) {
	admittedInventory, err := repositoryinventory.AdmitOutput(inventory.JSONValue())
	if err != nil {
		return Plan{}, fmt.Errorf("admit repository inventory: %w", err)
	}
	trust, tasks, err := intentPlan(intent)
	if err != nil {
		return Plan{}, err
	}
	guidance, err := nativeevidenceguidance.GuidanceReference()
	if err != nil {
		return Plan{}, err
	}
	var stackHint *stackpreset.PlanningHint
	if stackPresetID != "" {
		hint, ok := stackpreset.PlanningHintFor(stackPresetID)
		if !ok {
			return Plan{}, fmt.Errorf("stack preset must be one of: %s", joinStackIDs())
		}
		stackHint = &hint
	}
	return finalize(Plan{
		Intent:    intent,
		Inventory: admittedInventory,
		Packet: AuthoringPacket{
			GuidanceReference: guidance,
			InventoryRef:      admittedInventory.InventoryID,
			Tasks:             tasks,
		},
		StackHint:        stackHint,
		TrustDeclaration: trust,
	})
}

func intentPlan(intent string) (TrustDeclaration, []Task, error) {
	switch intent {
	case IntentFresh:
		return TrustDeclaration{Class: "owner_intent_required"}, freshTasks(), nil
	case IntentCodeBaseline:
		mode := capabilitymapadmission.TrustModeCodeBaseline
		return TrustDeclaration{CapabilityMapTrustMode: &mode, Class: "caller_declared_code_baseline"}, codeTasks(intent), nil
	case IntentAuditFromCode:
		mode := capabilitymapadmission.TrustModeAuditFromCode
		return TrustDeclaration{CapabilityMapTrustMode: &mode, Class: "untrusted_code_observation"}, codeTasks(intent), nil
	default:
		return TrustDeclaration{}, nil, fmt.Errorf("--mode requires fresh, code-baseline, or audit-from-code")
	}
}

func freshTasks() []Task {
	return []Task{
		newTask(1, "author-product-contract", nil, "candidate_behavior_statements", "Ask the consuming repository owner for observable outcomes, supported scenarios, guarantees, limits, edge cases, stable identifiers, owners, risk classes, and explicit non-claims. Do not infer product meaning from inventory filenames."),
		newTask(2, "materialize-requirement-source", commandRef("requirement-source-admission"), "candidate_requirement_source", "Materialize only owner-approved statements as a candidate requirement source, then admit that source before creating bindings or claiming coverage."),
		newTask(3, "design-native-evidence", commandRef("native-evidence-guidance"), "repository_specific_evidence_design", "For every admitted invariant, design a falsifier and native witness by resolving the referenced evidence-guidance slots under consuming-repository authority."),
	}
}

func codeTasks(intent string) []Task {
	observationInstruction := "Use the inventory only as non-semantic routing context. Ask the repository owner to select an explicit bounded code, test, and documentation scope, including a module root when root entries are opaque; inspect only that scope and materialize caller-owned capability observations without treating observed behavior as product truth."
	if intent == IntentCodeBaseline {
		observationInstruction = "Use the inventory only as non-semantic routing context. Ask the repository owner to select an explicit bounded code, test, and documentation scope, including a module root when root entries are opaque; materialize current behavior only from that scope as caller-declared baseline candidates, and keep every statement candidate-only until owner review and source admission."
	}
	return []Task{
		newTask(1, "materialize-capability-observations", nil, "caller_owned_capability_map", observationInstruction),
		newTask(2, "admit-capability-observations", commandRef("capability-map-admission"), "candidate_requirement_and_binding_seeds", "Run capability-map-admission with the plan's exact capabilityMapTrustMode; preserve unresolved owner questions and do not promote candidate seeds."),
		newTask(3, "review-and-author-requirements", commandRef("requirement-authoring-plan"), "owner_reviewed_requirement_candidates", "Require the consuming repository owner to accept, reject, or rewrite each candidate meaning before materializing stable requirement-source changes."),
		newTask(4, "design-native-evidence", commandRef("native-evidence-guidance"), "repository_specific_evidence_design", "For every owner-approved invariant, design a falsifier and native witness by resolving the referenced evidence-guidance slots under consuming-repository authority."),
	}
}

func newTask(order int, id string, commandID *string, outputKind string, instruction string) Task {
	return Task{
		CommandID:   commandID,
		Instruction: instruction,
		Order:       order,
		OutputKind:  outputKind,
		Owner:       "consuming_repository_owner",
		TaskID:      "proofkit.adoption-plan." + id,
	}
}

func commandRef(value string) *string {
	return &value
}

func joinStackIDs() string {
	return strings.Join(stackpreset.IDs(), ", ")
}
