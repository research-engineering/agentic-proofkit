// Package adoptionplan owns the non-authoritative adoption front-door plan.
package adoptionplan

import (
	"encoding/json"
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/nativeevidenceguidance"
	"github.com/research-engineering/agentic-proofkit/internal/command/repositoryinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	SchemaVersion = 1
	PlanKind      = "proofkit.adoption-plan"
	PacketKind    = "proofkit.candidate-authoring-packet-template"
	PlanState     = "authoring_required"

	IntentAuditFromCode = "audit-from-code"
	IntentCodeBaseline  = "code-baseline"
	IntentFresh         = "fresh"

	MaximumOutputBytes = 192 << 10
	MaximumTextBytes   = 8 << 10
	MaximumTextLines   = 24
)

var boundaryNonClaims = []string{
	"Adoption plans do not infer or generate requirement meaning, invariant text, product promises, owner decisions, or proof adequacy from repository inventory or stack hints.",
	"Adoption plans do not read source trees, write files, execute commands or witnesses, promote candidate data, approve merge, release, rollout, or production readiness.",
	"Selecting code-baseline records an explicit caller declaration; it does not independently prove that current code is correct or suitable as product truth.",
	"Stack hints are optional non-authoritative suggestions and cannot change the selected source-trust intent.",
}

var intentValues = []string{IntentAuditFromCode, IntentCodeBaseline, IntentFresh}

// IntentValues returns the closed public source-trust vocabulary in canonical
// order. CLI adapters consume this owner rather than repeating mode literals.
func IntentValues() []string {
	return append([]string(nil), intentValues...)
}

func IsIntent(value string) bool {
	for _, intent := range intentValues {
		if value == intent {
			return true
		}
	}
	return false
}

type TrustDeclaration struct {
	CapabilityMapTrustMode *string
	Class                  string
}

type Task struct {
	CommandID   *string
	Instruction string
	Order       int
	OutputKind  string
	Owner       string
	TaskID      string
}

type AuthoringPacket struct {
	GuidanceReference nativeevidenceguidance.Reference
	InventoryRef      string
	Tasks             []Task
}

type Plan struct {
	Intent           string
	Inventory        repositoryinventory.Snapshot
	Packet           AuthoringPacket
	PlanID           string
	StackHint        *stackpreset.PlanningHint
	TrustDeclaration TrustDeclaration
}

type TextLine struct {
	Label string
	Value string
}

func (plan Plan) JSONValue() map[string]any {
	var stackHint any
	if plan.StackHint != nil {
		stackHint = plan.StackHint.JSONValue()
	}
	var capabilityMapTrustMode any
	if plan.TrustDeclaration.CapabilityMapTrustMode != nil {
		capabilityMapTrustMode = *plan.TrustDeclaration.CapabilityMapTrustMode
	}
	return map[string]any{
		"authority":           "derived_non_authoritative_plan",
		"authoringPacket":     packetValue(plan.Packet),
		"intent":              plan.Intent,
		"nonClaims":           admit.StringSliceToAny(boundaryNonClaims),
		"planId":              plan.PlanID,
		"planKind":            PlanKind,
		"repositoryInventory": plan.Inventory.JSONValue(),
		"schemaVersion":       json.Number("1"),
		"sourceTrust": map[string]any{
			"capabilityMapTrustMode": capabilityMapTrustMode,
			"declarationClass":       plan.TrustDeclaration.Class,
		},
		"stackHint": stackHint,
		"state":     PlanState,
		"summary": map[string]any{
			"codeBaselineDeclared":       plan.Intent == IntentCodeBaseline,
			"generatedBindingCount":      json.Number("0"),
			"generatedRequirementCount":  json.Number("0"),
			"observedCatalogFileCount":   json.Number(fmt.Sprintf("%d", len(plan.Inventory.Entries))),
			"omittedRecognizedCount":     json.Number(fmt.Sprintf("%d", len(plan.Inventory.Omissions.OmittedRecognized))),
			"selectedStackPreset":        selectedStackPreset(plan.StackHint),
			"taskCount":                  json.Number(fmt.Sprintf("%d", len(plan.Packet.Tasks))),
			"unrecognizedRootEntryCount": json.Number(fmt.Sprintf("%d", plan.Inventory.Omissions.UnrecognizedCount)),
		},
	}
}

func packetValue(packet AuthoringPacket) map[string]any {
	tasks := make([]any, 0, len(packet.Tasks))
	for _, task := range packet.Tasks {
		var commandID any
		if task.CommandID != nil {
			commandID = *task.CommandID
		}
		tasks = append(tasks, map[string]any{
			"commandId":   commandID,
			"instruction": task.Instruction,
			"order":       json.Number(fmt.Sprintf("%d", task.Order)),
			"outputKind":  task.OutputKind,
			"owner":       task.Owner,
			"taskId":      task.TaskID,
		})
	}
	return map[string]any{
		"authority":                "candidate_only",
		"inventoryRef":             packet.InventoryRef,
		"nativeEvidenceGuidance":   packet.GuidanceReference.JSONValue(),
		"packetKind":               PacketKind,
		"proposedBindingCount":     json.Number("0"),
		"proposedRequirementCount": json.Number("0"),
		"tasks":                    tasks,
	}
}

func selectedStackPreset(hint *stackpreset.PlanningHint) any {
	if hint == nil {
		return nil
	}
	return hint.PresetID
}

func finalize(plan Plan) (Plan, error) {
	identity := plan.JSONValue()
	delete(identity, "planId")
	planID, err := digest.StableJSONSHA256Ref(identity)
	if err != nil {
		return Plan{}, err
	}
	plan.PlanID = planID
	if err := validateOutputByteLimit(plan, MaximumOutputBytes); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func validateOutputByteLimit(plan Plan, maximum int) error {
	encoded, err := stablejson.Marshal(plan.JSONValue())
	if err != nil {
		return err
	}
	if len(encoded) > maximum {
		return fmt.Errorf("adoption plan exceeds output byte limit")
	}
	return nil
}
