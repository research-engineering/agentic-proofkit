package requirementcoverageinput

import (
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// InputStructure refines the downstream owner's fields with the composer's
// presence-based modes. Child schemas and local references remain owner-owned.
func InputStructure() (map[string]any, error) {
	schema, err := requirementcoverageview.InputStructure()
	if err != nil {
		return nil, err
	}
	schema["$id"] = "urn:proofkit:requirement-coverage-input-compose:input:schema:3"
	properties := schema["properties"].(map[string]any)
	properties["composerInputId"] = jsonshape.String().JSONSchema()
	properties["selectedOwnerIds"] = jsonshape.Array(jsonshape.String(), 1).JSONSchema()
	properties["testEvidenceInventory"] = testevidenceinventory.DirectBoundaryShape().JSONSchema()
	properties["normalizedTestEvidenceInventory"] = map[string]any{"$ref": "#/$defs/normalizedInventory"}
	required := append(schema["required"].([]any), "composerInputId", "selectedOwnerIds")
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	schema["oneOf"] = []any{
		map[string]any{"required": []any{"requirementProofBinding", "testEvidenceInventory"}, "properties": map[string]any{
			"requirementProofBinding": map[string]any{"type": "object"}, "compactProofContract": false, "normalizedTestEvidenceInventory": false,
		}},
		map[string]any{"required": []any{"compactProofContract", "normalizedTestEvidenceInventory", "localEnvironmentPolicy"}, "properties": map[string]any{
			"compactProofContract": map[string]any{"type": "object"}, "requirementProofBinding": false, "testEvidenceInventory": false,
			"localEnvironmentPolicy": map[string]any{"type": "object"},
		}},
	}
	schema["description"] = "Exactly one inventory key must be present. Direct mode requires direct inventory (bare or wrapped) and requirementProofBinding, and forbids even null compact/envelope fields. Normalized mode requires the envelope and compact contract, and forbids even null direct inventory/binding fields. The selected owners must equal the universe owners. Native Build re-admits the composed output through coverage-view; passed source/binding/inventory admission, provenance joins, normalized text and path policies remain native obligations."
	return schema, nil
}

// OutputStructure retains the receiving contract and narrows it to compose's
// present fields, canonical inventory and canonical normalized envelope.
func OutputStructure() (map[string]any, error) {
	schema, err := requirementcoverageview.InputStructure()
	if err != nil {
		return nil, err
	}
	schema["$id"] = "urn:proofkit:requirement-coverage-input-compose:output:schema:3"
	properties := schema["properties"].(map[string]any)
	properties["testEvidenceInventory"] = testevidenceinventory.CanonicalInventoryShape().JSONSchema()
	properties["normalizedTestEvidenceInventory"] = map[string]any{"$ref": "#/$defs/normalizedInventory"}
	schema["$defs"].(map[string]any)["normalizedInventory"] = testevidenceinventory.NormalizedProjectionStructure()
	required := []any{}
	for name := range properties {
		if name != "normalizedTestEvidenceInventory" {
			required = append(required, name)
		}
	}
	slices.SortFunc(required, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
	schema["required"] = required
	variants := schema["oneOf"].([]any)
	variants[0].(map[string]any)["properties"].(map[string]any)["normalizedTestEvidenceInventory"] = false
	compact := variants[1].(map[string]any)
	compact["required"] = append(compact["required"].([]any), "normalizedTestEvidenceInventory")
	schema["description"] = "Producer refinement of requirement-coverage-view input: all common fields are emitted, including a null unused binding and optional-input defaults. Compact mode emits the canonical source envelope; direct mode omits it. No execution, oracle-adequacy or completeness claim follows from structural validity."
	return schema, nil
}
