package adoptioncontract

import (
	"maps"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionworkflow"
	"github.com/research-engineering/agentic-proofkit/internal/command/gradualadoption"
	"github.com/research-engineering/agentic-proofkit/internal/command/pilotadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

const draft = "https://json-schema.org/draft/2020-12/schema"

// Child records are admitted as objects in every mode, but only the selected
// mode's children reach their owner's admission.
const unselected = "Must be an object; this mode does not admit its members."

// Every --mode admits the aggregate root and child envelope headers, then
// delegates exactly one child path to its owner. The variants are keyed by the
// CLI options that change delegated admission; output-shape flags do not.
func AdoptionInputStructure() map[string]any {
	gradual := member(gradualadoption.ContractInputStructure())
	addUnselected(gradual, "bootstrap", "guidance")
	gradual["description"] = "input is the gradual adoption input; bootstrap and guidance must be objects but are not admitted in adoption mode."
	return aggregate(workflow(false), gradual, pilot(), nil)
}

func BootstrapInputStructure() map[string]any {
	return aggregate(workflow(false), member(gradualadoption.BootstrapContractInputStructure()), pilot(), nil)
}

func GuidanceInputStructure(modeOverride, scopeOverride, touchedOverride bool) map[string]any {
	gradual := member(gradualadoption.GuidanceContractInputStructure(modeOverride, scopeOverride, touchedOverride))
	addUnselected(gradual, "bootstrap")
	gradual["description"] = "guidance and input are admitted as by gradual-adoption-guidance --contract-envelope with the same override flags; bootstrap must be an object but is not admitted in guidance mode."
	return aggregate(workflow(false), gradual, pilot(), nil)
}

// pilotVariant is "all", "first" or "stack-diverse".
func PilotInputStructure(pilotVariant string) map[string]any {
	fields := map[string][]string{"all": {"input", "stackDiverseInput"}, "first": {"input"}, "stack-diverse": {"stackDiverseInput"}}[pilotVariant]
	if len(fields) == 0 {
		panic("adoption contract pilot structure has an unknown variant")
	}
	child := pilotadmission.ContractInputStructure("input", "stackDiverseInput")
	defs := child["$defs"].(map[string]any)
	delete(child, "$defs")
	for _, field := range []string{"input", "stackDiverseInput"} {
		if !slices.Contains(fields, field) {
			child["properties"].(map[string]any)[field] = unselectedObject()
		}
	}
	child["description"] = "The selected pilot input members are direct pilot inputs; an unselected member must be an object but is not admitted."
	return aggregate(workflow(false), gradualHeader(), member(child), defs)
}

func WorkflowInputStructure() map[string]any {
	return aggregate(workflow(true), gradualHeader(), pilot(), nil)
}

// AgentOutputStructure is the --agent-envelope carrier of one mode: the child
// envelope for admitted input or the shared invalid-input repair packet.
func AgentOutputStructure(mode string) map[string]any {
	switch mode {
	case "bootstrap":
		return sum(gradualadoption.BootstrapEnvelopeStructure(), agentenvelope.InvalidInputStructure())
	case "guidance":
		return sum(gradualadoption.GuidanceEnvelopeStructure(), agentenvelope.InvalidInputStructure())
	case "workflow":
		return adoptionworkflow.EnvelopeOutputStructure()
	}
	panic("adoption contract agent envelope mode is unsupported")
}

func aggregate(workflow, gradual, pilot, defs map[string]any) map[string]any {
	nonClaims := leaf(jsonshape.Array(jsonshape.NonBlankString(), 0))
	nonClaims["uniqueItems"] = true
	fields := map[string]any{
		"envelopeId": leaf(jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		"gradual":    gradual, "nonClaims": nonClaims, "pilot": pilot, "workflow": workflow,
	}
	if len(fields) != len(aggregateKeys) {
		panic("aggregate structure differs from its native member inventory")
	}
	for _, key := range aggregateKeys {
		if _, ok := fields[key]; !ok {
			panic("aggregate structure omits a native member")
		}
	}
	fields["schema"] = leaf(jsonshape.StringLiteral(aggregateEnvelopeSchema))
	schema := closed(fields)
	schema["$schema"] = draft
	if defs != nil {
		schema["$defs"] = defs
	}
	schema["description"] = "Closed v2 aggregate envelope: every child envelope is required, closed, carries its exact schema header and declares object members. envelopeId is a stable ID and nonClaims is trimmed unique secret-safe text, possibly empty; both are otherwise unused. Native admission owns stable-ID timestamp/secret policy and delegated semantic checks. Bootstrap-derived payload snapshots are secret-checked before decisions."
	return schema
}

func workflow(selected bool) map[string]any {
	schema := member(adoptionworkflow.ContractInputStructure())
	if !selected {
		schema["properties"].(map[string]any)["workflow"] = unselectedObject()
		schema["description"] = "workflow must be an object; it is admitted only in workflow mode."
	}
	return schema
}

func gradualHeader() map[string]any {
	schema := member(gradualadoption.ContractInputStructure())
	schema["properties"].(map[string]any)["input"] = unselectedObject()
	addUnselected(schema, "bootstrap", "guidance")
	schema["description"] = "bootstrap, guidance and input must be objects; this mode does not admit them."
	return schema
}

func pilot() map[string]any {
	schema := pilotadmission.ContractInputStructure("input", "stackDiverseInput")
	delete(schema, "$defs")
	for _, field := range []string{"input", "stackDiverseInput"} {
		schema["properties"].(map[string]any)[field] = unselectedObject()
	}
	schema["description"] = "input and stackDiverseInput must be objects; they are admitted only in pilot mode."
	return member(schema)
}

func addUnselected(schema map[string]any, fields ...string) {
	properties := schema["properties"].(map[string]any)
	for _, field := range fields {
		properties[field] = unselectedObject()
	}
	required := []any{}
	for _, key := range slices.Sorted(maps.Keys(properties)) {
		required = append(required, key)
	}
	schema["required"] = required
}

func unselectedObject() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": true, "description": unselected}
}

func sum(alternatives ...map[string]any) map[string]any {
	items := make([]any, 0, len(alternatives))
	for _, alternative := range alternatives {
		items = append(items, member(alternative))
	}
	return map[string]any{"$schema": draft, "oneOf": items}
}

func closed(fields map[string]any) map[string]any {
	required := []any{}
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		required = append(required, key)
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": fields, "required": required}
}

func leaf(shape jsonshape.Shape) map[string]any { return member(shape.JSONSchema()) }

func member(schema map[string]any) map[string]any {
	delete(schema, "$schema")
	return schema
}
