package adoptionworkflow

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

const draft = "https://json-schema.org/draft/2020-12/schema"

// InputStructure describes direct admission, including inputs whose plan is
// blocked. Native admission still owns path syntax, privacy and uniqueness.
func InputStructure() map[string]any {
	ref := jsonshape.ObjectFromKeys(inputRefKeys, map[string]jsonshape.Shape{
		"inputKind": jsonshape.Enum(inputKinds), "path": text(), "refId": ruleID(),
	})
	schema := jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		// Unique input kinds bound the reference count by the kind vocabulary.
		"inputRefs":     jsonshape.BoundedArray(ref, 0, len(inputKinds)),
		"nonClaims":     jsonshape.Array(jsonshape.NonBlankString(), 1),
		"presetId":      jsonshape.Nullable(jsonshape.Enum(set(stackpreset.IDs()...))),
		"scenario":      jsonshape.Enum(scenarios),
		"schemaVersion": jsonshape.IntegerLiteral(1),
		"workflowId":    ruleID(),
	}, "presetId").JSONSchema()
	nonClaims := schema["properties"].(map[string]any)["nonClaims"].(map[string]any)
	nonClaims["uniqueItems"] = true
	nonClaims["items"].(map[string]any)["not"] = map[string]any{"enum": admit.StringSliceToAny(workflowNonClaims)}
	schema["description"] = "Closed direct input; presetId may be absent or null. Native admission owns stable-ID timestamp/secret policy, repository-relative path syntax, unique refId and inputKind values, trimmed nonClaims and refusal of caller claims that equal a builtin claim after trimming. Missing scenario inputs or preset produce a blocked plan, not refusal. The CLI applies framing and optional JSON Pointer selection first. No command executes."
	return schema
}

// ContractInputStructure is the exact two-member contract envelope.
func ContractInputStructure() map[string]any {
	schema := closed(map[string]any{
		"schema": jsonshape.StringLiteral(contractEnvelopeSchema).JSONSchema(), "workflow": member(InputStructure()),
	})
	schema["$schema"] = draft
	schema["description"] = "Exactly schema and workflow are admitted; workflow is the direct input record."
	return schema
}

// OutputStructure describes plans in both states; blockers decide the state.
func OutputStructure() map[string]any {
	schema := planShape().JSONSchema()
	properties := schema["properties"].(map[string]any)
	nonClaims := properties["nonClaims"].(map[string]any)
	nonClaims["uniqueItems"] = true
	contains := make([]any, 0, len(workflowNonClaims))
	for _, claim := range workflowNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	nonClaims["allOf"] = contains
	schema["oneOf"] = []any{
		map[string]any{"properties": map[string]any{"planState": map[string]any{"const": planStateReady}, "blockers": map[string]any{"maxItems": 0}}},
		map[string]any{"properties": map[string]any{"planState": map[string]any{"const": planStateBlocked}, "blockers": map[string]any{"minItems": 1}}},
	}
	schema["description"] = "A plan is ready_for_caller_review (exit 0) exactly when it has no blockers, otherwise blocked (exit 1). Phase positions are fixed; each phase lists only its reachable command IDs. Native ordering, reference joins and argv launcher prefixes remain producer-owned. Commands are not executed and no file is written."
	return schema
}

// EnvelopeOutputStructure is the --agent-envelope carrier: the workflow
// envelope for admitted input, otherwise the shared invalid-input repair packet.
func EnvelopeOutputStructure() map[string]any {
	return map[string]any{"$schema": draft, "oneOf": []any{EnvelopeStructure(), member(agentenvelope.InvalidInputStructure())}}
}

func EnvelopeStructure() map[string]any {
	t := text()
	phases := set()
	for _, phase := range phaseOrder {
		phases[actionPhase(phase)] = struct{}{}
	}
	roles := set()
	for kind := range inputKinds {
		roles[contextRole(kind)] = struct{}{}
	}
	parts := agentenvelope.StructureParts{
		ActionPlan:             jsonshape.BoundedArray(agentenvelope.ActionStructure(jsonshape.Enum(phases)), 0, agentenvelope.MaxActionItems),
		BlockedPreconditions:   jsonshape.BoundedArray(agentenvelope.BlockedStructure(), 0, agentenvelope.MaxBlockedPreconditions),
		Bounds:                 agentenvelope.CompatibilityBoundsStructure(),
		ClarificationQuestions: jsonshape.BoundedArray(agentenvelope.ClarificationStructure(jsonshape.StringLiteral("missing_context_ref")), 0, agentenvelope.MaxClarificationQuestions),
		Commands: jsonshape.BoundedArray(jsonshape.Object(
			jsonshape.Required("argv", jsonshape.Array(t, 1)), jsonshape.Required("command", t), jsonshape.Required("commandId", t),
			jsonshape.Required("nonClaim", jsonshape.StringLiteral(agentCommandNonClaim)),
			jsonshape.Required("owner", jsonshape.StringLiteral(workflowOwner)), jsonshape.Required("purpose", t),
		), 0, agentenvelope.MaxCommandRefs),
		ContextRefs:    jsonshape.BoundedArray(agentenvelope.ContextRefStructure(jsonshape.StringLiteral("path"), jsonshape.Enum(roles)), 0, agentenvelope.MaxContextRefs),
		Omitted:        jsonshape.BoundedArray(agentenvelope.OmissionStructure(), 0, agentenvelope.MaxOmittedItems),
		ReceiptRefs:    jsonshape.Tuple(),
		RouteQuestions: jsonshape.BoundedArray(agentenvelope.RouteQuestionStructure(), 3, 3),
		SourceReport:   agentenvelope.SourceReportStructure(planKind, ruleID(), jsonshape.Null(), jsonshape.Enum(set("passed", "failed"))),
	}
	schema := agentenvelope.Structure(envelopeID, parts).JSONSchema()
	delete(schema, "$schema")
	schema["description"] = "Workflow routing envelope. Source state is passed exactly for a ready plan. Overlong local context IDs degrade into omissions and bounds violations instead of refusal. Envelope builders redact and order records; references, counts and stop reasons remain native semantics."
	return schema
}

func planShape() jsonshape.Shape {
	commands := reachableCommandIDs()
	phases := make([]jsonshape.Shape, 0, len(phaseOrder))
	for _, phase := range phaseOrder {
		ids := commands[phase]
		if len(ids) == 0 {
			phases = append(phases, jsonshape.Object(jsonshape.Required("commands", jsonshape.Tuple()), jsonshape.Required("phase", jsonshape.StringLiteral(phase))))
			continue
		}
		command := jsonshape.Object(
			jsonshape.Required("argv", jsonshape.Array(text(), 1)), jsonshape.Required("commandId", jsonshape.Enum(set(ids...))),
			jsonshape.Required("inputRefIds", jsonshape.BoundedArray(ruleID(), 0, 1)),
			jsonshape.Required("nonClaim", jsonshape.StringLiteral(commandNonClaim)), jsonshape.Required("owner", jsonshape.StringLiteral(workflowOwner)),
		)
		phases = append(phases, jsonshape.Object(
			jsonshape.Required("commands", jsonshape.BoundedArray(command, 0, len(ids))), jsonshape.Required("phase", jsonshape.StringLiteral(phase)),
		))
	}
	ids, reasons := reachableBlockers()
	blocker := jsonshape.Object(
		jsonshape.Required("blockerId", jsonshape.Enum(ids)), jsonshape.Required("nonClaim", jsonshape.StringLiteral(blockerNonClaim)),
		jsonshape.Required("reason", jsonshape.Enum(reasons)), jsonshape.Required("requiredInputKinds", jsonshape.Array(jsonshape.Enum(inputKinds), 0)),
		jsonshape.Required("scenario", jsonshape.Enum(scenarios)),
	)
	ref := jsonshape.ObjectFromKeys(inputRefKeys, map[string]jsonshape.Shape{
		"inputKind": jsonshape.Enum(inputKinds), "path": text(), "refId": ruleID(),
	})
	return jsonshape.Object(
		jsonshape.Required("blockers", jsonshape.Array(blocker, 0)),
		jsonshape.Required("inputRefs", jsonshape.BoundedArray(ref, 0, len(inputKinds))),
		jsonshape.Required("nonClaims", jsonshape.Array(text(), len(workflowNonClaims)+1)),
		jsonshape.Required("phases", jsonshape.Tuple(phases...)),
		jsonshape.Required("planKind", jsonshape.StringLiteral(planKind)),
		jsonshape.Required("planState", jsonshape.Enum(set(planStateReady, planStateBlocked))),
		jsonshape.Required("scenario", jsonshape.Enum(scenarios)),
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("workflowId", ruleID()),
	)
}

// Command routes are monotone in available refs and the preset, so the
// complete reachable vocabulary is the producer's output for every scenario
// with every input kind present. No route table is copied here.
func reachableCommandIDs() map[string][]string {
	refs := map[string]inputRef{}
	for kind := range inputKinds {
		refs[kind] = inputRef{InputKind: kind, Path: "proofkit/" + kind + ".json", RefID: "proofkit." + kind}
	}
	var preset *string
	if presets := stackpreset.IDs(); len(presets) > 0 {
		preset = &presets[0]
	}
	result := map[string][]string{}
	for scenario := range scenarios {
		for _, phase := range phaseOrder {
			for _, raw := range workflowCommandsForPhase(scenario, preset, refs, phase, cliexec.PathRenderer()) {
				id := raw.(map[string]any)["commandId"].(string)
				if !slices.Contains(result[phase], id) {
					result[phase] = append(result[phase], id)
				}
			}
		}
	}
	return result
}

// Blockers only disappear as refs or a preset are supplied, so the empty
// request enumerates every reachable blocker of each scenario.
func reachableBlockers() (map[string]struct{}, map[string]struct{}) {
	ids, reasons := set(), set()
	for scenario := range scenarios {
		for _, item := range workflowBlockers(scenario, nil, nil) {
			ids[item.BlockerID] = struct{}{}
			reasons[item.Reason] = struct{}{}
		}
	}
	return ids, reasons
}

func ruleID() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func text() jsonshape.Shape { return jsonshape.StringGrammar(`[\s\S]+`) }

func set(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func member(schema map[string]any) map[string]any {
	delete(schema, "$schema")
	return schema
}

func closed(fields map[string]any) map[string]any {
	required := make([]any, 0, len(fields))
	for _, key := range sortedKeyList(fields) {
		required = append(required, key)
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": fields, "required": required}
}

func sortedKeyList(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
