package migrationplan

import (
	"regexp"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

// InputShape describes admitted input JSON, including inputs whose
// cross-record facts later produce a blocked plan.
func InputShape() jsonshape.Shape {
	id, text := ruleIDShape(), jsonshape.NonBlankString()
	return jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "migrationId": id,
		"sourceProofOwners":    jsonshape.Array(sourceOwnerShape(), 1),
		"targetProofkitRefs":   jsonshape.Array(targetRefShape(), 1),
		"parityEvidenceRefs":   jsonshape.Array(parityEvidenceShape(), 0),
		"retirementCandidates": jsonshape.Array(retirementCandidateShape(), 0),
		"retainedOwners":       jsonshape.Array(trimmedRuleIDShape(), 0),
		"followUpCommands": jsonshape.Array(jsonshape.RequiredObject(followUpCommandKeys, map[string]jsonshape.Shape{
			"command": text, "commandId": id, "nonClaim": text, "owner": vocabularyShape(commandOwners), "phase": vocabularyShape(phaseOrder),
		}), 0),
		"nonClaims": jsonshape.Array(text, 0),
	})
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	retained := schema["properties"].(map[string]any)["retainedOwners"].(map[string]any)["items"].(map[string]any)
	refineGrammar(retained, TrimmedRuleIDBoundShape())
	schema["description"] = "All nine root fields and every nested record field are required and nonnull. sourceProofOwners and targetProofkitRefs are nonempty; parity evidence, retirement candidates, retained owners, follow-up commands and caller nonClaims may be empty. Record IDs are raw RuleIDs. retainedOwners items trim Unicode whitespace before RuleID admission: padding is admitted and the trimmed identifier keeps the 256-byte bound. Text and paths trim and must be nonblank. Native admission owns secret-like text, timestamp-like identifiers, safe repository-relative paths, display-only follow-up command text, record ordering and unique owner, target, evidence, candidate, command and retained IDs. Unknown references, retain policy, missing parity and missing post-retirement commands are reported as blockers, not refused. No command is executed and no file is edited."
	return schema
}

// TrimmedRuleIDBoundShape bounds the trimmed identifier core. It refines the
// padded RuleID grammar because one regular grammar cannot express both.
func TrimmedRuleIDBoundShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*[^" + space + "]{1," + strconv.Itoa(admit.MaxRuleIDBytes) + "}[" + space + "]*"
	})
}

// OutputShape is the exclusive ready/blocked plan sum emitted by Build.
func OutputShape() jsonshape.Shape {
	return jsonshape.DiscriminatedUnion("planState", planShape(planStateReady), planShape(planStateBlocked))
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	contains := make([]any, 0, len(migrationNonClaims))
	for _, claim := range migrationNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		branch["properties"].(map[string]any)["nonClaims"].(map[string]any)["allOf"] = contains
		branch["description"] = "Ready plans (exit 0) have no blockers and one retire-old-owner action per retirement candidate; blocked plans (exit 1) have sorted blockers and no retire-old-owner action. Each blocker reason fixes its requiredEvidence and blockerId suffix. Phases are the five fixed phases in order. nonClaims are the sorted unique union of the four builtin claims and caller claims. Native Build owns sorted unique records and lists, evidence/command selection, blocker detection, retire-action/candidate correspondence and the plan-state/exit-code relation. A plan routes caller-owned review only; it does not edit files, delete owners, execute commands, authenticate parity evidence or approve merge."
	}
	return schema
}

func planShape(state string) jsonshape.Shape {
	id, text := ruleIDShape(), jsonshape.NonBlankString()
	blockers, retireActions := jsonshape.Tuple(), jsonshape.Array(retireActionShape(), 0)
	if state == planStateBlocked {
		blockers, retireActions = jsonshape.Array(blockerShape(), 1), jsonshape.Tuple()
	}
	// Fixed actions reference owner, target or parity paths; only parity may be empty.
	minimumEvidence := map[string]int{"baseline": 1, "parallel-proof": 1, "parity-check": 0, "post-retirement-validation": 1}
	phases := make([]jsonshape.Shape, 0, len(phaseOrder))
	for _, phase := range phaseOrder {
		actions := retireActions
		if instruction, fixed := phaseInstructions[phase]; fixed {
			actions = jsonshape.Tuple(actionShape(jsonshape.StringLiteral(actionIDPrefix+phase), jsonshape.StringLiteral(instruction), minimumEvidence[phase]))
		}
		phases = append(phases, jsonshape.Object(jsonshape.Required("actions", actions), jsonshape.Required("phase", jsonshape.StringLiteral(phase))))
	}
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)), jsonshape.Required("planKind", jsonshape.StringLiteral(planKind)),
		jsonshape.Required("planState", jsonshape.StringLiteral(state)), jsonshape.Required("migrationId", id),
		jsonshape.Required("blockers", blockers), jsonshape.Required("phases", jsonshape.Tuple(phases...)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(migrationNonClaims))),
		jsonshape.Required("parityEvidenceRefs", jsonshape.Array(parityEvidenceShape(), 0)),
		jsonshape.Required("retainedOwners", jsonshape.Array(id, 0)),
		jsonshape.Required("retirementCandidates", jsonshape.Array(retirementCandidateShape(), 0)),
		jsonshape.Required("sourceProofOwners", jsonshape.Array(sourceOwnerShape(), 1)),
		jsonshape.Required("targetProofkitRefs", jsonshape.Array(targetRefShape(), 1)),
	)
}

func actionShape(actionID, instruction jsonshape.Shape, minimumEvidence int) jsonshape.Shape {
	return jsonshape.Object(
		jsonshape.Required("actionId", actionID), jsonshape.Required("commandIds", jsonshape.Array(ruleIDShape(), 0)),
		jsonshape.Required("evidenceRefs", jsonshape.Array(jsonshape.NonBlankString(), minimumEvidence)),
		jsonshape.Required("instruction", instruction), jsonshape.Required("nonClaim", jsonshape.StringLiteral(actionNonClaim)),
		jsonshape.Required("owner", jsonshape.StringLiteral(consumerRepositoryOwner)),
	)
}

// Retire actions carry the admitted candidate owner ID and trimmed reason.
func retireActionShape() jsonshape.Shape {
	prefix := actionIDPrefix + retireActionSuffixPrefix
	actionID := jsonshape.BoundedStringGrammar(regexp.QuoteMeta(prefix)+"(?:"+admit.RuleIDPatternBody+")", len(prefix)+admit.MaxRuleIDBytes)
	instruction := jsonshape.WhitespaceStringGrammar(func(space string) string {
		return regexp.QuoteMeta(retirementInstructionPrefix) + "(?:" + admit.RuleIDPatternBody + ")" +
			regexp.QuoteMeta(retirementInstructionSeparator) + `[\s\S]*[^` + space + `][\s\S]*`
	})
	return actionShape(actionID, instruction, 1)
}

func blockerShape() jsonshape.Shape {
	alternatives := make([]jsonshape.Shape, 0, len(blockerRules))
	for _, rule := range blockerRules {
		suffix := "." + blockerReasonSlug(rule.reason)
		blockerID := jsonshape.BoundedStringGrammar(regexp.QuoteMeta(blockerIDPrefix)+"(?:"+admit.RuleIDPatternBody+")"+regexp.QuoteMeta(suffix),
			len(blockerIDPrefix)+admit.MaxRuleIDBytes+len(suffix))
		alternatives = append(alternatives, jsonshape.Object(
			jsonshape.Required("blockerId", blockerID), jsonshape.Required("nonClaim", jsonshape.StringLiteral(blockerNonClaim)),
			jsonshape.Required("ownerId", ruleIDShape()), jsonshape.Required("reason", jsonshape.StringLiteral(rule.reason)),
			jsonshape.Required("requiredEvidence", jsonshape.Tuple(jsonshape.StringLiteral(rule.requiredEvidence))),
		))
	}
	return jsonshape.DiscriminatedUnion("reason", alternatives...)
}

func sourceOwnerShape() jsonshape.Shape {
	return jsonshape.RequiredObject(sourceOwnerKeys, map[string]jsonshape.Shape{
		"ownerId": ruleIDShape(), "ownerKind": vocabularyShape(sourceOwnerKinds),
		"path": jsonshape.NonBlankString(), "retirementPolicy": vocabularyShape(retirementPolicies),
	})
}

func targetRefShape() jsonshape.Shape {
	return jsonshape.RequiredObject(targetRefKeys, map[string]jsonshape.Shape{
		"path": jsonshape.NonBlankString(), "targetId": ruleIDShape(), "targetKind": vocabularyShape(targetKinds),
	})
}

func parityEvidenceShape() jsonshape.Shape {
	return jsonshape.RequiredObject(parityEvidenceKeys, map[string]jsonshape.Shape{
		"evidenceId": ruleIDShape(), "evidenceRef": jsonshape.NonBlankString(), "nonClaim": jsonshape.NonBlankString(),
		"sourceOwnerId": ruleIDShape(), "targetId": ruleIDShape(),
	})
}

func retirementCandidateShape() jsonshape.Shape {
	return jsonshape.RequiredObject(retirementCandidateKeys, map[string]jsonshape.Shape{
		"ownerId": ruleIDShape(), "reason": jsonshape.NonBlankString(), "removalRef": jsonshape.NonBlankString(),
	})
}

func ruleIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

func trimmedRuleIDShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*(?:" + admit.RuleIDPatternBody + ")[" + space + "]*"
	})
}

func vocabularyShape(values []string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

// refineGrammar conjoins a second projected grammar with an existing string node.
func refineGrammar(node map[string]any, refinement jsonshape.Shape) {
	node["allOf"] = []any{map[string]any{"pattern": refinement.JSONSchema()["pattern"]}}
}
