package capabilitymapadmission

import (
	"regexp"
	"slices"
	"strconv"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

// Member inventories are shared by native admission and the structural projection.
var (
	inputKeys          = []string{"authority", "capabilities", "mapId", "nonClaims", "proofScope", "repository", "requiredVerification", "scenarioAnchors", "schemaVersion", "trustMode"}
	repositoryKeys     = []string{"nonClaims", "primaryLanguages", "repositoryId"}
	proofScopeKeys     = []string{"baseRef", "dirtyState", "headRef", "nonClaims", "scopeId"}
	capabilityKeys     = []string{"capabilityId", "nonClaims", "ownerId", "riskClasses", "scenarioShapes", "sourcePaths", "summary"}
	scenarioShapeKeys  = []string{"candidateRequirementId", "nonClaims", "ownerQuestions", "requiredEvidence", "scenarioId", "summary"}
	scenarioAnchorKeys = []string{"commandRefs", "falsificationWitness", "nonClaims", "positiveWitness", "scenarioId", "selector", "sourcePath", "status"}
	verificationKeys   = []string{"command", "commandId", "environmentClass", "nonClaims", "reason"}
)

// Sorted unique scalar lists; keyed object uniqueness remains native.
var uniqueInputLists = [][]string{
	{"nonClaims"}, {"repository", "nonClaims"}, {"repository", "primaryLanguages"}, {"proofScope", "nonClaims"},
	{"capabilities", "*", "nonClaims"}, {"capabilities", "*", "riskClasses"}, {"capabilities", "*", "sourcePaths"},
	{"capabilities", "*", "scenarioShapes", "*", "nonClaims"}, {"capabilities", "*", "scenarioShapes", "*", "ownerQuestions"},
	{"capabilities", "*", "scenarioShapes", "*", "requiredEvidence"},
	{"scenarioAnchors", "*", "commandRefs"}, {"scenarioAnchors", "*", "nonClaims"}, {"requiredVerification", "*", "nonClaims"},
}

// InputShape declares every admitted member with one grammar per leaf. The
// selector anchor byte bound and list uniqueness are added by InputStructure.
func InputShape() jsonshape.Shape {
	id := ruleIDShape()
	ids := jsonshape.Nullable(jsonshape.BoundedArray(id, 0, maxTextItems))
	claims := nonClaimsInputShape()
	repository := jsonshape.ObjectFromKeys(repositoryKeys, map[string]jsonshape.Shape{
		"nonClaims": claims, "primaryLanguages": ids, "repositoryId": id,
	}, "nonClaims", "primaryLanguages")
	scope := jsonshape.ObjectFromKeys(proofScopeKeys, map[string]jsonshape.Shape{
		"baseRef": jsonshape.Nullable(jsonshape.NonBlankString()), "dirtyState": jsonshape.Enum(dirtyStateValues),
		"headRef": jsonshape.Nullable(jsonshape.NonBlankString()), "nonClaims": claims, "scopeId": id,
	}, "baseRef", "headRef", "nonClaims")
	scenario := jsonshape.ObjectFromKeys(scenarioShapeKeys, map[string]jsonshape.Shape{
		"candidateRequirementId": jsonshape.Nullable(id), "nonClaims": claims,
		"ownerQuestions":   jsonshape.Nullable(jsonshape.BoundedArray(canonicalTextShape(maxQuestionRunes), 0, maxQuestionsPerScenario)),
		"requiredEvidence": jsonshape.Nullable(jsonshape.BoundedArray(requiredEvidenceShape(), 0, maxTextItems)),
		"scenarioId":       id, "summary": trimmedTextShape(maxSummaryRunes),
	}, "candidateRequirementId", "nonClaims", "ownerQuestions", "requiredEvidence")
	capability := jsonshape.ObjectFromKeys(capabilityKeys, map[string]jsonshape.Shape{
		"capabilityId": id, "nonClaims": claims, "ownerId": id, "riskClasses": ids,
		"scenarioShapes": jsonshape.BoundedArray(scenario, 1, maxScenarioShapesPerCapability),
		"sourcePaths":    jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), 1), "summary": trimmedTextShape(maxSummaryRunes),
	}, "nonClaims", "riskClasses")
	anchor := jsonshape.ObjectFromKeys(scenarioAnchorKeys, map[string]jsonshape.Shape{
		"commandRefs": ids, "falsificationWitness": jsonshape.Nullable(jsonshape.Boolean()), "nonClaims": claims,
		"positiveWitness": jsonshape.Nullable(jsonshape.Boolean()), "scenarioId": id, "selector": selectorInputShape(),
		"sourcePath": jsonshape.NonBlankString(), "status": jsonshape.Enum(anchorStatusValues),
	}, "commandRefs", "falsificationWitness", "nonClaims", "positiveWitness")
	verification := jsonshape.ObjectFromKeys(verificationKeys, map[string]jsonshape.Shape{
		"command": trimmedTextShape(maxCommandRunes), "commandId": id, "environmentClass": id,
		"nonClaims": claims, "reason": trimmedTextShape(maxSummaryRunes),
	}, "nonClaims")
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"authority": jsonshape.Enum(authorityValues), "capabilities": jsonshape.BoundedArray(capability, 1, maxCapabilities),
		"mapId": id, "nonClaims": claims, "proofScope": scope, "repository": repository,
		"requiredVerification": jsonshape.Nullable(jsonshape.BoundedArray(verification, 0, maxRequiredVerificationCommands)),
		"scenarioAnchors":      jsonshape.Nullable(jsonshape.BoundedArray(anchor, 0, maxScenarioAnchors)),
		"schemaVersion":        jsonshape.IntegerLiteral(1), "trustMode": jsonshape.Enum(modeValues),
	}, "nonClaims", "requiredVerification", "scenarioAnchors")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	for _, path := range uniqueInputLists {
		structureNode(schema, path...)["uniqueItems"] = true
	}
	selector := structureNode(schema, "scenarioAnchors", "*", "selector")
	selector["allOf"] = []any{map[string]any{"pattern": selectorAnchorBoundShape().JSONSchema()["pattern"]}}
	schema["description"] = "Seven root members are required. Root nonClaims, requiredVerification and scenarioAnchors and every other optional list, ref, candidate ID or witness flag admit absence or explicit null, both meaning undeclared: an empty list, no ref or ID, or a false flag. IDs and enums are exact and untrimmed. Summary, reason and command trim by native Unicode whitespace to at most 280, 280 and 240 code points; nonClaims and ownerQuestions are already-trimmed text of at most 240 code points. Text and ID lists are sorted unique; sourcePaths are raw canonical paths, anchor sourcePath trims first. A selector trims to exactly one path::anchor split whose anchor is a RuleID of at most 256 bytes. Native admission still owns RuleID secret/timestamp exclusions, text privacy, sorted order, repository-relative POSIX path safety, display-only command tokens, selector path equality with sourcePath, and unique capability, scenario, anchor and command keys. Declared-scenario and commandRef closure, code_baseline candidate/anchor/witness obligations and requiredEvidence satisfaction produce admitted failed reports, not input refusal."
	return schema
}

// OutputShape is the exclusive trust-mode by state sum emitted by Build.
func OutputShape() jsonshape.Shape {
	modes := make([]string, 0, len(modeValues))
	for mode := range modeValues {
		modes = append(modes, mode)
	}
	slices.Sort(modes)
	branches := make([]jsonshape.Shape, 0, 2*len(modes))
	for _, mode := range modes {
		branches = append(branches, reportShape(mode, true), reportShape(mode, false))
	}
	return jsonshape.OneOf(branches...)
}

func OutputStructure() map[string]any {
	schema := OutputShape().JSONSchema()
	for _, raw := range schema["oneOf"].([]any) {
		branch := raw.(map[string]any)
		properties := branch["properties"].(map[string]any)
		properties["reportId"] = nestedSchema(ruleIDShape())
		properties["nonClaims"] = reportNonClaimsStructure()
		branch["description"] = "One branch per trust mode and state. reportId and summary.mapId preserve mapId. Passed reports have no failures and exit 0; failed reports carry sorted unique failure text, the shape rule joins those failures, and exit 1 with JSON. Admission errors exit 1 on stderr without a report. Trust mode fixes instructions, seed promotion/authority literals, missing-anchor severity and the mode rule. Seed and action lists follow native capability/scenario/anchor order; witnessKinds keep positive before falsification. nonClaims merge builtin and caller claims, sorted and deduplicated. Native evaluation owns counts, reference closure and seed eligibility. Seeds are candidate-only; structural validity does not execute witnesses or promote requirements."
	}
	return schema
}

func reportShape(mode string, passed bool) jsonshape.Shape {
	id, text, count := ruleIDShape(), jsonshape.StringGrammar(`[\s\S]+`), jsonshape.IntegerMinimum(0)
	state, failureCount, failures, shapeMessage := "failed", jsonshape.IntegerMinimum(1), jsonshape.Array(text, 1), text
	modeMessage := modeRuleMessage(mode, []string{"failure"})
	if passed {
		state, failureCount, failures = "passed", jsonshape.IntegerLiteral(0), jsonshape.Tuple()
		shapeMessage, modeMessage = jsonshape.StringLiteral(shapeRuleMessage(nil)), modeRuleMessage(mode, nil)
	}
	summary := jsonshape.Object(
		jsonshape.Required("agentActionCount", count), jsonshape.Required("candidateProofBindingSeedCount", count),
		jsonshape.Required("candidateRequirementSeedCount", count), jsonshape.Required("capabilityCount", jsonshape.IntegerRange(1, maxCapabilities)),
		jsonshape.Required("failureCount", failureCount), jsonshape.Required("mapId", id), jsonshape.Required("repositoryId", id),
		jsonshape.Required("scenarioAnchorCount", jsonshape.IntegerRange(0, maxScenarioAnchors)),
		jsonshape.Required("scenarioShapeCount", jsonshape.IntegerRange(1, maxCapabilities*maxScenarioShapesPerCapability)),
		jsonshape.Required("scopeId", id), jsonshape.Required("trustMode", jsonshape.StringLiteral(mode)),
		jsonshape.Required("verificationCommandCount", jsonshape.IntegerRange(0, maxRequiredVerificationCommands)),
	)
	lines := instructions(mode)
	instructionShapes := make([]jsonshape.Shape, len(lines))
	for index, line := range lines {
		instructionShapes[index] = jsonshape.StringLiteral(line.(string))
	}
	diagnostics := jsonshape.Tuple(
		report.DiagnosticStructure("trustMode", jsonshape.StringLiteral(mode)),
		report.DiagnosticStructure("failures", failures),
		report.DiagnosticStructure("instructions", jsonshape.Tuple(instructionShapes...)),
		report.DiagnosticStructure("candidateRequirementSeeds", jsonshape.Array(requirementSeedShape(mode), 0)),
		report.DiagnosticStructure("candidateProofBindingSeeds", jsonshape.Array(bindingSeedShape(mode), 0)),
		report.DiagnosticStructure("agentActionPlan", jsonshape.Array(jsonshape.DiscriminatedUnion("type", addAnchorActionShape(mode), resolveQuestionsActionShape()), 0)),
	)
	status := jsonshape.StringLiteral(state)
	rules := jsonshape.Tuple(
		report.RuleStructure(jsonshape.StringLiteral(shapeRuleID), status, shapeMessage, jsonshape.Tuple()),
		report.RuleStructure(jsonshape.StringLiteral(trustModeRuleID(mode)), status, jsonshape.StringLiteral(modeMessage), jsonshape.Tuple()),
	)
	return report.Structure(1, reportKind, status, summary, diagnostics, rules)
}

func requirementSeedShape(mode string) jsonshape.Shape {
	id := ruleIDShape()
	return jsonshape.Object(
		jsonshape.Required("claimLevel", jsonshape.StringLiteral(candidateSeedState)),
		jsonshape.Required("nonClaims", jsonshape.BoundedArray(canonicalTextShape(maxNonClaimRunes), 0, 2*maxNonClaims)),
		jsonshape.Required("ownerId", id), jsonshape.Required("promotionState", jsonshape.StringLiteral(promotionState(mode))),
		jsonshape.Required("requiredEvidence", jsonshape.BoundedArray(requiredEvidenceShape(), 0, len(requiredEvidenceWitnessKind))),
		jsonshape.Required("requirementId", id), jsonshape.Required("sourceCapabilityId", id), jsonshape.Required("sourceScenarioId", id),
		jsonshape.Required("sourceTrustMode", jsonshape.StringLiteral(mode)),
		jsonshape.Required("statementSeed", canonicalTextShape(maxSummaryRunes)),
	)
}

func bindingSeedShape(mode string) jsonshape.Shape {
	id := ruleIDShape()
	positive, falsification := jsonshape.StringLiteral(positiveWitnessKind), jsonshape.StringLiteral(falsificationWitnessKind)
	return jsonshape.Object(
		jsonshape.Required("commandRefs", jsonshape.BoundedArray(id, 1, maxTextItems)),
		jsonshape.Required("evidenceAuthority", jsonshape.StringLiteral(evidenceAuthority(mode))),
		jsonshape.Required("executableEvidenceState", jsonshape.StringLiteral(executableEvidenceState(mode))),
		jsonshape.Required("nonClaims", jsonshape.BoundedArray(canonicalTextShape(maxNonClaimRunes), 0, maxNonClaims)),
		jsonshape.Required("promotionState", jsonshape.StringLiteral(promotionState(mode))),
		jsonshape.Required("requiredEvidence", jsonshape.BoundedArray(requiredEvidenceShape(), 0, len(requiredEvidenceWitnessKind))),
		jsonshape.Required("requirementId", id), jsonshape.Required("scenarioId", id),
		jsonshape.Required("selector", jsonshape.WhitespaceStringGrammar(selectorCore)),
		jsonshape.Required("sourcePath", canonicalTextShape(0)),
		jsonshape.Required("state", jsonshape.StringLiteral(candidateSeedState)),
		jsonshape.Required("witnessKinds", jsonshape.OneOf(jsonshape.Tuple(positive), jsonshape.Tuple(falsification), jsonshape.Tuple(positive, falsification))),
	)
}

func addAnchorActionShape(mode string) jsonshape.Shape {
	id := ruleIDShape()
	return jsonshape.Object(
		jsonshape.Required("actionId", actionIDShape(addAnchorActionSuffix)), jsonshape.Required("capabilityId", id),
		jsonshape.Required("commandRefs", jsonshape.Tuple()), jsonshape.Required("message", jsonshape.StringLiteral(addAnchorActionMessage)),
		jsonshape.Required("ownerId", id), jsonshape.Required("scenarioId", id),
		jsonshape.Required("severity", jsonshape.StringLiteral(severityForMode(mode, missingAnchorCondition))),
		jsonshape.Required("type", jsonshape.StringLiteral(addAnchorActionType)),
	)
}

func resolveQuestionsActionShape() jsonshape.Shape {
	id := ruleIDShape()
	return jsonshape.Object(
		jsonshape.Required("actionId", actionIDShape(resolveQuestionsActionSuffix)), jsonshape.Required("capabilityId", id),
		jsonshape.Required("commandRefs", jsonshape.Array(id, 0)), jsonshape.Required("message", jsonshape.StringLiteral(resolveQuestionsActionMessage)),
		jsonshape.Required("ownerId", id), jsonshape.Required("scenarioId", id),
		jsonshape.Required("severity", jsonshape.StringLiteral(reviewSeverity)), jsonshape.Required("type", jsonshape.StringLiteral(resolveQuestionsActionType)),
	)
}

func actionIDShape(suffix string) jsonshape.Shape {
	body := regexp.QuoteMeta(actionIDPrefix) + "(?:" + admit.RuleIDPatternBody + ")" + regexp.QuoteMeta(suffix)
	return jsonshape.BoundedStringGrammar(body, len(actionIDPrefix)+admit.MaxRuleIDBytes+len(suffix))
}

func reportNonClaimsStructure() map[string]any {
	claims := nestedSchema(jsonshape.Array(canonicalTextShape(0), len(commandNonClaims)))
	contains := make([]any, 0, len(commandNonClaims))
	for _, claim := range commandNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], claims["uniqueItems"] = contains, true
	return claims
}

func nonClaimsInputShape() jsonshape.Shape {
	return jsonshape.Nullable(jsonshape.BoundedArray(canonicalTextShape(maxNonClaimRunes), 0, maxNonClaims))
}

func requiredEvidenceShape() jsonshape.Shape {
	values := make(map[string]struct{}, len(requiredEvidenceWitnessKind))
	for value := range requiredEvidenceWitnessKind {
		values[value] = struct{}{}
	}
	return jsonshape.Enum(values)
}

func ruleIDShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

// selectorInputShape trims to one path::anchor split: the path part is nonempty,
// has no "::" and no trailing colon, so strings.Split yields exactly two parts.
func selectorInputShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*" + selectorCore(space) + "[" + space + "]*"
	})
}

func selectorCore(space string) string {
	return "(?:[^" + space + ":]|:[^:])(?:[^:]|:[^:])*::(?:" + admit.RuleIDPatternBody + ")"
}

// The single separator makes the trailing non-space run the anchor RuleID.
func selectorAnchorBoundShape() jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return `[\s\S]*::[^` + space + `]{1,` + strconv.Itoa(admit.MaxRuleIDBytes) + `}[` + space + `]*`
	})
}

// trimmedTextShape admits NonEmptyText whose trimmed value has at most maximum runes.
func trimmedTextShape(maximum int) jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string {
		return "[" + space + "]*" + canonicalTextBody(space, maximum) + "[" + space + "]*"
	})
}

// canonicalTextShape admits already-trimmed nonempty text; zero means unbounded.
func canonicalTextShape(maximum int) jsonshape.Shape {
	return jsonshape.WhitespaceStringGrammar(func(space string) string { return canonicalTextBody(space, maximum) })
}

func canonicalTextBody(space string, maximum int) string {
	inner := `[\s\S]*`
	if maximum > 0 {
		inner = `[\s\S]{0,` + strconv.Itoa(maximum-2) + `}`
	}
	return "[^" + space + "](?:" + inner + "[^" + space + "])?"
}

func nestedSchema(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

// structureNode follows properties, array items and nullable wrappers only.
func structureNode(schema map[string]any, path ...string) map[string]any {
	node := nonNullStructure(schema)
	for _, segment := range path {
		if segment == "*" {
			node = node["items"].(map[string]any)
		} else {
			node = node["properties"].(map[string]any)[segment].(map[string]any)
		}
		node = nonNullStructure(node)
	}
	return node
}

func nonNullStructure(node map[string]any) map[string]any {
	alternatives, nullable := node["anyOf"].([]any)
	if !nullable {
		return node
	}
	for _, raw := range alternatives {
		if branch := raw.(map[string]any); branch["type"] != "null" {
			return branch
		}
	}
	panic("nullable structure has no value branch")
}
