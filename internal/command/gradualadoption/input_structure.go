package gradualadoption

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

var adoptionInputKeys = []string{"adoptionId", "adoptionMode", "agentReport", "budget", "module", "nativeWitnesses", "nonClaims", "packageVersionRef", "proofBinding", "repository", "rollback", "rolloutClaim", "schemaVersion"}
var guidanceInputKeys = []string{"agentGuidance", "guidanceId", "guidanceMode", "modernization", "nonClaims", "ownerRoute", "schemaVersion", "scopeEvidence", "sourceReport"}
var bootstrapInputKeys = []string{"bootstrapId", "budget", "checkedScope", "commands", "guidanceMode", "module", "nativeWitnesses", "nonClaims", "ownerRoute", "packageVersionRef", "paths", "proofBindingPath", "repository", "rollback", "schemaVersion", "touchedRuleIds"}
var sourceReportKeys = []string{"diagnostics", "nonClaims", "reportId", "reportKind", "ruleResults", "schemaVersion", "state", "summary"}
var sourceRuleKeys = []string{"diagnostics", "message", "ruleId", "status"}

// Input structures describe admitted JSON, including policy-failing inputs.
// Evaluation-only members cannot acquire success-only type requirements here.
func InputStructure() map[string]any {
	fields := map[string]any{
		"adoptionId": ruleIDStructure(), "adoptionMode": textStructure(),
		"agentReport":     evaluatedObject("Agent report fields are evaluated into a failed report, not rejected at input admission."),
		"budget":          evaluatedObject("Budget keys, integer spelling, positivity and comparisons are evaluated into a failed report."),
		"module":          evaluatedObject("Module identity, paths and requirement bounds are evaluated into a failed report."),
		"nativeWitnesses": nativeWitnessStructure(), "nonClaims": textArrayStructure(1),
		"packageVersionRef": textStructure(),
		"proofBinding":      evaluatedObject("Binding format, IDs, paths and set equality are evaluated into a failed report."),
		"repository":        evaluatedObject("Repository fields and no-copied-verifier policy are evaluated into a failed report."),
		"rollback":          evaluatedObject("Command policy is evaluated into a failed report; optional owner/versionPin are redacted strings or empty projections."),
		"rolloutClaim":      jsonshape.Boolean().JSONSchema(), "schemaVersion": jsonshape.IntegerLiteral(1).JSONSchema(),
	}
	return inputDescription(structureObject(adoptionInputKeys, fields), "All root fields are required. Native admission owns canonical version spelling, RuleIDs, nonempty trimmed secret-safe text and sorted unique nonClaims. Child policy failures are report data, except malformed vocabulary/commands and witness-plan identity conflicts, which refuse the input. No witness executes.")
}

func GuidanceInputStructure() map[string]any {
	fields := map[string]any{
		"agentGuidance": evaluatedJSON("Agent guidance is projected with collected failures; every decoded JSON kind is accepted at this phase."),
		"guidanceId":    ruleIDStructure(), "guidanceMode": jsonshape.Enum(adoptionmode.ValuesMap()).JSONSchema(),
		"modernization": evaluatedJSON("Absence/null normalizes to empty candidates and required owner review; malformed values collect failures."),
		"nonClaims":     textArrayStructure(1),
		"ownerRoute":    evaluatedJSON("Owner routes are projected with collected failures, including absent/non-object values."),
		"schemaVersion": jsonshape.IntegerLiteral(1).JSONSchema(),
		"scopeEvidence": evaluatedJSON("Scope evidence is projected with collected failures; mode/scope compatibility remains native evaluation."),
		"sourceReport":  sourceReportStructure(),
	}
	return inputDescription(structureObject(guidanceInputKeys, fields, "agentGuidance", "modernization", "ownerRoute", "scopeEvidence"), "Only identity, mode, nonClaims and sourceReport have hard input constraints. NonClaims are sorted unique secret-safe text; sourceReport rules retain ID/status only, ignoring optional JSON payloads. Mode options are valid only with the contract envelope on the public CLI. Enforcement policy and actionability are native evaluation, not input refusal.")
}

func BootstrapInputStructure() map[string]any {
	fields := map[string]any{
		"bootstrapId":       ruleIDStructure(),
		"budget":            evaluatedObject("Budget is preserved in generated payloads and evaluated by the adoption profile."),
		"checkedScope":      evaluatedJSON("Non-string values project to empty scope and a failed report; observe-mode bootstrap expects none."),
		"commands":          evaluatedJSON("Invalid display-only command lists collect failures and normalize to empty."),
		"guidanceMode":      jsonshape.Enum(adoptionmode.ValuesMap()).JSONSchema(),
		"module":            evaluatedJSON("Missing/non-object or malformed module data produces normalized fields and a failed report."),
		"nativeWitnesses":   nativeWitnessStructure(),
		"nonClaims":         evaluatedJSON("Unsorted unique caller claims are normalized to sorted text. Missing, malformed or duplicate caller claims collect failures. Caller claims are then merged with builtin claims; a duplicate in that merge collects failure and normalizes report nonClaims to an empty array."),
		"ownerRoute":        evaluatedJSON("Owner routes normalize through failure-collecting projections."),
		"packageVersionRef": textStructure(),
		"paths":             evaluatedJSON("Paths normalize through failure-collecting projections; no filesystem access or file write occurs."),
		"proofBindingPath":  evaluatedJSON("Malformed binding paths collect failures and normalize to empty text."),
		"repository":        evaluatedObject("Repository content is preserved and evaluated by the generated adoption profile."),
		"rollback":          evaluatedObject("Rollback content is preserved; optional owner/versionPin text is redacted before egress."),
		"schemaVersion":     jsonshape.IntegerLiteral(1).JSONSchema(),
		"touchedRuleIds":    evaluatedJSON("Invalid ID arrays collect failures; bootstrap expects an empty touched scope."),
	}
	return inputDescription(structureObject(bootstrapInputKeys, fields, "checkedScope", "commands", "module", "nonClaims", "ownerRoute", "paths", "proofBindingPath", "touchedRuleIds"), "The full decoded root is strictly serialized and detached, then secret-shaped keys/values are rejected before decisions or egress. Budget/repository/rollback and packageVersionRef are hard constraints inherited from the generated adoption profile. GuidanceMode must be a supported mode even for failed reports; only observe with scope none can pass initial bootstrap. Native witness policy, input byte limits and privacy are not replaced by this structural description.")
}

func ContractInputStructure() map[string]any {
	return inputDescription(structureObject([]string{"input", "schema"}, map[string]any{
		"input": InputStructure(), "schema": jsonshape.StringLiteral("proofkit.gradual-adoption-profile.v1").JSONSchema(),
	}), "Exactly schema and input are admitted; extra bootstrap/guidance members are rejected for this command.")
}

// Optional override flags replace only their respective guidance operands.
func GuidanceContractInputStructure(modeOverride, scopeOverride, touchedOverride bool) map[string]any {
	scopeFields := map[string]any{"checkedScope": textStructure(), "touchedRuleIds": textArrayStructure(0)}
	optional := []string{}
	if scopeOverride {
		scopeFields["checkedScope"] = evaluatedJSON("Ignored when --checked-scope supplies this operand.")
		optional = append(optional, "checkedScope")
	}
	if touchedOverride {
		scopeFields["touchedRuleIds"] = evaluatedJSON("Ignored when --touched-rule-id supplies this operand.")
		optional = append(optional, "touchedRuleIds")
	}
	guidanceFields := map[string]any{
		"agentGuidance": evaluatedObject("Object-valued guidance fields are failure-collecting projections."),
		"defaultMode":   jsonshape.Enum(adoptionmode.ValuesMap()).JSONSchema(),
		"guidanceId":    ruleIDStructure(), "modernization": evaluatedJSON("Optional failure-collecting modernization input."),
		"nonClaims": textArrayStructure(1), "ownerRoute": evaluatedObject("Owner route policy is evaluated, not a hard object-child shape."),
		"scopeEvidence": structureOpenObject(scopeFields, optional...),
	}
	guidanceOptional := []string{"modernization"}
	if modeOverride {
		guidanceFields["defaultMode"] = evaluatedJSON("Ignored when --guidance-mode supplies the mode.")
		guidanceOptional = append(guidanceOptional, "defaultMode")
	}
	fields := map[string]any{
		"guidance": structureOpenObject(guidanceFields, guidanceOptional...),
		"input":    InputStructure(), "schema": jsonshape.StringLiteral("proofkit.gradual-adoption-profile.v1").JSONSchema(),
	}
	return inputDescription(structureObject([]string{"guidance", "input", "schema"}, fields), "Exactly schema, guidance and input are admitted; bootstrap is rejected. Envelope guidance/scope objects permit extra members. Overrides replace only the selected value, not the object requirement. Native nonempty text, display commands, sorted IDs, mode/scope relations and option values remain authoritative.")
}

func sourceReportStructure() map[string]any {
	rule := structureObject(sourceRuleKeys, map[string]any{
		"diagnostics": evaluatedJSON("Ignored source rule payload."), "message": evaluatedJSON("Ignored source rule payload."),
		"ruleId": ruleIDStructure(), "status": jsonshape.Enum(sourceReportStates).JSONSchema(),
	}, "diagnostics", "message")
	fields := map[string]any{
		"diagnostics": evaluatedJSON("Ignored source report payload."), "nonClaims": evaluatedJSON("Ignored source report payload."),
		"reportId": ruleIDStructure(), "reportKind": textStructure(), "ruleResults": map[string]any{"type": "array", "items": rule},
		"schemaVersion": jsonshape.IntegerLiteral(1).JSONSchema(), "state": jsonshape.Enum(sourceReportStates).JSONSchema(),
		"summary": evaluatedJSON("Ignored source report payload."),
	}
	return structureObject(sourceReportKeys, fields, "diagnostics", "nonClaims", "summary")
}

func nativeWitnessStructure() map[string]any {
	return structureOpenObject(map[string]any{
		"commands":   jsonshape.Array(witnesscommand.CommandStructure(), 0).JSONSchema(),
		"vocabulary": witnesscommand.VocabularyStructure(),
	})
}

func inputDescription(schema map[string]any, description string) map[string]any {
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	schema["description"] = description
	return schema
}

func ruleIDStructure() map[string]any {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
}

func textStructure() map[string]any { return jsonshape.StringGrammar(`[\s\S]+`).JSONSchema() }
func textArrayStructure(minimum int) map[string]any {
	return jsonshape.Array(jsonshape.StringGrammar(`[\s\S]+`), minimum).JSONSchema()
}

func evaluatedJSON(description string) map[string]any {
	return map[string]any{"description": description}
}
func evaluatedObject(description string) map[string]any {
	return map[string]any{"type": "object", "additionalProperties": true, "description": description}
}

// No schema interpretation occurs here. Unrestricted members describe a real
// earlier-phase domain; native evaluation still owns their success conditions.
func structureObject(keys []string, fields map[string]any, optional ...string) map[string]any {
	if len(keys) != len(fields) {
		panic("gradual adoption structure differs from its member inventory")
	}
	required := []any{}
	ordered := slices.Clone(keys)
	slices.Sort(ordered)
	for _, key := range ordered {
		if _, ok := fields[key]; !ok {
			panic("gradual adoption structure omits a member")
		}
		if !slices.Contains(optional, key) {
			required = append(required, key)
		}
	}
	return map[string]any{"type": "object", "properties": fields, "required": required, "additionalProperties": false}
}

func structureOpenObject(fields map[string]any, optional ...string) map[string]any {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	schema := structureObject(keys, fields, optional...)
	schema["additionalProperties"] = true
	return schema
}
