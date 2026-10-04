package selectivegateplan

import (
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

func InputStructure() map[string]any {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	command := commandStructure(false)
	touched := jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("touched", jsonshape.Boolean()))
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("archiveOrBinaryPathPatterns", texts),
		jsonshape.Required("artifactIntegrityPolicies", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("command", text), jsonshape.Required("pathPattern", text), jsonshape.Required("policy", id)), 0)),
		jsonshape.Required("baseCommands", jsonshape.Array(command, 0)),
		jsonshape.Required("changedPaths", texts),
		jsonshape.Required("dependencyFreshness", jsonshape.Object(jsonshape.Required("command", text), jsonshape.Required("paths", texts))),
		jsonshape.Optional("fallbackCoverage", jsonshape.Nullable(jsonshape.Array(fallbackStructure(command), 0))),
		jsonshape.Optional("fullWorkspaceCommand", command),
		jsonshape.Required("generatedArtifactRules", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("command", text), jsonshape.Required("generator", text),
			jsonshape.Required("path", text), jsonshape.Required("sourceOfTruthPatterns", texts)), 0)),
		jsonshape.Required("ignoredProofLikePaths", texts),
		jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Required("packageCommands", jsonshape.Array(command, 0)),
		jsonshape.Optional("pathTriggeredCommands", jsonshape.Nullable(jsonshape.Array(jsonshape.Object(
			jsonshape.Required("command", command), jsonshape.Required("pathPatterns", jsonshape.Array(text, 1))), 0))),
		jsonshape.Required("preexistingFailures", texts),
		jsonshape.Required("privatePathPrefixes", texts),
		jsonshape.Required("proofLikePathPatterns", texts),
		jsonshape.Required("publicApi", touched), jsonshape.Required("requirementImpact", touched),
		jsonshape.Required("scanObligation", scanStructure()),
		jsonshape.Required("touchedRequirementWitnesses", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("commands", jsonshape.Array(text, 1)), jsonshape.Required("path", text),
			jsonshape.Required("requirementIds", jsonshape.Array(id, 1))), 0)),
		jsonshape.Optional("unknownEdges", jsonshape.Nullable(jsonshape.Array(unknownEdgeStructure(false), 0))),
	).JSONSchema()
	schema["description"] = "Missing or null pathTriggeredCommands, fallbackCoverage and unknownEdges become empty arrays; fullWorkspaceCommand is optional but nonnull. Native admission owns trimming, privacy, safe paths and display-only command text, prefix and path-pattern grammar, sorted uniqueness and identity collisions. Scan ownership fixes its reason and the two Proofkit-owned command IDs; external ownership must not reuse either ID. Evaluation may fail closed while still emitting a plan. No witness is executed."
	return schema
}

// EvidencePlanStructure belongs to the plan's re-admission boundary, also used
// by selective-gate-evidence. Its domain includes caller-authored valid plans.
func EvidencePlanStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	texts := jsonshape.Array(text, 0)
	return jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("artifactIntegrity", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("command", text), jsonshape.Required("path", text), jsonshape.Required("policy", text)), 0)),
		jsonshape.Required("changedPaths", texts), jsonshape.Required("failures", texts),
		jsonshape.Required("fallbackCoverage", jsonshape.Array(fallbackStructure(commandStructure(true)), 0)),
		jsonshape.Required("generatedArtifacts", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("generator", text), jsonshape.Required("path", text),
			jsonshape.Required("reason", jsonshape.Enum(map[string]struct{}{"generated_artifact_changed": {}, "source_changed": {}})),
			jsonshape.Required("sourceOfTruth", texts)), 0)),
		jsonshape.Required("nonClaims", texts),
		jsonshape.Required("planState", jsonshape.Enum(map[string]struct{}{"ok": {}, "fail_closed": {}})),
		jsonshape.Required("privatePathExclusions", jsonshape.Object(jsonshape.Required("appliesTo", texts), jsonshape.Required("pathPrefixes", texts))),
		jsonshape.Required("proofLikePaths", texts), jsonshape.Required("publicApiContractTouched", jsonshape.Boolean()),
		jsonshape.Required("requiredCommands", jsonshape.Array(commandStructure(true), 0)),
		jsonshape.Required("scanObligation", scanStructure()),
		jsonshape.Required("skippedGates", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("id", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)), jsonshape.Required("reason", text)), 0)),
		jsonshape.Required("touchedRequirementWitnesses", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("commands", texts), jsonshape.Required("path", text), jsonshape.Required("requirementIds", texts)), 0)),
		jsonshape.Required("unknownEdges", jsonshape.Array(unknownEdgeStructure(true), 0)),
	)
}

func OutputStructure() map[string]any {
	schema := EvidencePlanStructure().JSONSchema()
	schema["description"] = "Both ok and fail_closed plans use the plan owner's evidence-admission structure. Native relations require ok exactly when failures is empty, unique command keys and edge IDs, truthful fallback coverage, and retained scan/fallback commands for successful plans. Native checks own privacy, safe paths, scan ownership and canonical ordering. The producer additionally emits appliesTo=[artifact-integrity] and nonempty witness command/requirement lists; re-admission permits broader caller-authored lists. Planning is advisory, not execution or merge approval."
	return schema
}

func commandStructure(output bool) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	reason := id
	if output {
		reason = text
	}
	fields := []jsonshape.Property{jsonshape.Required("command", text), jsonshape.Required("id", id), jsonshape.Required("reason", reason), jsonshape.Optional("sourcePath", text)}
	if output {
		fields = append(fields, jsonshape.Optional("commandOwnership", jsonshape.Enum(scanOwnershipSet)))
	}
	return jsonshape.Object(fields...)
}

func scanStructure() jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	return jsonshape.Object(
		jsonshape.Required("command", text),
		jsonshape.Required("commandId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("commandOwnership", jsonshape.Enum(scanOwnershipSet)),
		jsonshape.Required("mode", jsonshape.StringLiteral("diff-scoped")),
		jsonshape.Required("reason", jsonshape.Enum(scanReasonSet)),
		jsonshape.Required("required", jsonshape.BooleanLiteral(true)),
	)
}

func fallbackStructure(command jsonshape.Shape) jsonshape.Shape {
	return jsonshape.Object(jsonshape.Required("command", command), jsonshape.Required("edgeClasses", jsonshape.Array(jsonshape.Enum(edgeClassSet), 1)), jsonshape.Required("reason", jsonshape.StringGrammar(`[\s\S]+`)))
}

func unknownEdgeStructure(output bool) jsonshape.Shape {
	text := jsonshape.StringGrammar(`[\s\S]+`)
	fields := []jsonshape.Property{
		jsonshape.Required("edgeClass", jsonshape.Enum(edgeClassSet)),
		jsonshape.Required("edgeId", jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)),
		jsonshape.Required("path", text), jsonshape.Required("reason", text),
	}
	if output {
		fields = append(fields, jsonshape.Required("coverageState", jsonshape.Enum(outputEdgeCoverageStateSet)), jsonshape.Required("fallbackCommandIds", jsonshape.Array(text, 0)))
	}
	return jsonshape.Object(fields...)
}
