package requirementimpactinput

import (
	"slices"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func InputStructure() (map[string]any, error) {
	source, err := requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
	if err != nil {
		return nil, err
	}
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.NonBlankString()
	texts := jsonshape.Array(text, 0)
	schema := jsonshape.Object(
		jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(3)), jsonshape.Required("composerInputId", id),
		jsonshape.Required("baseCommit", text), jsonshape.Required("baseRef", text), jsonshape.Required("headRef", text),
		jsonshape.Optional("headCommit", jsonshape.Nullable(text)),
		jsonshape.Required("changedPathSources", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("sourceId", id), jsonshape.Required("paths", texts)), 1)),
		jsonshape.Required("proofBindingSourcePaths", texts),
		jsonshape.Required("localEnvironmentPolicy", jsonshape.Object(
			jsonshape.Required("localEnvironmentClasses", texts))),
		jsonshape.Required("proofLikePathPolicy", jsonshape.Object(
			jsonshape.Required("ignoredProofLikePaths", texts), jsonshape.Required("proofLikePathPatterns", texts),
			jsonshape.Required("nonClaims", jsonshape.Array(text, 1)))),
		jsonshape.Required("generatedArtifactPolicyState", jsonshape.Object(
			jsonshape.Required("source", id), jsonshape.Required("state", id), jsonshape.Required("uncoveredGeneratedPaths", texts))),
		jsonshape.Required("generatedArtifactRules", jsonshape.Array(jsonshape.Object(
			jsonshape.Required("generatedPath", text), jsonshape.Required("sourcePathPatterns", texts)), 0)),
		jsonshape.Required("preexistingFailures", texts), jsonshape.Required("nonClaims", jsonshape.Array(text, 1)),
		jsonshape.Optional("unboundProofChangeRationale", text),
	).JSONSchema()
	sources := map[string]any{"type": "array", "minItems": 1, "items": source}
	compact := compactproofcontract.InputStructure()
	compactRef := map[string]any{"$ref": "#/$defs/compactProofContract"}
	schema["$id"] = "urn:proofkit:requirement-impact-input-compose:input:schema:3"
	schema["$defs"] = map[string]any{"compactProofContract": compact}
	properties := schema["properties"].(map[string]any)
	properties["currentRequirementSources"], properties["currentCompactProofContract"] = sources, compactRef
	properties["baseRequirementSources"] = map[string]any{"anyOf": []any{map[string]any{"type": "null"}, sources}}
	properties["baseCompactProofContract"] = map[string]any{"anyOf": []any{map[string]any{"type": "null"}, compactRef}}
	required := append(schema["required"].([]any), "currentCompactProofContract", "currentRequirementSources")
	sort.Slice(required, func(i, j int) bool { return required[i].(string) < required[j].(string) })
	schema["required"] = required
	schema["description"] = "Native source admission, source scenario links, unique requirement IDs and compact-proof semantics remain owned by the children. Base sources and compact contract must both be absent/null or both supplied. Native composition owns changed-path admission, normalized uniqueness, preserved sorted arrays, path/pattern/display/privacy rules, binding fingerprints and impact routing. Local environment classes trim before RuleID and length validation; surrounding Unicode whitespace and raw strings longer than the normalized ID bound are admissible. Native admission owns that normalized RuleID grammar, byte bound and sorted uniqueness. Generated policy source/state are arbitrary admitted RuleIDs; non-complete state or uncovered paths add downstream failures rather than rejecting structure. Composer admission can succeed while the emitted impact input evaluates to failed. headCommit admits absence/null; the emitted input always includes it. There is no agent-envelope mode."
	return schema, nil
}

func OutputStructure() map[string]any {
	schema := impact.InputStructure()
	required := schema["required"].([]any)
	if !slices.Contains(required, any("nonClaims")) {
		required = append(required, "nonClaims")
		sort.Slice(required, func(i, j int) bool { return required[i].(string) < required[j].(string) })
		schema["required"] = required
	}
	refinement := map[string]any{"properties": map[string]any{
		"nonClaims": map[string]any{"type": "array", "minItems": 1},
	}}
	if existing, present := schema["allOf"]; present {
		schema["allOf"] = append(existing.([]any), refinement)
	} else {
		schema["allOf"] = []any{refinement}
	}
	schema["description"] = "Producer refinement of the impact input owner: nonClaims is always present, nonnull and nonempty. All inherited input fields and constraints remain; native Build re-admits this exact projection through impact.Build before emission. Composition success does not imply a passing impact report; preexisting, generated-policy and missing-binding failures remain in the downstream input. No witness execution or merge authority is created."
	return schema
}
