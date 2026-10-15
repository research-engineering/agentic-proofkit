package adoptiondoctor

import (
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
)

var inputKeys = []string{"blockedPreconditions", "checkedScope", "childReports", "doctorId", "mode", "modernization", "nonClaims", "ownerRoutes", "schemaVersion", "staleAuthority", "touchedRuleIds"}
var ownerRouteKeys = []string{"commands", "nativeWitnessRefs", "nonClaims", "owner", "proofBindingPaths", "routeId", "specPaths", "touchedRuleIds"}
var modernizationKeys = []string{"candidateBoundaries"}
var candidateKeys = []string{"admissionState", "affectedPaths", "blockedPreconditions", "boundaryId", "candidateOwner", "contractWitnessRefs", "nativeWitnessRefs", "nonClaims", "observedFacts", "ownerQuestions", "proofBindingRefs", "requirementRefs", "uncertainties"}
var childReportKeys = []string{"evidenceRefs", "nonClaim", "reportId", "reportKind", "state", "summary", "touchedRuleIds"}
var preconditionKeys = []string{"evidenceRefs", "nonClaim", "owner", "preconditionId", "reason", "touchedRuleIds"}
var staleAuthorityKeys = []string{"authoritySurfaces", "currentPackage", "forbiddenVocabulary", "retiredScopes"}
var packageKeys = []string{"name", "version"}
var vocabularyKeys = []string{"replacementText", "text", "vocabularyId"}
var surfaceKeys = []string{"authorityState", "evidenceRefs", "matchedVocabularyIds", "nonClaims", "owner", "path", "retiredScopeId", "surfaceId", "touchedRuleIds"}
var retiredScopeKeys = []string{"allowedVocabularyIds", "nonClaim", "pathPrefixes", "scopeId"}

// InputShape describes accepted decoded JSON. The mode/scope relation is a
// root constraint projected separately by InputStructure.
func InputShape() jsonshape.Shape {
	id, text, path := identifierShape(), jsonshape.NonBlankString(), pathShape()
	// Native `optional` treats absence and null as the empty default.
	ids, texts, paths := jsonshape.Nullable(jsonshape.Array(id, 0)), jsonshape.Nullable(jsonshape.Array(text, 0)), jsonshape.Nullable(jsonshape.Array(path, 0))
	route := jsonshape.ObjectFromKeys(ownerRouteKeys, map[string]jsonshape.Shape{
		"commands": texts, "nativeWitnessRefs": paths, "nonClaims": texts, "owner": text,
		"proofBindingPaths": paths, "routeId": id, "specPaths": paths, "touchedRuleIds": ids,
	}, "commands", "nativeWitnessRefs", "nonClaims", "proofBindingPaths", "specPaths", "touchedRuleIds")
	candidate := jsonshape.ObjectFromKeys(candidateKeys, map[string]jsonshape.Shape{
		"admissionState": jsonshape.Enum(admissionStates), "affectedPaths": paths, "blockedPreconditions": texts,
		"boundaryId": id, "candidateOwner": text, "contractWitnessRefs": paths, "nativeWitnessRefs": paths,
		"nonClaims": texts, "observedFacts": texts, "ownerQuestions": texts, "proofBindingRefs": paths,
		"requirementRefs": ids, "uncertainties": texts,
	}, "affectedPaths", "blockedPreconditions", "contractWitnessRefs", "nativeWitnessRefs", "nonClaims", "observedFacts",
		"ownerQuestions", "proofBindingRefs", "requirementRefs", "uncertainties")
	child := jsonshape.ObjectFromKeys(childReportKeys, map[string]jsonshape.Shape{
		"evidenceRefs": paths, "nonClaim": text, "reportId": id, "reportKind": id,
		"state": jsonshape.Enum(childReportStates), "summary": text, "touchedRuleIds": ids,
	}, "evidenceRefs", "touchedRuleIds")
	precondition := jsonshape.ObjectFromKeys(preconditionKeys, map[string]jsonshape.Shape{
		"evidenceRefs": paths, "nonClaim": text, "owner": text, "preconditionId": id, "reason": text, "touchedRuleIds": ids,
	}, "evidenceRefs", "touchedRuleIds")
	vocabulary := jsonshape.ObjectFromKeys(vocabularyKeys, map[string]jsonshape.Shape{
		"replacementText": jsonshape.Nullable(text), "text": text, "vocabularyId": id,
	}, "replacementText")
	surface := jsonshape.ObjectFromKeys(surfaceKeys, map[string]jsonshape.Shape{
		"authorityState": jsonshape.Enum(authorityStates), "evidenceRefs": paths, "matchedVocabularyIds": ids,
		"nonClaims": texts, "owner": text, "path": path, "retiredScopeId": jsonshape.Nullable(id), "surfaceId": id, "touchedRuleIds": ids,
	}, "evidenceRefs", "matchedVocabularyIds", "nonClaims", "retiredScopeId", "touchedRuleIds")
	scope := jsonshape.ObjectFromKeys(retiredScopeKeys, map[string]jsonshape.Shape{
		"allowedVocabularyIds": jsonshape.Array(id, 0), "nonClaim": text, "pathPrefixes": jsonshape.Array(path, 1), "scopeId": id,
	})
	stale := jsonshape.ObjectFromKeys(staleAuthorityKeys, map[string]jsonshape.Shape{
		"authoritySurfaces":   jsonshape.Nullable(jsonshape.Array(surface, 0)),
		"currentPackage":      jsonshape.Nullable(jsonshape.ObjectFromKeys(packageKeys, map[string]jsonshape.Shape{"name": text, "version": text})),
		"forbiddenVocabulary": jsonshape.Nullable(jsonshape.Array(vocabulary, 0)),
		"retiredScopes":       jsonshape.Nullable(jsonshape.Array(scope, 0)),
	}, staleAuthorityKeys...)
	return jsonshape.ObjectFromKeys(inputKeys, map[string]jsonshape.Shape{
		"blockedPreconditions": jsonshape.Array(precondition, 0), "checkedScope": jsonshape.Enum(scopeValues()),
		"childReports": jsonshape.Array(child, 0), "doctorId": id, "mode": jsonshape.Enum(adoptionmode.ValuesMap()),
		"modernization": jsonshape.Nullable(jsonshape.ObjectFromKeys(modernizationKeys, map[string]jsonshape.Shape{
			"candidateBoundaries": jsonshape.Array(candidate, 0),
		})),
		"nonClaims": jsonshape.Array(text, 1), "ownerRoutes": jsonshape.Array(route, 0),
		"schemaVersion": jsonshape.IntegerLiteral(1), "staleAuthority": jsonshape.Nullable(stale), "touchedRuleIds": ids,
	}, "modernization", "staleAuthority", "touchedRuleIds")
}

func InputStructure() map[string]any {
	schema := InputShape().JSONSchema()
	schema["oneOf"] = modeScopeAlternatives()
	schema["description"] = "Required members are schemaVersion, doctorId, mode, checkedScope, ownerRoutes, childReports, blockedPreconditions and nonClaims. Optional members and optional record lists admit absence or null as an empty default; retiredScopes require allowedVocabularyIds and nonempty pathPrefixes. The root oneOf projects the native mode/checkedScope admission relation. Text trims to nonempty secret-safe text; paths are untrimmed nonempty strings whose safe repository-relative POSIX grammar and privacy remain native. Native admission also owns IDs without secret/timestamp components, display-only commands without shell control tokens, already sorted unique ID/path/command lists and record IDs, normalized unique nonClaims and blocked preconditions, and stale-authority references to declared vocabulary and retired scope IDs. schemaVersion requires the literal integer token 1. Admitted adoption gaps produce passed, failed or blocked reports rather than input refusal."
	return schema
}

// The relation is evaluated by the native owner for every mode and scope, so
// this projection cannot drift into an independently authored policy table.
func modeScopeAlternatives() []any {
	modes := sortedValues(adoptionmode.ValuesMap())
	scopes := sortedValues(scopeValues())
	alternatives := make([]any, 0, len(modes))
	for _, mode := range modes {
		admitted := map[string]struct{}{}
		for _, scope := range scopes {
			if adoptionmode.ValidateScope(mode, scope, "") == nil {
				admitted[scope] = struct{}{}
			}
		}
		alternatives = append(alternatives, map[string]any{"properties": map[string]any{
			"checkedScope": fragment(jsonshape.Enum(admitted)), "mode": fragment(jsonshape.StringLiteral(mode)),
		}})
	}
	return alternatives
}

func scopeValues() map[string]struct{} {
	return map[string]struct{}{adoptionmode.ScopeAll: {}, adoptionmode.ScopeNone: {}, adoptionmode.ScopeTouched: {}}
}

func identifierShape() jsonshape.Shape {
	return jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
}

// Paths are not trimmed here; native admission owns their safe POSIX grammar.
func pathShape() jsonshape.Shape { return nonemptyText() }

func nonemptyText() jsonshape.Shape { return jsonshape.StringGrammar(`[\s\S]+`) }

func fragment(shape jsonshape.Shape) map[string]any {
	schema := shape.JSONSchema()
	delete(schema, "$schema")
	return schema
}

func valuesShape(values ...string) jsonshape.Shape {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return jsonshape.Enum(set)
}

func sortedValues(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}
