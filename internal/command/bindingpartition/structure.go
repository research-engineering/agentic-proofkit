package bindingpartition

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputKeys = []string{"bindingSurfaces", "delegations", "nonClaims", "partitionId", "proofRouteRefs", "routeOwners", "routeReferences", "schemaVersion", "surfaceThresholds"}
var surfaceKeys = []string{"ownerId", "selectorRefs", "surfaceId"}
var routeOwnerKeys = []string{"cohesionGroupId", "ownerId", "proofRouteRef", "selectorRefs", "surfaceId"}
var routeReferenceKeys = []string{"delegationRefs", "proofRouteRef", "referenceId", "referrerOwnerId", "referrerSurfaceId"}
var delegationKeys = []string{"delegationRef", "evidenceRefs", "fromOwnerId", "fromSurfaceId", "nonClaims", "proofRouteRefs", "reviewConditionRef", "toOwnerId", "toSurfaceId"}
var thresholdKeys = []string{"maxCohesionGroupCount", "maxOwnedProofRouteCount", "maxOwnedSelectorCount", "surfaceId"}

func surfaceFields() map[string]jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	return map[string]jsonshape.Shape{"ownerId": id, "selectorRefs": jsonshape.Array(id, 1), "surfaceId": id}
}

func routeOwnerFields() map[string]jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	fields := surfaceFields()
	fields["cohesionGroupId"], fields["proofRouteRef"] = id, id
	return fields
}

func routeReferenceFields() map[string]jsonshape.Shape {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	return map[string]jsonshape.Shape{
		"delegationRefs": jsonshape.Array(id, 0), "proofRouteRef": id, "referenceId": id, "referrerOwnerId": id, "referrerSurfaceId": id,
	}
}

func InputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	limit := jsonshape.Nullable(jsonshape.IntegerMinimum(1))
	schema := jsonshape.RequiredObject(inputKeys, map[string]jsonshape.Shape{
		"bindingSurfaces": jsonshape.Array(jsonshape.RequiredObject(surfaceKeys, surfaceFields()), 1),
		"delegations": jsonshape.Array(jsonshape.ObjectFromKeys(delegationKeys, map[string]jsonshape.Shape{
			"delegationRef": id, "evidenceRefs": jsonshape.Array(text, 1), "fromOwnerId": id, "fromSurfaceId": id,
			"nonClaims": jsonshape.Array(text, 1), "proofRouteRefs": jsonshape.Array(id, 1),
			"reviewConditionRef": jsonshape.Nullable(id), "toOwnerId": id, "toSurfaceId": id,
		}, "reviewConditionRef"), 0),
		"nonClaims": jsonshape.Array(text, 1), "partitionId": id, "proofRouteRefs": jsonshape.Array(id, 1),
		"routeOwners":     jsonshape.Array(jsonshape.RequiredObject(routeOwnerKeys, routeOwnerFields()), 1),
		"routeReferences": jsonshape.Array(jsonshape.RequiredObject(routeReferenceKeys, routeReferenceFields()), 0),
		"schemaVersion":   jsonshape.IntegerLiteral(1),
		"surfaceThresholds": jsonshape.Array(jsonshape.ObjectFromKeys(thresholdKeys, map[string]jsonshape.Shape{
			"maxCohesionGroupCount": limit, "maxOwnedProofRouteCount": limit, "maxOwnedSelectorCount": limit, "surfaceId": id,
		}, "maxCohesionGroupCount", "maxOwnedProofRouteCount", "maxOwnedSelectorCount"), 0),
	}).JSONSchema()
	properties := schema["properties"].(map[string]any)
	for _, name := range []string{"bindingSurfaces", "delegations", "nonClaims", "proofRouteRefs", "routeReferences", "surfaceThresholds"} {
		properties[name].(map[string]any)["uniqueItems"] = true
	}
	properties["nonClaims"].(map[string]any)["items"].(map[string]any)["not"] = map[string]any{"enum": admit.StringSliceToAny(boundaryNonClaims)}
	for name, lists := range map[string][]string{
		"bindingSurfaces": {"selectorRefs"}, "routeOwners": {"selectorRefs"}, "routeReferences": {"delegationRefs"},
		"delegations": {"evidenceRefs", "nonClaims", "proofRouteRefs"},
	} {
		fields := properties[name].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
		for _, list := range lists {
			fields[list].(map[string]any)["uniqueItems"] = true
		}
	}
	threshold := properties["surfaceThresholds"].(map[string]any)["items"].(map[string]any)
	alternatives := make([]any, 0, 3)
	for _, name := range thresholdKeys[:3] {
		alternatives = append(alternatives, map[string]any{"required": []any{name}, "properties": map[string]any{name: jsonshape.IntegerMinimum(1).JSONSchema()}})
	}
	threshold["anyOf"] = alternatives
	schema["description"] = "All root fields are required. Delegation reviewConditionRef is optional nullable ID; the three threshold limits are optional nullable positive integers, with at least one nonnull limit required. Threshold surfaceId must resolve at admission. Surface/reference/delegation/threshold keys are unique; repeated routeOwners are intentionally admitted and evaluated as failed ownership. ID arrays sort and reject duplicates; text/evidence arrays trim and sort, evidence then uses safe repository-relative POSIX paths. Builtin/caller nonClaim collisions reject. Undeclared routes, owners, surfaces, mismatched delegation relations and exceeded thresholds produce failed reports, not general input rejection. Unused foreign delegations can remain admitted. Key uniqueness, normalized paths/text, privacy, exact integer spelling and relational evaluation remain native."
	return schema
}

func OutputStructure() map[string]any {
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	text := jsonshape.StringGrammar(`[\s\S]+`)
	ids, findings := jsonshape.Array(id, 0), jsonshape.Array(text, 0)
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	ownershipFields := routeOwnerFields()
	ownershipFields["selectorRefs"], ownershipFields["referenceIds"], ownershipFields["structuralFindings"] = ids, ids, findings
	ownership := jsonshape.RequiredObject(append(append([]string{}, routeOwnerKeys...), "referenceIds", "structuralFindings"), ownershipFields)
	referenceFields := routeReferenceFields()
	referenceFields["canonicalOwnerId"], referenceFields["canonicalSurfaceId"] = jsonshape.Nullable(id), jsonshape.Nullable(id)
	referenceFields["crossOwner"], referenceFields["crossSurface"] = jsonshape.Boolean(), jsonshape.Boolean()
	referenceFields["matchedDelegationRefs"], referenceFields["structuralFindings"] = ids, findings
	reference := jsonshape.RequiredObject(append(append([]string{}, routeReferenceKeys...), "canonicalOwnerId", "canonicalSurfaceId", "crossOwner", "crossSurface", "matchedDelegationRefs", "structuralFindings"), referenceFields)
	surfaceFields := surfaceFields()
	surfaceFields["cohesionGroupIds"], surfaceFields["ownedProofRouteRefs"], surfaceFields["ownedSelectorRefs"] = ids, ids, jsonshape.Array(id, 1)
	surfaceFields["structuralFindings"], surfaceFields["thresholdEvaluated"] = findings, jsonshape.Boolean()
	surface := jsonshape.RequiredObject(append(append([]string{}, surfaceKeys...), "cohesionGroupIds", "ownedProofRouteRefs", "ownedSelectorRefs", "structuralFindings", "thresholdEvaluated"), surfaceFields)
	count := jsonshape.IntegerMinimum(0)
	rule := func(suffix, key string, diagnostic jsonshape.Shape) jsonshape.Shape {
		prefix := "proofkit.binding-partition." + suffix + "."
		return report.RuleStructure(jsonshape.BoundedStringGrammar(regexp.QuoteMeta(prefix)+admit.RuleIDPatternBody, len(prefix)+admit.MaxRuleIDBytes),
			status, text, jsonshape.Tuple(report.DiagnosticStructure(key, diagnostic)))
	}
	schema := report.Structure(1, reportKind, status, jsonshape.Object(
		jsonshape.Required("crossOwnerReferenceCount", count), jsonshape.Required("crossSurfaceReferenceCount", count),
		jsonshape.Required("delegationCount", count), jsonshape.Required("failedProofRouteCount", count),
		jsonshape.Required("failedSurfaceCount", count), jsonshape.Required("proofRouteCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("routeReferenceCount", count), jsonshape.Required("surfaceCount", jsonshape.IntegerMinimum(1)),
		jsonshape.Required("thresholdEvaluatedSurfaceCount", count), jsonshape.Required("thresholdSkippedSurfaceCount", count),
	), jsonshape.Tuple(
		report.DiagnosticStructure("delegationDiagnostics", jsonshape.Array(reference, 0)),
		report.DiagnosticStructure("failedProofRouteRefs", ids), report.DiagnosticStructure("failedSurfaceIds", ids),
		report.DiagnosticStructure("routeOwnership", jsonshape.Array(ownership, 1)),
		report.DiagnosticStructure("surfaceDiagnostics", jsonshape.Array(surface, 1)),
	), jsonshape.Array(jsonshape.OneOf(
		rule("route-owner", "routeOwnership", ownership), rule("route-reference", "delegationDiagnostic", reference), rule("surface", "surfaceDiagnostic", surface),
	), 2)).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	claims := jsonshape.Array(text, len(boundaryNonClaims)+1).JSONSchema()
	claims["uniqueItems"] = true
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	claims["allOf"], properties["nonClaims"] = contains, claims
	schema["description"] = "ReportId preserves partitionId. Fixed top-level diagnostics describe references, failed route/surface IDs, route ownership and surfaces. Reference canonicalOwnerId/canonicalSurfaceId are required nullable IDs when zero or multiple owners prevent canonical selection. Missing route owners use named placeholder IDs and an empty selector list. ownedProofRouteRefs can contain duplicates from admitted repeated owner rows. Rules are grouped in route-owner, route-reference, surface order with family-specific prefixed bounded IDs; route identity covers declared routes plus owner/reference routes, not delegation-only refs. Sorted unique nonClaims include all five builtins. Canonical sorting, list uniqueness except repeated owned routes, counts, status/messages, relationships and cross-projection equality remain native. No topology discovery, evidence authentication or proof adequacy is established."
	return schema
}
