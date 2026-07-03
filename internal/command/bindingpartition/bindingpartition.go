package bindingpartition

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.binding-partition-admission"

var boundaryNonClaims = []string{
	"Binding partition admission reports do not approve merge, release, rollout, or production readiness.",
	"Binding partition admission reports do not compute freshness.",
	"Binding partition admission reports do not evaluate requirement meaning or proof adequacy.",
	"Binding partition admission reports do not execute witnesses or authenticate evidence.",
	"Binding partition admission reports do not read repository files or infer topology.",
}

type surfaceInput struct {
	OwnerID      string
	SelectorRefs []string
	SurfaceID    string
}

type routeOwnerInput struct {
	CohesionGroupID string
	OwnerID         string
	ProofRouteRef   string
	SelectorRefs    []string
	SurfaceID       string
}

type routeReferenceInput struct {
	DelegationRefs    []string
	ProofRouteRef     string
	ReferenceID       string
	ReferrerOwnerID   string
	ReferrerSurfaceID string
}

type delegationInput struct {
	DelegationRef      string
	EvidenceRefs       []string
	FromOwnerID        string
	FromSurfaceID      string
	NonClaims          []string
	ProofRouteRefs     []string
	ReviewConditionRef *string
	ToOwnerID          string
	ToSurfaceID        string
}

type thresholdInput struct {
	MaxCohesionGroupCount   *int
	MaxOwnedProofRouteCount *int
	MaxOwnedSelectorCount   *int
	SurfaceID               string
}

type admittedInput struct {
	BindingSurfaces   []surfaceInput
	Delegations       []delegationInput
	NonClaims         []string
	PartitionID       string
	ProofRouteRefs    []string
	RouteOwners       []routeOwnerInput
	RouteReferences   []routeReferenceInput
	SurfaceThresholds []thresholdInput
}

type routeOwnership struct {
	routeOwnerInput
	ReferenceIDs       []string
	StructuralFindings []string
}

type delegationDiagnostic struct {
	routeReferenceInput
	CanonicalOwnerID      *string
	CanonicalSurfaceID    *string
	CrossOwner            bool
	CrossSurface          bool
	MatchedDelegationRefs []string
	StructuralFindings    []string
}

type surfaceDiagnostic struct {
	surfaceInput
	CohesionGroupIDs    []string
	OwnedProofRouteRefs []string
	OwnedSelectorRefs   []string
	StructuralFindings  []string
	ThresholdEvaluated  bool
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	surfacesByID := map[string]surfaceInput{}
	for _, surface := range input.BindingSurfaces {
		surfacesByID[surface.SurfaceID] = surface
	}
	routeOwnersByRef := mapRouteOwners(input.RouteOwners)
	referencesByRouteRef := groupReferencesByRouteRef(input.RouteReferences)
	thresholdsBySurfaceID := map[string]thresholdInput{}
	for _, threshold := range input.SurfaceThresholds {
		thresholdsBySurfaceID[threshold.SurfaceID] = threshold
	}
	selectorOwners := selectorOwnerMap(input.BindingSurfaces)
	declaredProofRouteRefs := map[string]struct{}{}
	for _, proofRouteRef := range input.ProofRouteRefs {
		declaredProofRouteRefs[proofRouteRef] = struct{}{}
	}
	allRouteRefs := sortedUnique(append(append([]string{}, input.ProofRouteRefs...), append(routeOwnerRefs(input.RouteOwners), referenceRouteRefs(input.RouteReferences)...)...))
	routeOwnerships := make([]routeOwnership, 0, len(allRouteRefs))
	for _, proofRouteRef := range allRouteRefs {
		routeOwnerships = append(routeOwnerships, evaluateRouteOwnership(
			proofRouteRef,
			routeOwnersByRef[proofRouteRef],
			referencesByRouteRef[proofRouteRef],
			surfacesByID,
			selectorOwners,
			declaredProofRouteRefs,
		))
	}
	delegationDiagnostics := make([]delegationDiagnostic, 0, len(input.RouteReferences))
	for _, reference := range input.RouteReferences {
		delegationDiagnostics = append(delegationDiagnostics, evaluateRouteReference(reference, routeOwnersByRef[reference.ProofRouteRef], input.Delegations, surfacesByID))
	}
	surfaceDiagnostics := make([]surfaceDiagnostic, 0, len(input.BindingSurfaces))
	for _, surface := range input.BindingSurfaces {
		threshold, ok := thresholdsBySurfaceID[surface.SurfaceID]
		surfaceDiagnostics = append(surfaceDiagnostics, evaluateSurface(surface, input.RouteOwners, selectorOwners, threshold, ok))
	}
	failedProofRouteRefs := sortedUnique(append(failedOwnershipRouteRefs(routeOwnerships), failedDelegationRouteRefs(delegationDiagnostics)...))
	failedSurfaceIDs := failedSurfaceIDs(surfaceDiagnostics)
	state := "passed"
	if len(failedProofRouteRefs) > 0 || len(failedSurfaceIDs) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.PartitionID,
		State:         state,
		Summary: map[string]any{
			"crossOwnerReferenceCount":       countDelegations(delegationDiagnostics, func(item delegationDiagnostic) bool { return item.CrossOwner }),
			"crossSurfaceReferenceCount":     countDelegations(delegationDiagnostics, func(item delegationDiagnostic) bool { return item.CrossSurface }),
			"delegationCount":                len(input.Delegations),
			"failedProofRouteCount":          len(failedProofRouteRefs),
			"failedSurfaceCount":             len(failedSurfaceIDs),
			"proofRouteCount":                len(input.ProofRouteRefs),
			"routeReferenceCount":            len(input.RouteReferences),
			"surfaceCount":                   len(input.BindingSurfaces),
			"thresholdEvaluatedSurfaceCount": countSurfaces(surfaceDiagnostics, func(item surfaceDiagnostic) bool { return item.ThresholdEvaluated }),
			"thresholdSkippedSurfaceCount":   countSurfaces(surfaceDiagnostics, func(item surfaceDiagnostic) bool { return !item.ThresholdEvaluated }),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "delegationDiagnostics", Value: delegationDiagnosticsJSON(delegationDiagnostics)},
			{Key: "failedProofRouteRefs", Value: admit.StringSliceToAny(failedProofRouteRefs)},
			{Key: "failedSurfaceIds", Value: admit.StringSliceToAny(failedSurfaceIDs)},
			{Key: "routeOwnership", Value: routeOwnershipsJSON(routeOwnerships)},
			{Key: "surfaceDiagnostics", Value: surfaceDiagnosticsJSON(surfaceDiagnostics)},
		},
		RuleResults: ruleResults(routeOwnerships, delegationDiagnostics, surfaceDiagnostics),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("binding partition input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bindingSurfaces", "delegations", "nonClaims", "partitionId", "proofRouteRefs", "routeOwners", "routeReferences", "schemaVersion", "surfaceThresholds"}, "binding partition input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("binding partition schemaVersion must be 1")
	}
	proofRouteRefs, err := ruleIDArray(record["proofRouteRefs"], "binding partition proofRouteRefs", false)
	if err != nil {
		return admittedInput{}, err
	}
	bindingSurfaces, err := surfaceArray(record["bindingSurfaces"])
	if err != nil {
		return admittedInput{}, err
	}
	routeOwners, err := routeOwnerArray(record["routeOwners"])
	if err != nil {
		return admittedInput{}, err
	}
	routeReferences, err := routeReferenceArray(record["routeReferences"])
	if err != nil {
		return admittedInput{}, err
	}
	delegations, err := delegationArray(record["delegations"])
	if err != nil {
		return admittedInput{}, err
	}
	surfaceThresholds, err := thresholdArray(record["surfaceThresholds"])
	if err != nil {
		return admittedInput{}, err
	}
	surfaceIDs := map[string]struct{}{}
	for _, surface := range bindingSurfaces {
		surfaceIDs[surface.SurfaceID] = struct{}{}
	}
	for _, threshold := range surfaceThresholds {
		if _, ok := surfaceIDs[threshold.SurfaceID]; !ok {
			return admittedInput{}, fmt.Errorf("binding partition threshold surface %s is not declared", threshold.SurfaceID)
		}
	}
	partitionID, err := admit.RuleID(record["partitionId"], "binding partition partitionId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaimsInput, err := textArray(record["nonClaims"], "binding partition nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), nonClaimsInput...)
	sort.Strings(nonClaims)
	if err := sortedUniqueOrError(nonClaims, "binding partition nonClaims", false); err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		BindingSurfaces:   bindingSurfaces,
		Delegations:       delegations,
		NonClaims:         nonClaims,
		PartitionID:       partitionID,
		ProofRouteRefs:    proofRouteRefs,
		RouteOwners:       routeOwners,
		RouteReferences:   routeReferences,
		SurfaceThresholds: surfaceThresholds,
	}, nil
}

func surfaceArray(raw any) ([]surfaceInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("binding partition bindingSurfaces must be a non-empty array")
	}
	surfaces := make([]surfaceInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("binding partition surface must be an object")
		}
		if err := admit.KnownKeys(record, []string{"ownerId", "selectorRefs", "surfaceId"}, "binding partition surface"); err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(record["surfaceId"], "binding partition surfaceId")
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(record["ownerId"], "binding partition surface ownerId")
		if err != nil {
			return nil, err
		}
		selectorRefs, err := ruleIDArray(record["selectorRefs"], "binding partition surface selectorRefs", false)
		if err != nil {
			return nil, err
		}
		surfaces = append(surfaces, surfaceInput{OwnerID: ownerID, SelectorRefs: selectorRefs, SurfaceID: surfaceID})
	}
	sort.Slice(surfaces, func(left, right int) bool { return surfaces[left].SurfaceID < surfaces[right].SurfaceID })
	return surfaces, uniqueSurfaces(surfaces)
}

func routeOwnerArray(raw any) ([]routeOwnerInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("binding partition routeOwners must be a non-empty array")
	}
	owners := make([]routeOwnerInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("binding partition route owner must be an object")
		}
		if err := admit.KnownKeys(record, []string{"cohesionGroupId", "ownerId", "proofRouteRef", "selectorRefs", "surfaceId"}, "binding partition route owner"); err != nil {
			return nil, err
		}
		owner, err := routeOwner(record)
		if err != nil {
			return nil, err
		}
		owners = append(owners, owner)
	}
	sort.Slice(owners, func(left, right int) bool { return compareRouteOwner(owners[left], owners[right]) < 0 })
	return owners, nil
}

func routeOwner(record map[string]any) (routeOwnerInput, error) {
	proofRouteRef, err := admit.RuleID(record["proofRouteRef"], "binding partition proofRouteRef")
	if err != nil {
		return routeOwnerInput{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], "binding partition route ownerId")
	if err != nil {
		return routeOwnerInput{}, err
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], "binding partition route surfaceId")
	if err != nil {
		return routeOwnerInput{}, err
	}
	selectorRefs, err := ruleIDArray(record["selectorRefs"], "binding partition route selectorRefs", false)
	if err != nil {
		return routeOwnerInput{}, err
	}
	cohesionGroupID, err := admit.RuleID(record["cohesionGroupId"], "binding partition cohesionGroupId")
	if err != nil {
		return routeOwnerInput{}, err
	}
	return routeOwnerInput{CohesionGroupID: cohesionGroupID, OwnerID: ownerID, ProofRouteRef: proofRouteRef, SelectorRefs: selectorRefs, SurfaceID: surfaceID}, nil
}

func routeReferenceArray(raw any) ([]routeReferenceInput, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("binding partition routeReferences must be an array")
	}
	references := make([]routeReferenceInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("binding partition route reference must be an object")
		}
		if err := admit.KnownKeys(record, []string{"delegationRefs", "proofRouteRef", "referenceId", "referrerOwnerId", "referrerSurfaceId"}, "binding partition route reference"); err != nil {
			return nil, err
		}
		reference, err := routeReference(record)
		if err != nil {
			return nil, err
		}
		references = append(references, reference)
	}
	sort.Slice(references, func(left, right int) bool { return references[left].ReferenceID < references[right].ReferenceID })
	return references, uniqueReferences(references)
}

func routeReference(record map[string]any) (routeReferenceInput, error) {
	referenceID, err := admit.RuleID(record["referenceId"], "binding partition referenceId")
	if err != nil {
		return routeReferenceInput{}, err
	}
	referrerOwnerID, err := admit.RuleID(record["referrerOwnerId"], "binding partition referrerOwnerId")
	if err != nil {
		return routeReferenceInput{}, err
	}
	referrerSurfaceID, err := admit.RuleID(record["referrerSurfaceId"], "binding partition referrerSurfaceId")
	if err != nil {
		return routeReferenceInput{}, err
	}
	proofRouteRef, err := admit.RuleID(record["proofRouteRef"], "binding partition reference proofRouteRef")
	if err != nil {
		return routeReferenceInput{}, err
	}
	delegationRefs, err := ruleIDArray(record["delegationRefs"], "binding partition reference delegationRefs", true)
	if err != nil {
		return routeReferenceInput{}, err
	}
	return routeReferenceInput{DelegationRefs: delegationRefs, ProofRouteRef: proofRouteRef, ReferenceID: referenceID, ReferrerOwnerID: referrerOwnerID, ReferrerSurfaceID: referrerSurfaceID}, nil
}

func delegationArray(raw any) ([]delegationInput, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("binding partition delegations must be an array")
	}
	delegations := make([]delegationInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("binding partition delegation must be an object")
		}
		if err := admit.KnownKeys(record, []string{"delegationRef", "evidenceRefs", "fromOwnerId", "fromSurfaceId", "nonClaims", "proofRouteRefs", "reviewConditionRef", "toOwnerId", "toSurfaceId"}, "binding partition delegation"); err != nil {
			return nil, err
		}
		delegation, err := delegation(record)
		if err != nil {
			return nil, err
		}
		delegations = append(delegations, delegation)
	}
	sort.Slice(delegations, func(left, right int) bool { return delegations[left].DelegationRef < delegations[right].DelegationRef })
	return delegations, uniqueDelegations(delegations)
}

func delegation(record map[string]any) (delegationInput, error) {
	delegationRef, err := admit.RuleID(record["delegationRef"], "binding partition delegationRef")
	if err != nil {
		return delegationInput{}, err
	}
	fromOwnerID, err := admit.RuleID(record["fromOwnerId"], "binding partition delegation fromOwnerId")
	if err != nil {
		return delegationInput{}, err
	}
	fromSurfaceID, err := admit.RuleID(record["fromSurfaceId"], "binding partition delegation fromSurfaceId")
	if err != nil {
		return delegationInput{}, err
	}
	toOwnerID, err := admit.RuleID(record["toOwnerId"], "binding partition delegation toOwnerId")
	if err != nil {
		return delegationInput{}, err
	}
	toSurfaceID, err := admit.RuleID(record["toSurfaceId"], "binding partition delegation toSurfaceId")
	if err != nil {
		return delegationInput{}, err
	}
	proofRouteRefs, err := ruleIDArray(record["proofRouteRefs"], "binding partition delegation proofRouteRefs", false)
	if err != nil {
		return delegationInput{}, err
	}
	evidenceRefs, err := pathArray(record["evidenceRefs"], "binding partition delegation evidenceRefs", false)
	if err != nil {
		return delegationInput{}, err
	}
	reviewConditionRef, err := nullableRuleID(record["reviewConditionRef"], "binding partition delegation reviewConditionRef")
	if err != nil {
		return delegationInput{}, err
	}
	nonClaims, err := textArray(record["nonClaims"], "binding partition delegation nonClaims", false)
	if err != nil {
		return delegationInput{}, err
	}
	return delegationInput{DelegationRef: delegationRef, EvidenceRefs: evidenceRefs, FromOwnerID: fromOwnerID, FromSurfaceID: fromSurfaceID, NonClaims: nonClaims, ProofRouteRefs: proofRouteRefs, ReviewConditionRef: reviewConditionRef, ToOwnerID: toOwnerID, ToSurfaceID: toSurfaceID}, nil
}

func thresholdArray(raw any) ([]thresholdInput, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("binding partition surfaceThresholds must be an array")
	}
	thresholds := make([]thresholdInput, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("binding partition threshold must be an object")
		}
		if err := admit.KnownKeys(record, []string{"maxCohesionGroupCount", "maxOwnedProofRouteCount", "maxOwnedSelectorCount", "surfaceId"}, "binding partition threshold"); err != nil {
			return nil, err
		}
		threshold, err := threshold(record)
		if err != nil {
			return nil, err
		}
		thresholds = append(thresholds, threshold)
	}
	sort.Slice(thresholds, func(left, right int) bool { return thresholds[left].SurfaceID < thresholds[right].SurfaceID })
	return thresholds, uniqueThresholds(thresholds)
}

func threshold(record map[string]any) (thresholdInput, error) {
	surfaceID, err := admit.RuleID(record["surfaceId"], "binding partition threshold surfaceId")
	if err != nil {
		return thresholdInput{}, err
	}
	result := thresholdInput{SurfaceID: surfaceID}
	if record["maxCohesionGroupCount"] != nil {
		value, err := admit.PositiveInteger(record["maxCohesionGroupCount"], "binding partition maxCohesionGroupCount")
		if err != nil {
			return thresholdInput{}, err
		}
		result.MaxCohesionGroupCount = &value
	}
	if record["maxOwnedProofRouteCount"] != nil {
		value, err := admit.PositiveInteger(record["maxOwnedProofRouteCount"], "binding partition maxOwnedProofRouteCount")
		if err != nil {
			return thresholdInput{}, err
		}
		result.MaxOwnedProofRouteCount = &value
	}
	if record["maxOwnedSelectorCount"] != nil {
		value, err := admit.PositiveInteger(record["maxOwnedSelectorCount"], "binding partition maxOwnedSelectorCount")
		if err != nil {
			return thresholdInput{}, err
		}
		result.MaxOwnedSelectorCount = &value
	}
	if result.MaxCohesionGroupCount == nil && result.MaxOwnedProofRouteCount == nil && result.MaxOwnedSelectorCount == nil {
		return thresholdInput{}, fmt.Errorf("binding partition threshold must declare at least one limit")
	}
	return result, nil
}

func evaluateRouteOwnership(proofRouteRef string, ownerRecords []routeOwnerInput, references []routeReferenceInput, surfacesByID map[string]surfaceInput, selectorOwners map[string][]string, declaredProofRouteRefs map[string]struct{}) routeOwnership {
	findings := []string{}
	if _, ok := declaredProofRouteRefs[proofRouteRef]; !ok {
		findings = append(findings, fmt.Sprintf("proofRouteRef %s is not listed in proofRouteRefs", proofRouteRef))
	}
	if len(ownerRecords) == 0 {
		findings = append(findings, fmt.Sprintf("proofRouteRef %s has no canonical route owner", proofRouteRef))
	}
	if len(ownerRecords) > 1 {
		findings = append(findings, fmt.Sprintf("proofRouteRef %s has more than one canonical route owner", proofRouteRef))
	}
	referenceIDs := referenceIDs(references)
	if len(ownerRecords) > 0 {
		owner := ownerRecords[0]
		findings = append(findings, routeOwnerFindings(owner, surfacesByID, selectorOwners)...)
		sort.Strings(findings)
		return routeOwnership{
			routeOwnerInput:    owner,
			ReferenceIDs:       referenceIDs,
			StructuralFindings: findings,
		}
	}
	sort.Strings(findings)
	return routeOwnership{
		routeOwnerInput: routeOwnerInput{
			CohesionGroupID: "missing_cohesion_group",
			OwnerID:         "missing_owner",
			ProofRouteRef:   proofRouteRef,
			SelectorRefs:    []string{},
			SurfaceID:       "missing_surface",
		},
		ReferenceIDs:       referenceIDs,
		StructuralFindings: findings,
	}
}

func routeOwnerFindings(owner routeOwnerInput, surfacesByID map[string]surfaceInput, selectorOwners map[string][]string) []string {
	surface, ok := surfacesByID[owner.SurfaceID]
	if !ok {
		return []string{fmt.Sprintf("route owner surface %s is not declared", owner.SurfaceID)}
	}
	findings := []string{}
	if owner.OwnerID != surface.OwnerID {
		findings = append(findings, fmt.Sprintf("route owner %s differs from surface owner %s", owner.OwnerID, surface.OwnerID))
	}
	surfaceSelectorRefs := map[string]struct{}{}
	for _, selectorRef := range surface.SelectorRefs {
		surfaceSelectorRefs[selectorRef] = struct{}{}
	}
	for _, selectorRef := range owner.SelectorRefs {
		if _, ok := surfaceSelectorRefs[selectorRef]; !ok {
			findings = append(findings, fmt.Sprintf("route selector %s is not declared by surface %s", selectorRef, owner.SurfaceID))
		}
		if len(selectorOwners[selectorRef]) > 1 {
			findings = append(findings, fmt.Sprintf("route selector %s is declared by multiple surfaces", selectorRef))
		}
	}
	return findings
}

func evaluateRouteReference(reference routeReferenceInput, ownerRecords []routeOwnerInput, delegations []delegationInput, surfacesByID map[string]surfaceInput) delegationDiagnostic {
	var owner *routeOwnerInput
	if len(ownerRecords) == 1 {
		owner = &ownerRecords[0]
	}
	referrerSurface, referrerSurfaceExists := surfacesByID[reference.ReferrerSurfaceID]
	crossOwner := owner != nil && owner.OwnerID != reference.ReferrerOwnerID
	crossSurface := owner != nil && owner.SurfaceID != reference.ReferrerSurfaceID
	matchedDelegationRefs := []string{}
	if owner != nil {
		for _, delegationRef := range reference.DelegationRefs {
			for _, delegation := range delegations {
				if delegationMatchesReference(delegation, reference, *owner, delegationRef) {
					matchedDelegationRefs = append(matchedDelegationRefs, delegationRef)
					break
				}
			}
		}
		sort.Strings(matchedDelegationRefs)
	}
	findings := []string{}
	if len(ownerRecords) == 0 {
		findings = append(findings, fmt.Sprintf("reference %s points at an unowned proofRouteRef", reference.ReferenceID))
	}
	if len(ownerRecords) > 1 {
		findings = append(findings, fmt.Sprintf("reference %s points at a multiply owned proofRouteRef", reference.ReferenceID))
	}
	if !referrerSurfaceExists {
		findings = append(findings, fmt.Sprintf("reference %s referrer surface %s is not declared", reference.ReferenceID, reference.ReferrerSurfaceID))
	}
	if referrerSurfaceExists && referrerSurface.OwnerID != reference.ReferrerOwnerID {
		findings = append(findings, fmt.Sprintf("reference %s referrer owner %s differs from surface owner %s", reference.ReferenceID, reference.ReferrerOwnerID, referrerSurface.OwnerID))
	}
	if (crossOwner || crossSurface) && len(matchedDelegationRefs) == 0 {
		findings = append(findings, fmt.Sprintf("reference %s crosses owner or surface without exact delegation", reference.ReferenceID))
	}
	if owner != nil && !crossOwner && !crossSurface && len(reference.DelegationRefs) > 0 {
		findings = append(findings, fmt.Sprintf("reference %s declares delegationRefs for same-owner same-surface route", reference.ReferenceID))
	}
	if len(matchedDelegationRefs) != len(reference.DelegationRefs) {
		unmatched := []string{}
		matched := map[string]struct{}{}
		for _, ref := range matchedDelegationRefs {
			matched[ref] = struct{}{}
		}
		for _, delegationRef := range reference.DelegationRefs {
			if _, ok := matched[delegationRef]; !ok {
				unmatched = append(unmatched, delegationRef)
			}
		}
		if len(unmatched) > 0 {
			findings = append(findings, fmt.Sprintf("reference %s has unmatched delegationRefs: %s", reference.ReferenceID, strings.Join(unmatched, ", ")))
		}
	}
	sort.Strings(findings)
	var canonicalOwnerID *string
	var canonicalSurfaceID *string
	if owner != nil {
		canonicalOwnerID = &owner.OwnerID
		canonicalSurfaceID = &owner.SurfaceID
	}
	return delegationDiagnostic{
		routeReferenceInput:   reference,
		CanonicalOwnerID:      canonicalOwnerID,
		CanonicalSurfaceID:    canonicalSurfaceID,
		CrossOwner:            crossOwner,
		CrossSurface:          crossSurface,
		MatchedDelegationRefs: matchedDelegationRefs,
		StructuralFindings:    findings,
	}
}

func delegationMatchesReference(delegation delegationInput, reference routeReferenceInput, owner routeOwnerInput, delegationRef string) bool {
	return delegation.DelegationRef == delegationRef &&
		delegation.FromOwnerID == reference.ReferrerOwnerID &&
		delegation.FromSurfaceID == reference.ReferrerSurfaceID &&
		delegation.ToOwnerID == owner.OwnerID &&
		delegation.ToSurfaceID == owner.SurfaceID &&
		includes(delegation.ProofRouteRefs, reference.ProofRouteRef)
}

func evaluateSurface(surface surfaceInput, routeOwners []routeOwnerInput, selectorOwners map[string][]string, threshold thresholdInput, hasThreshold bool) surfaceDiagnostic {
	ownedRoutes := []routeOwnerInput{}
	for _, owner := range routeOwners {
		if owner.SurfaceID == surface.SurfaceID {
			ownedRoutes = append(ownedRoutes, owner)
		}
	}
	ownedProofRouteRefs := routeOwnerRefs(ownedRoutes)
	cohesionGroupIDs := sortedUnique(routeOwnerCohesionGroups(ownedRoutes))
	findings := []string{}
	for _, selectorRef := range surface.SelectorRefs {
		if len(selectorOwners[selectorRef]) > 1 {
			findings = append(findings, fmt.Sprintf("selector %s is declared by multiple surfaces", selectorRef))
		}
	}
	if hasThreshold {
		findings = append(findings, thresholdFindings(surface.SurfaceID, threshold, len(cohesionGroupIDs), len(ownedProofRouteRefs), len(surface.SelectorRefs))...)
	}
	sort.Strings(findings)
	return surfaceDiagnostic{
		surfaceInput:        surface,
		CohesionGroupIDs:    cohesionGroupIDs,
		OwnedProofRouteRefs: ownedProofRouteRefs,
		OwnedSelectorRefs:   surface.SelectorRefs,
		StructuralFindings:  findings,
		ThresholdEvaluated:  hasThreshold,
	}
}

func thresholdFindings(surfaceID string, threshold thresholdInput, cohesionGroupCount int, ownedProofRouteCount int, ownedSelectorCount int) []string {
	findings := []string{}
	if threshold.MaxOwnedSelectorCount != nil && ownedSelectorCount > *threshold.MaxOwnedSelectorCount {
		findings = append(findings, fmt.Sprintf("surface %s exceeds caller maxOwnedSelectorCount: %d > %d", surfaceID, ownedSelectorCount, *threshold.MaxOwnedSelectorCount))
	}
	if threshold.MaxOwnedProofRouteCount != nil && ownedProofRouteCount > *threshold.MaxOwnedProofRouteCount {
		findings = append(findings, fmt.Sprintf("surface %s exceeds caller maxOwnedProofRouteCount: %d > %d", surfaceID, ownedProofRouteCount, *threshold.MaxOwnedProofRouteCount))
	}
	if threshold.MaxCohesionGroupCount != nil && cohesionGroupCount > *threshold.MaxCohesionGroupCount {
		findings = append(findings, fmt.Sprintf("surface %s exceeds caller maxCohesionGroupCount: %d > %d", surfaceID, cohesionGroupCount, *threshold.MaxCohesionGroupCount))
	}
	return findings
}

func mapRouteOwners(routeOwners []routeOwnerInput) map[string][]routeOwnerInput {
	result := map[string][]routeOwnerInput{}
	for _, owner := range routeOwners {
		result[owner.ProofRouteRef] = append(result[owner.ProofRouteRef], owner)
	}
	for key := range result {
		sort.Slice(result[key], func(left, right int) bool { return compareRouteOwner(result[key][left], result[key][right]) < 0 })
	}
	return result
}

func groupReferencesByRouteRef(references []routeReferenceInput) map[string][]routeReferenceInput {
	result := map[string][]routeReferenceInput{}
	for _, reference := range references {
		result[reference.ProofRouteRef] = append(result[reference.ProofRouteRef], reference)
	}
	for key := range result {
		sort.Slice(result[key], func(left, right int) bool { return result[key][left].ReferenceID < result[key][right].ReferenceID })
	}
	return result
}

func selectorOwnerMap(surfaces []surfaceInput) map[string][]string {
	result := map[string][]string{}
	for _, surface := range surfaces {
		for _, selectorRef := range surface.SelectorRefs {
			result[selectorRef] = append(result[selectorRef], surface.SurfaceID)
		}
	}
	for key := range result {
		sort.Strings(result[key])
	}
	return result
}

func routeOwnershipsJSON(values []routeOwnership) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, reportRouteOwnership(value))
	}
	return result
}

func delegationDiagnosticsJSON(values []delegationDiagnostic) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, reportDelegationDiagnostic(value))
	}
	return result
}

func surfaceDiagnosticsJSON(values []surfaceDiagnostic) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, reportSurfaceDiagnostic(value))
	}
	return result
}

func reportRouteOwnership(ownership routeOwnership) map[string]any {
	return map[string]any{
		"cohesionGroupId":    ownership.CohesionGroupID,
		"ownerId":            ownership.OwnerID,
		"proofRouteRef":      ownership.ProofRouteRef,
		"referenceIds":       admit.StringSliceToAny(ownership.ReferenceIDs),
		"selectorRefs":       admit.StringSliceToAny(ownership.SelectorRefs),
		"structuralFindings": admit.StringSliceToAny(ownership.StructuralFindings),
		"surfaceId":          ownership.SurfaceID,
	}
}

func reportDelegationDiagnostic(diagnostic delegationDiagnostic) map[string]any {
	return map[string]any{
		"canonicalOwnerId":      nullableStringValue(diagnostic.CanonicalOwnerID),
		"canonicalSurfaceId":    nullableStringValue(diagnostic.CanonicalSurfaceID),
		"crossOwner":            diagnostic.CrossOwner,
		"crossSurface":          diagnostic.CrossSurface,
		"delegationRefs":        admit.StringSliceToAny(diagnostic.DelegationRefs),
		"matchedDelegationRefs": admit.StringSliceToAny(diagnostic.MatchedDelegationRefs),
		"proofRouteRef":         diagnostic.ProofRouteRef,
		"referenceId":           diagnostic.ReferenceID,
		"referrerOwnerId":       diagnostic.ReferrerOwnerID,
		"referrerSurfaceId":     diagnostic.ReferrerSurfaceID,
		"structuralFindings":    admit.StringSliceToAny(diagnostic.StructuralFindings),
	}
}

func reportSurfaceDiagnostic(surface surfaceDiagnostic) map[string]any {
	return map[string]any{
		"cohesionGroupIds":    admit.StringSliceToAny(surface.CohesionGroupIDs),
		"ownedProofRouteRefs": admit.StringSliceToAny(surface.OwnedProofRouteRefs),
		"ownedSelectorRefs":   admit.StringSliceToAny(surface.OwnedSelectorRefs),
		"ownerId":             surface.OwnerID,
		"selectorRefs":        admit.StringSliceToAny(surface.SelectorRefs),
		"structuralFindings":  admit.StringSliceToAny(surface.StructuralFindings),
		"surfaceId":           surface.SurfaceID,
		"thresholdEvaluated":  surface.ThresholdEvaluated,
	}
}

func ruleResults(routeOwnerships []routeOwnership, delegationDiagnostics []delegationDiagnostic, surfaceDiagnostics []surfaceDiagnostic) []report.RuleResult {
	results := []report.RuleResult{}
	for _, ownership := range routeOwnerships {
		results = append(results, routeOwnershipRuleResult(ownership))
	}
	for _, diagnostic := range delegationDiagnostics {
		results = append(results, delegationRuleResult(diagnostic))
	}
	for _, surface := range surfaceDiagnostics {
		results = append(results, surfaceRuleResult(surface))
	}
	return results
}

func routeOwnershipRuleResult(ownership routeOwnership) report.RuleResult {
	status := "passed"
	message := fmt.Sprintf("proof route %s has one admitted owner", ownership.ProofRouteRef)
	if len(ownership.StructuralFindings) > 0 {
		status = "failed"
		message = fmt.Sprintf("proof route %s has invalid route ownership", ownership.ProofRouteRef)
	}
	return report.RuleResult{
		Diagnostics: []report.Diagnostic{{Key: "routeOwnership", Value: reportRouteOwnership(ownership)}},
		Message:     message,
		RuleID:      fmt.Sprintf("proofkit.binding-partition.route-owner.%s", ownership.ProofRouteRef),
		Status:      status,
	}
}

func delegationRuleResult(diagnostic delegationDiagnostic) report.RuleResult {
	status := "passed"
	message := fmt.Sprintf("route reference %s has admitted ownership path", diagnostic.ReferenceID)
	if len(diagnostic.StructuralFindings) > 0 {
		status = "failed"
		message = fmt.Sprintf("route reference %s has invalid ownership path", diagnostic.ReferenceID)
	}
	return report.RuleResult{
		Diagnostics: []report.Diagnostic{{Key: "delegationDiagnostic", Value: reportDelegationDiagnostic(diagnostic)}},
		Message:     message,
		RuleID:      fmt.Sprintf("proofkit.binding-partition.route-reference.%s", diagnostic.ReferenceID),
		Status:      status,
	}
}

func surfaceRuleResult(surface surfaceDiagnostic) report.RuleResult {
	status := "passed"
	message := fmt.Sprintf("surface %s has admitted partition shape", surface.SurfaceID)
	if len(surface.StructuralFindings) > 0 {
		status = "failed"
		message = fmt.Sprintf("surface %s has invalid partition shape", surface.SurfaceID)
	}
	return report.RuleResult{
		Diagnostics: []report.Diagnostic{{Key: "surfaceDiagnostic", Value: reportSurfaceDiagnostic(surface)}},
		Message:     message,
		RuleID:      fmt.Sprintf("proofkit.binding-partition.surface.%s", surface.SurfaceID),
		Status:      status,
	}
}

func ruleIDArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, ruleID)
	}
	sort.Strings(result)
	return result, sortedUniqueOrError(result, context, allowEmpty)
}

func pathArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		path, err := admit.SafeRepoRelativePath(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, path)
	}
	sort.Strings(result)
	return result, sortedUniqueOrError(result, context, allowEmpty)
}

func textArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	sort.Strings(result)
	return result, sortedUniqueOrError(result, context, allowEmpty)
}

func nullableRuleID(raw any, context string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func sortedUnique(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func sortedUniqueOrError(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must not be empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func compareRouteOwner(left routeOwnerInput, right routeOwnerInput) int {
	return compareText(left.ProofRouteRef, right.ProofRouteRef,
		left.OwnerID, right.OwnerID,
		left.SurfaceID, right.SurfaceID,
		left.CohesionGroupID, right.CohesionGroupID,
		strings.Join(left.SelectorRefs, "\n"), strings.Join(right.SelectorRefs, "\n"))
}

func compareText(values ...string) int {
	for index := 0; index < len(values); index += 2 {
		left := values[index]
		right := values[index+1]
		if left < right {
			return -1
		}
		if left > right {
			return 1
		}
	}
	return 0
}

func uniqueSurfaces(surfaces []surfaceInput) error {
	ids := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		ids = append(ids, surface.SurfaceID)
	}
	return sortedUniqueOrError(ids, "binding partition surface ids", false)
}

func uniqueReferences(references []routeReferenceInput) error {
	ids := make([]string, 0, len(references))
	for _, reference := range references {
		ids = append(ids, reference.ReferenceID)
	}
	return sortedUniqueOrError(ids, "binding partition reference ids", true)
}

func uniqueDelegations(delegations []delegationInput) error {
	ids := make([]string, 0, len(delegations))
	for _, delegation := range delegations {
		ids = append(ids, delegation.DelegationRef)
	}
	return sortedUniqueOrError(ids, "binding partition delegation refs", true)
}

func uniqueThresholds(thresholds []thresholdInput) error {
	ids := make([]string, 0, len(thresholds))
	for _, threshold := range thresholds {
		ids = append(ids, threshold.SurfaceID)
	}
	return sortedUniqueOrError(ids, "binding partition threshold surface ids", true)
}

func routeOwnerRefs(values []routeOwnerInput) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ProofRouteRef)
	}
	sort.Strings(result)
	return result
}

func routeOwnerCohesionGroups(values []routeOwnerInput) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.CohesionGroupID)
	}
	return result
}

func referenceRouteRefs(values []routeReferenceInput) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ProofRouteRef)
	}
	sort.Strings(result)
	return result
}

func referenceIDs(values []routeReferenceInput) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.ReferenceID)
	}
	sort.Strings(result)
	return result
}

func failedOwnershipRouteRefs(values []routeOwnership) []string {
	result := []string{}
	for _, value := range values {
		if len(value.StructuralFindings) > 0 {
			result = append(result, value.ProofRouteRef)
		}
	}
	return result
}

func failedDelegationRouteRefs(values []delegationDiagnostic) []string {
	result := []string{}
	for _, value := range values {
		if len(value.StructuralFindings) > 0 {
			result = append(result, value.ProofRouteRef)
		}
	}
	return result
}

func failedSurfaceIDs(values []surfaceDiagnostic) []string {
	result := []string{}
	for _, value := range values {
		if len(value.StructuralFindings) > 0 {
			result = append(result, value.SurfaceID)
		}
	}
	sort.Strings(result)
	return result
}

func countDelegations(values []delegationDiagnostic, predicate func(delegationDiagnostic) bool) int {
	count := 0
	for _, value := range values {
		if predicate(value) {
			count++
		}
	}
	return count
}

func countSurfaces(values []surfaceDiagnostic, predicate func(surfaceDiagnostic) bool) int {
	count := 0
	for _, value := range values {
		if predicate(value) {
			count++
		}
	}
	return count
}

func nullableStringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func includes(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
