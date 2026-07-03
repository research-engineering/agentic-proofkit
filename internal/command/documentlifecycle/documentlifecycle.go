package documentlifecycle

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.document-lifecycle-boundary"

var lifecycleKinds = map[string]struct{}{
	"context":             {},
	"decision_record":     {},
	"design_doc":          {},
	"generated_lookup":    {},
	"implementation_plan": {},
	"proof_binding":       {},
	"rendered_view":       {},
	"requirement_records": {},
	"router":              {},
	"skill":               {},
	"spec_overview":       {},
	"work_ledger":         {},
}

var lifecycleStates = map[string]struct{}{
	"active_pr_local":     {},
	"archived_historical": {},
	"current":             {},
	"merged_retained":     {},
}

var authorityRoles = map[string]struct{}{
	"durable_meaning":        {},
	"generated_lookup":       {},
	"historical_evidence":    {},
	"navigation":             {},
	"open_work_truth":        {},
	"presentation_only":      {},
	"proof_route":            {},
	"temporary_pr_reasoning": {},
	"workflow_memory":        {},
}

var routingRoles = map[string]struct{}{
	"historical_reference": {},
	"lookup_projection":    {},
	"none":                 {},
	"owner_surface":        {},
	"presentation_view":    {},
	"primary_router":       {},
	"pr_local_input":       {},
	"restore_surface":      {},
}

var activeAuthorityRoles = map[string]struct{}{
	"durable_meaning":   {},
	"generated_lookup":  {},
	"navigation":        {},
	"open_work_truth":   {},
	"presentation_only": {},
	"proof_route":       {},
	"workflow_memory":   {},
}

var currentRoutingRoles = map[string]struct{}{
	"owner_surface":   {},
	"primary_router":  {},
	"restore_surface": {},
}

var temporaryKinds = map[string]struct{}{
	"design_doc":          {},
	"implementation_plan": {},
}

var presentationKinds = map[string]struct{}{
	"generated_lookup": {},
	"rendered_view":    {},
}

var durableKinds = map[string]struct{}{
	"context":             {},
	"decision_record":     {},
	"proof_binding":       {},
	"requirement_records": {},
	"router":              {},
	"skill":               {},
	"spec_overview":       {},
	"work_ledger":         {},
}

var boundaryNonClaims = []any{
	"Document lifecycle boundary reports do not approve merge or archive deletion.",
	"Document lifecycle boundary reports do not decide product semantics.",
	"Document lifecycle boundary reports do not execute documentation checks.",
	"Document lifecycle boundary reports do not prove generated artifact freshness.",
	"Document lifecycle boundary reports do not read document content.",
}

type documentInput struct {
	AuthorityRole      string
	DocumentID         string
	ForbiddenPayloads  []string
	FreshnessCheckRefs []string
	Kind               string
	LifecycleState     string
	MutationTriggers   []string
	NonClaims          []string
	Owner              string
	Path               string
	RoutingRole        string
	SourceRefs         []string
}

type admittedInput struct {
	BoundaryID string
	Documents  []documentInput
	NonClaims  []string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	failures := []string{}
	for _, document := range input.Documents {
		failures = append(failures, documentFailures(document)...)
	}
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(admit.AnySliceToString(boundaryNonClaims), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.BoundaryID,
		State:         state,
		Summary: map[string]any{
			"archivedDocumentCount":    countLifecycleState(input.Documents, "archived_historical"),
			"currentAuthorityCount":    countActiveAuthority(input.Documents),
			"documentCount":            len(input.Documents),
			"failureCount":             len(failures),
			"historicalAuthorityCount": countAuthorityRole(input.Documents, "historical_evidence"),
			"temporaryDocumentCount":   countTemporaryKinds(input.Documents),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
		},
		RuleResults: documentLifecycleRuleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("document lifecycle boundary input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"boundaryId", "documents", "nonClaims", "schemaVersion"}, "document lifecycle boundary input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("document lifecycle boundary schemaVersion must be 1")
	}
	documents, err := documentArray(record["documents"])
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "document lifecycle boundary nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	boundaryID, err := admit.RuleID(record["boundaryId"], "document lifecycle boundaryId")
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		BoundaryID: boundaryID,
		Documents:  documents,
		NonClaims:  nonClaims,
	}, nil
}

func documentArray(raw any) ([]documentInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("document lifecycle records must be a non-empty array")
	}
	documents := make([]documentInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("document lifecycle records[%d] must be an object", index)
		}
		document, err := admitDocument(record)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	sort.Slice(documents, func(left int, right int) bool {
		return documents[left].DocumentID < documents[right].DocumentID
	})
	for index := 1; index < len(documents); index++ {
		if documents[index-1].DocumentID == documents[index].DocumentID {
			return nil, fmt.Errorf("document lifecycle document ids must be sorted and unique")
		}
	}
	return documents, nil
}

func admitDocument(record map[string]any) (documentInput, error) {
	if err := admit.KnownKeys(record, []string{"authorityRole", "documentId", "forbiddenPayloads", "freshnessCheckRefs", "kind", "lifecycleState", "mutationTriggers", "nonClaims", "owner", "path", "routingRole", "sourceRefs"}, "document lifecycle record"); err != nil {
		return documentInput{}, err
	}
	documentID, err := admit.RuleID(record["documentId"], "document lifecycle documentId")
	if err != nil {
		return documentInput{}, err
	}
	pathText, err := admit.NonEmptyText(record["path"], fmt.Sprintf("document lifecycle %s path", documentID))
	if err != nil {
		return documentInput{}, err
	}
	pathValue, err := admit.SafeRepoRelativePath(pathText, fmt.Sprintf("document lifecycle %s path", documentID))
	if err != nil {
		return documentInput{}, err
	}
	kind, err := admit.Enum(record["kind"], lifecycleKinds, fmt.Sprintf("document lifecycle %s kind", documentID))
	if err != nil {
		return documentInput{}, err
	}
	lifecycleState, err := admit.Enum(record["lifecycleState"], lifecycleStates, fmt.Sprintf("document lifecycle %s lifecycleState", documentID))
	if err != nil {
		return documentInput{}, err
	}
	authorityRole, err := admit.Enum(record["authorityRole"], authorityRoles, fmt.Sprintf("document lifecycle %s authorityRole", documentID))
	if err != nil {
		return documentInput{}, err
	}
	routingRole, err := admit.Enum(record["routingRole"], routingRoles, fmt.Sprintf("document lifecycle %s routingRole", documentID))
	if err != nil {
		return documentInput{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], fmt.Sprintf("document lifecycle %s owner", documentID))
	if err != nil {
		return documentInput{}, err
	}
	mutationTriggers, err := admit.PreserveSortedTextArray(record["mutationTriggers"], fmt.Sprintf("document lifecycle %s mutationTriggers", documentID), false)
	if err != nil {
		return documentInput{}, err
	}
	freshnessCheckRefs, err := admit.PreserveSortedPathArray(record["freshnessCheckRefs"], fmt.Sprintf("document lifecycle %s freshnessCheckRefs", documentID), true)
	if err != nil {
		return documentInput{}, err
	}
	sourceRefs, err := admit.PreserveSortedPathArray(record["sourceRefs"], fmt.Sprintf("document lifecycle %s sourceRefs", documentID), true)
	if err != nil {
		return documentInput{}, err
	}
	forbiddenPayloads, err := admit.PreserveSortedTextArray(record["forbiddenPayloads"], fmt.Sprintf("document lifecycle %s forbiddenPayloads", documentID), false)
	if err != nil {
		return documentInput{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], fmt.Sprintf("document lifecycle %s nonClaims", documentID), false)
	if err != nil {
		return documentInput{}, err
	}
	return documentInput{
		AuthorityRole:      authorityRole,
		DocumentID:         documentID,
		ForbiddenPayloads:  forbiddenPayloads,
		FreshnessCheckRefs: freshnessCheckRefs,
		Kind:               kind,
		LifecycleState:     lifecycleState,
		MutationTriggers:   mutationTriggers,
		NonClaims:          nonClaims,
		Owner:              owner,
		Path:               pathValue,
		RoutingRole:        routingRole,
		SourceRefs:         sourceRefs,
	}, nil
}

func documentFailures(document documentInput) []string {
	failures := []string{}
	if has(temporaryKinds, document.Kind) {
		if document.LifecycleState == "active_pr_local" {
			if document.AuthorityRole != "temporary_pr_reasoning" {
				failures = append(failures, fmt.Sprintf("active PR-local %s must use temporary_pr_reasoning authority: %s", document.Kind, document.DocumentID))
			}
			if document.RoutingRole != "pr_local_input" && document.RoutingRole != "none" {
				failures = append(failures, fmt.Sprintf("active PR-local %s must use pr_local_input or none routing: %s", document.Kind, document.DocumentID))
			}
		} else if document.LifecycleState == "current" {
			failures = append(failures, fmt.Sprintf("temporary %s must not use current lifecycle state: %s", document.Kind, document.DocumentID))
		} else {
			if document.AuthorityRole != "historical_evidence" {
				failures = append(failures, fmt.Sprintf("retained %s must be historical evidence only: %s", document.Kind, document.DocumentID))
			}
			if document.RoutingRole != "historical_reference" && document.RoutingRole != "none" {
				failures = append(failures, fmt.Sprintf("retained %s must not be routed as current authority: %s", document.Kind, document.DocumentID))
			}
		}
	}
	if !has(temporaryKinds, document.Kind) && document.AuthorityRole == "temporary_pr_reasoning" {
		failures = append(failures, fmt.Sprintf("non-temporary document must not use temporary_pr_reasoning authority: %s", document.DocumentID))
	}
	if document.LifecycleState == "archived_historical" && has(activeAuthorityRoles, document.AuthorityRole) {
		failures = append(failures, fmt.Sprintf("archived document must not keep active authority: %s", document.DocumentID))
	}
	if document.LifecycleState == "archived_historical" && has(currentRoutingRoles, document.RoutingRole) {
		failures = append(failures, fmt.Sprintf("archived document must not keep current routing role: %s", document.DocumentID))
	}
	if has(presentationKinds, document.Kind) {
		expectedAuthority := expectedPresentationAuthorityRole(document.Kind)
		expectedRouting := expectedPresentationRoutingRole(document.Kind)
		if document.AuthorityRole != expectedAuthority {
			failures = append(failures, fmt.Sprintf("%s document must use %s authority role: %s", document.Kind, expectedAuthority, document.DocumentID))
		}
		if len(document.SourceRefs) == 0 {
			failures = append(failures, fmt.Sprintf("%s document must declare source refs: %s", document.Kind, document.DocumentID))
		}
		if len(document.FreshnessCheckRefs) == 0 {
			failures = append(failures, fmt.Sprintf("%s document must declare freshness check refs: %s", document.Kind, document.DocumentID))
		}
		if document.RoutingRole != expectedRouting && document.RoutingRole != "none" {
			failures = append(failures, fmt.Sprintf("%s document must use %s or none routing: %s", document.Kind, expectedRouting, document.DocumentID))
		}
	}
	if document.AuthorityRole == "generated_lookup" && document.Kind != "generated_lookup" {
		failures = append(failures, fmt.Sprintf("non-generated document must not use generated_lookup authority role: %s", document.DocumentID))
	}
	if document.AuthorityRole == "presentation_only" && document.Kind != "rendered_view" {
		failures = append(failures, fmt.Sprintf("non-rendered document must not use presentation_only authority role: %s", document.DocumentID))
	}
	if has(durableKinds, document.Kind) && document.LifecycleState == "current" && len(document.FreshnessCheckRefs) == 0 {
		failures = append(failures, fmt.Sprintf("current durable document must declare freshness check refs: %s", document.DocumentID))
	}
	if document.RoutingRole == "primary_router" && document.AuthorityRole != "navigation" {
		failures = append(failures, fmt.Sprintf("primary router must use navigation authority role: %s", document.DocumentID))
	}
	if document.Kind == "work_ledger" && document.AuthorityRole != "open_work_truth" {
		failures = append(failures, fmt.Sprintf("work ledger must use open_work_truth authority role: %s", document.DocumentID))
	}
	if len(document.ForbiddenPayloads) == 0 {
		failures = append(failures, fmt.Sprintf("document must declare forbidden payload boundaries: %s", document.DocumentID))
	}
	return failures
}

func documentLifecycleRuleResults(failures []string) []report.RuleResult {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{
			Key:   fmt.Sprintf("failure.%03d", index+1),
			Value: failure,
		})
	}
	status := "passed"
	if len(failures) > 0 {
		status = "failed"
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.document-lifecycle-boundary.authority-demotion",
			Status:      status,
			Message:     "temporary, archived, generated, routed, and durable documents must keep declared authority boundaries",
			Diagnostics: diagnostics,
		},
		{
			RuleID:      "proofkit.document-lifecycle-boundary.boundary",
			Status:      "passed",
			Message:     "documentation lifecycle facts are validated without reading document content",
			Diagnostics: []report.Diagnostic{},
		},
	}
}

func expectedPresentationAuthorityRole(kind string) string {
	if kind == "generated_lookup" {
		return "generated_lookup"
	}
	return "presentation_only"
}

func expectedPresentationRoutingRole(kind string) string {
	if kind == "generated_lookup" {
		return "lookup_projection"
	}
	return "presentation_view"
}

func countLifecycleState(documents []documentInput, state string) int {
	count := 0
	for _, document := range documents {
		if document.LifecycleState == state {
			count++
		}
	}
	return count
}

func countAuthorityRole(documents []documentInput, role string) int {
	count := 0
	for _, document := range documents {
		if document.AuthorityRole == role {
			count++
		}
	}
	return count
}

func countActiveAuthority(documents []documentInput) int {
	count := 0
	for _, document := range documents {
		if has(activeAuthorityRoles, document.AuthorityRole) {
			count++
		}
	}
	return count
}

func countTemporaryKinds(documents []documentInput) int {
	count := 0
	for _, document := range documents {
		if has(temporaryKinds, document.Kind) {
			count++
		}
	}
	return count
}

func has(values map[string]struct{}, value string) bool {
	_, ok := values[value]
	return ok
}
