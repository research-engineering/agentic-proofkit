package migrationparityadmission

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.migration-parity-admission"

var equivalenceKinds = []string{
	"agent_envelope_projection",
	"command_ref_projection",
	"generated_view_projection",
	"receipt_shape_projection",
	"report_summary_projection",
	"requirement_binding_projection",
}
var equivalenceKindSet = toSet(equivalenceKinds)

var parityStatuses = []string{"matched", "mismatched", "not_comparable", "not_run"}
var parityStatusSet = toSet(parityStatuses)

var sourceOwnerKinds = []string{"local_doc", "local_manifest", "local_script", "local_test", "other"}
var sourceOwnerKindSet = toSet(sourceOwnerKinds)

var targetKinds = []string{"proofkit_input", "proofkit_profile", "proofkit_report", "proofkit_view"}
var targetKindSet = toSet(targetKinds)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var boundaryNonClaims = []string{
	"Migration parity admission does not approve old-owner deletion, migration exceptions, merge, release, rollout, or production readiness.",
	"Migration parity admission does not authenticate parity evidence.",
	"Migration parity admission does not compute digest values or proof freshness.",
	"Migration parity admission does not execute native commands or prove command result correctness.",
	"Migration parity admission does not prove semantic correctness of either legacy or Proofkit-owned infrastructure.",
}

type sourceProofOwner struct {
	OwnerID   string
	OwnerKind string
	Path      string
}

type targetRef struct {
	Path       string
	TargetID   string
	TargetKind string
}

type parityRecord struct {
	EquivalenceKind    string
	EvidenceID         string
	EvidenceRefs       []string
	LegacyDigest       string
	LegacySubjectRef   string
	NonClaims          []string
	ProofkitDigest     string
	ProofkitSubjectRef string
	Reason             string
	ReceiptRefs        []string
	SourceOwnerID      string
	Status             string
	TargetID           string
}

type parityDiagnostic struct {
	parityRecord
	Findings []string
}

type admittedEvidenceRef struct {
	EquivalenceKind string
	EvidenceID      string
	EvidenceRefs    []string
	ReceiptRefs     []string
	SourceOwnerID   string
	TargetID        string
}

type admittedInput struct {
	NonClaims          []string
	ParityRecords      []parityRecord
	ParitySetID        string
	SourceProofOwners  []sourceProofOwner
	TargetProofkitRefs []targetRef
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	sourceOwnerIDs := map[string]struct{}{}
	for _, owner := range input.SourceProofOwners {
		sourceOwnerIDs[owner.OwnerID] = struct{}{}
	}
	targetIDs := map[string]struct{}{}
	for _, target := range input.TargetProofkitRefs {
		targetIDs[target.TargetID] = struct{}{}
	}
	diagnostics := make([]parityDiagnostic, 0, len(input.ParityRecords))
	for _, record := range input.ParityRecords {
		diagnostics = append(diagnostics, evaluateParityRecord(record, sourceOwnerIDs, targetIDs))
	}
	sort.Slice(diagnostics, func(left int, right int) bool {
		return diagnostics[left].EvidenceID < diagnostics[right].EvidenceID
	})
	failures := []string{}
	admittedRefs := []admittedEvidenceRef{}
	for _, diagnostic := range diagnostics {
		failures = append(failures, diagnostic.Findings...)
		if len(diagnostic.Findings) == 0 {
			admittedRefs = append(admittedRefs, admittedEvidenceRef{
				EquivalenceKind: diagnostic.EquivalenceKind,
				EvidenceID:      diagnostic.EvidenceID,
				EvidenceRefs:    diagnostic.EvidenceRefs,
				ReceiptRefs:     diagnostic.ReceiptRefs,
				SourceOwnerID:   diagnostic.SourceOwnerID,
				TargetID:        diagnostic.TargetID,
			})
		}
	}
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.ParitySetID,
		State:         state,
		Summary: map[string]any{
			"admittedParityEvidenceCount": len(admittedRefs),
			"failureCount":                len(failures),
			"matchedCount":                countByStatus(diagnostics, "matched"),
			"mismatchedCount":             countByStatus(diagnostics, "mismatched"),
			"notComparableCount":          countByStatus(diagnostics, "not_comparable"),
			"notRunCount":                 countByStatus(diagnostics, "not_run"),
			"parityRecordCount":           len(diagnostics),
			"sourceProofOwnerCount":       len(input.SourceProofOwners),
			"targetProofkitRefCount":      len(input.TargetProofkitRefs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "admittedParityEvidenceRefs", Value: admittedEvidenceDiagnostics(admittedRefs)},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "migrationParity", Value: parityDiagnostics(diagnostics)},
		},
		RuleResults: ruleResults(diagnostics),
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
		return admittedInput{}, fmt.Errorf("migration parity input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "parityRecords", "paritySetId", "schemaVersion", "sourceProofOwners", "targetProofkitRefs"}, "migration parity input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("migration parity schemaVersion must be 1")
	}
	paritySetID, err := admit.RuleID(record["paritySetId"], "migration parity paritySetId")
	if err != nil {
		return admittedInput{}, err
	}
	sourceOwners, err := sourceProofOwners(record["sourceProofOwners"])
	if err != nil {
		return admittedInput{}, err
	}
	targetRefs, err := targetRefs(record["targetProofkitRefs"])
	if err != nil {
		return admittedInput{}, err
	}
	parityRecords, err := parityRecords(record["parityRecords"])
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "migration parity nonClaims", true)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		NonClaims:          nonClaims,
		ParityRecords:      parityRecords,
		ParitySetID:        paritySetID,
		SourceProofOwners:  sourceOwners,
		TargetProofkitRefs: targetRefs,
	}, nil
}

func sourceProofOwners(raw any) ([]sourceProofOwner, error) {
	records, err := nonEmptyRecords(raw, "migration parity sourceProofOwners")
	if err != nil {
		return nil, err
	}
	result := make([]sourceProofOwner, 0, len(records))
	for _, record := range records {
		item, err := admitSourceProofOwner(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].OwnerID < result[right].OwnerID
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.OwnerID)
	}
	if err := preserveSortedUnique(ids, "migration parity source owner ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitSourceProofOwner(record map[string]any) (sourceProofOwner, error) {
	if err := admit.KnownKeys(record, []string{"ownerId", "ownerKind", "path"}, "migration parity source proof owner"); err != nil {
		return sourceProofOwner{}, err
	}
	ownerID, err := admit.RuleID(record["ownerId"], "migration parity source ownerId")
	if err != nil {
		return sourceProofOwner{}, err
	}
	path, err := pathField(record["path"], "migration parity source owner path")
	if err != nil {
		return sourceProofOwner{}, err
	}
	ownerKind, err := enum(record["ownerKind"], sourceOwnerKindSet, sourceOwnerKinds, "migration parity source ownerKind")
	if err != nil {
		return sourceProofOwner{}, err
	}
	return sourceProofOwner{OwnerID: ownerID, OwnerKind: ownerKind, Path: path}, nil
}

func targetRefs(raw any) ([]targetRef, error) {
	records, err := nonEmptyRecords(raw, "migration parity targetProofkitRefs")
	if err != nil {
		return nil, err
	}
	result := make([]targetRef, 0, len(records))
	for _, record := range records {
		item, err := admitTargetRef(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].TargetID < result[right].TargetID
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.TargetID)
	}
	if err := preserveSortedUnique(ids, "migration parity target ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitTargetRef(record map[string]any) (targetRef, error) {
	if err := admit.KnownKeys(record, []string{"path", "targetId", "targetKind"}, "migration parity target ref"); err != nil {
		return targetRef{}, err
	}
	targetID, err := admit.RuleID(record["targetId"], "migration parity targetId")
	if err != nil {
		return targetRef{}, err
	}
	path, err := pathField(record["path"], "migration parity target path")
	if err != nil {
		return targetRef{}, err
	}
	targetKind, err := enum(record["targetKind"], targetKindSet, targetKinds, "migration parity targetKind")
	if err != nil {
		return targetRef{}, err
	}
	return targetRef{Path: path, TargetID: targetID, TargetKind: targetKind}, nil
}

func parityRecords(raw any) ([]parityRecord, error) {
	records, err := nonEmptyRecords(raw, "migration parity parityRecords")
	if err != nil {
		return nil, err
	}
	result := make([]parityRecord, 0, len(records))
	for _, record := range records {
		item, err := admitParityRecord(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].EvidenceID < result[right].EvidenceID
	})
	ids := make([]string, 0, len(result))
	for _, item := range result {
		ids = append(ids, item.EvidenceID)
	}
	if err := preserveSortedUnique(ids, "migration parity evidence ids", false); err != nil {
		return nil, err
	}
	return result, nil
}

func admitParityRecord(record map[string]any) (parityRecord, error) {
	if err := admit.KnownKeys(record, []string{"equivalenceKind", "evidenceId", "evidenceRefs", "legacyDigest", "legacySubjectRef", "nonClaims", "proofkitDigest", "proofkitSubjectRef", "reason", "receiptRefs", "sourceOwnerId", "status", "targetId"}, "migration parity record"); err != nil {
		return parityRecord{}, err
	}
	evidenceID, err := admit.RuleID(record["evidenceId"], "migration parity evidenceId")
	if err != nil {
		return parityRecord{}, err
	}
	sourceOwnerID, err := admit.RuleID(record["sourceOwnerId"], "migration parity sourceOwnerId")
	if err != nil {
		return parityRecord{}, err
	}
	targetID, err := admit.RuleID(record["targetId"], "migration parity targetId")
	if err != nil {
		return parityRecord{}, err
	}
	equivalenceKind, err := enum(record["equivalenceKind"], equivalenceKindSet, equivalenceKinds, "migration parity equivalenceKind")
	if err != nil {
		return parityRecord{}, err
	}
	legacySubjectRef, err := text(record["legacySubjectRef"], "migration parity "+evidenceID+" legacySubjectRef")
	if err != nil {
		return parityRecord{}, err
	}
	proofkitSubjectRef, err := text(record["proofkitSubjectRef"], "migration parity "+evidenceID+" proofkitSubjectRef")
	if err != nil {
		return parityRecord{}, err
	}
	legacyDigest, err := digest(record["legacyDigest"], "migration parity "+evidenceID+" legacyDigest")
	if err != nil {
		return parityRecord{}, err
	}
	proofkitDigest, err := digest(record["proofkitDigest"], "migration parity "+evidenceID+" proofkitDigest")
	if err != nil {
		return parityRecord{}, err
	}
	status, err := enum(record["status"], parityStatusSet, parityStatuses, "migration parity "+evidenceID+" status")
	if err != nil {
		return parityRecord{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], "migration parity "+evidenceID+" evidenceRefs", false)
	if err != nil {
		return parityRecord{}, err
	}
	receiptRefs, err := sortedRuleIDs(record["receiptRefs"], "migration parity "+evidenceID+" receiptRefs", true)
	if err != nil {
		return parityRecord{}, err
	}
	reason, err := text(record["reason"], "migration parity "+evidenceID+" reason")
	if err != nil {
		return parityRecord{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "migration parity "+evidenceID+" nonClaims", false)
	if err != nil {
		return parityRecord{}, err
	}
	return parityRecord{
		EquivalenceKind:    equivalenceKind,
		EvidenceID:         evidenceID,
		EvidenceRefs:       evidenceRefs,
		LegacyDigest:       legacyDigest,
		LegacySubjectRef:   legacySubjectRef,
		NonClaims:          nonClaims,
		ProofkitDigest:     proofkitDigest,
		ProofkitSubjectRef: proofkitSubjectRef,
		Reason:             reason,
		ReceiptRefs:        receiptRefs,
		SourceOwnerID:      sourceOwnerID,
		Status:             status,
		TargetID:           targetID,
	}, nil
}

func evaluateParityRecord(record parityRecord, sourceOwnerIDs map[string]struct{}, targetIDs map[string]struct{}) parityDiagnostic {
	findings := []string{}
	if _, ok := sourceOwnerIDs[record.SourceOwnerID]; !ok {
		findings = append(findings, fmt.Sprintf("migration parity record %s references unknown source owner: %s", record.EvidenceID, record.SourceOwnerID))
	}
	if _, ok := targetIDs[record.TargetID]; !ok {
		findings = append(findings, fmt.Sprintf("migration parity record %s references unknown target: %s", record.EvidenceID, record.TargetID))
	}
	if record.Status == "matched" && record.LegacyDigest != record.ProofkitDigest {
		findings = append(findings, fmt.Sprintf("migration parity record %s is matched but digests differ", record.EvidenceID))
	}
	if record.Status == "mismatched" && record.LegacyDigest == record.ProofkitDigest {
		findings = append(findings, fmt.Sprintf("migration parity record %s is mismatched but digests are equal", record.EvidenceID))
	}
	if record.Status != "matched" {
		findings = append(findings, fmt.Sprintf("migration parity record %s is not admitted: %s", record.EvidenceID, record.Status))
	}
	sort.Strings(findings)
	return parityDiagnostic{parityRecord: record, Findings: findings}
}

func parityDiagnostics(diagnostics []parityDiagnostic) []any {
	result := make([]any, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, map[string]any{
			"equivalenceKind":    diagnostic.EquivalenceKind,
			"evidenceId":         diagnostic.EvidenceID,
			"evidenceRefs":       admit.StringSliceToAny(diagnostic.EvidenceRefs),
			"findings":           admit.StringSliceToAny(diagnostic.Findings),
			"legacyDigest":       diagnostic.LegacyDigest,
			"legacySubjectRef":   diagnostic.LegacySubjectRef,
			"proofkitDigest":     diagnostic.ProofkitDigest,
			"proofkitSubjectRef": diagnostic.ProofkitSubjectRef,
			"reason":             diagnostic.Reason,
			"receiptRefs":        admit.StringSliceToAny(diagnostic.ReceiptRefs),
			"sourceOwnerId":      diagnostic.SourceOwnerID,
			"status":             diagnostic.Status,
			"targetId":           diagnostic.TargetID,
		})
	}
	return result
}

func admittedEvidenceDiagnostics(refs []admittedEvidenceRef) []any {
	result := make([]any, 0, len(refs))
	for _, ref := range refs {
		result = append(result, map[string]any{
			"equivalenceKind": ref.EquivalenceKind,
			"evidenceId":      ref.EvidenceID,
			"evidenceRefs":    admit.StringSliceToAny(ref.EvidenceRefs),
			"receiptRefs":     admit.StringSliceToAny(ref.ReceiptRefs),
			"sourceOwnerId":   ref.SourceOwnerID,
			"targetId":        ref.TargetID,
		})
	}
	return result
}

func ruleResults(diagnostics []parityDiagnostic) []report.RuleResult {
	results := make([]report.RuleResult, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		status := "passed"
		message := "migration parity evidence record is admitted"
		ruleDiagnostics := []report.Diagnostic{}
		if len(diagnostic.Findings) > 0 {
			status = "failed"
			message = "migration parity evidence record is not admitted"
			ruleDiagnostics = []report.Diagnostic{{Key: "findings", Value: admit.StringSliceToAny(diagnostic.Findings)}}
		}
		results = append(results, report.RuleResult{
			RuleID:      "proofkit.migration-parity-admission.record." + diagnostic.EvidenceID,
			Status:      status,
			Message:     message,
			Diagnostics: ruleDiagnostics,
		})
	}
	return results
}

func nonEmptyRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must contain objects", context)
		}
		result = append(result, record)
	}
	return result, nil
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.RuleID)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, text)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, pathField)
}

func sortedMapped(raw any, context string, allowEmpty bool, mapper func(any, string) (string, error)) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := mapper(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Strings(result)
	if err := preserveSortedUnique(result, context, allowEmpty); err != nil {
		return nil, err
	}
	return result, nil
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be non-empty", context)
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func pathField(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return value, nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	return value, nil
}

func countByStatus(diagnostics []parityDiagnostic, status string) int {
	count := 0
	for _, diagnostic := range diagnostics {
		if diagnostic.Status == status {
			count++
		}
	}
	return count
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func join(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += ", " + value
	}
	return result
}
