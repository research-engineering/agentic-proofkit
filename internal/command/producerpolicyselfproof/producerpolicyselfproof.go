package producerpolicyselfproof

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.producer-policy-self-proof"

var changeKinds = []string{"add_producer", "expand_environment_class", "expand_receipt_kind", "promote_to_merge_satisfying"}
var changeKindSet = toSet(changeKinds)

var admissionLevels = proofvocab.MergeSatisfactionClasses()
var admissionLevelSet = proofvocab.MergeSatisfactionClassSet()

var receiptStatuses = proofvocab.ReceiptStatuses()
var receiptStatusSet = proofvocab.ReceiptStatusSet()

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var boundaryNonClaims = []string{
	"Producer policy self-proof guard does not approve merge, release, rollout, or migration exceptions.",
	"Producer policy self-proof guard does not authenticate producers.",
	"Producer policy self-proof guard does not compute receipt freshness.",
	"Producer policy self-proof guard does not execute commands or inspect CI state.",
	"Producer policy self-proof guard does not verify policy digest provenance.",
}

type admissionChange struct {
	ArtifactRetentionRuleRef string
	ChangeID                 string
	ChangeKind               string
	EnvironmentClass         string
	EvidenceRefs             []string
	FromAdmissionLevel       *string
	NonClaim                 string
	NonClaimRefs             []string
	ProducerClass            string
	ProducerID               string
	ProofClass               string
	ProvenanceRuleRef        string
	ReceiptKind              string
	ToAdmissionLevel         string
}

type receiptRef struct {
	ArtifactRetentionRuleRef string
	EnvironmentClass         string
	EvidenceRef              string
	NonClaim                 string
	NonClaimRefs             []string
	ProducerAdmissionClass   string
	ProducerClass            string
	ProducerID               string
	ProofClass               string
	ProofReceiptDigest       string
	ProofReceiptRef          string
	ProvenanceRuleRef        string
	ReceiptID                string
	ReceiptKind              string
	ReceiptStatus            string
	SatisfiesMergeObligation bool
	UsedForPolicyChangeID    string
}

type admittedInput struct {
	AdmissionChanges           []admissionChange
	BaselinePolicyDigest       string
	GuardID                    string
	MergeObligationReceiptRefs []receiptRef
	NonClaimRefs               []string
	NonClaims                  []string
	PolicyChangeDigest         string
	PolicyChangeID             string
	PolicyID                   string
	PolicyOwner                string
	PolicySurfaceRefs          []string
	ProposedPolicyDigest       string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	newlyMergeSatisfyingTupleKeys := map[string]struct{}{}
	for _, change := range input.AdmissionChanges {
		if change.ToAdmissionLevel == "merge_satisfying" {
			newlyMergeSatisfyingTupleKeys[admissionTupleKey(change)] = struct{}{}
		}
	}
	selfProofReceipts := []receiptRef{}
	for _, receipt := range input.MergeObligationReceiptRefs {
		if !receipt.SatisfiesMergeObligation {
			continue
		}
		if _, ok := newlyMergeSatisfyingTupleKeys[receiptTupleKey(receipt)]; ok {
			selfProofReceipts = append(selfProofReceipts, receipt)
		}
	}
	failures := selfProofFailures(input, newlyMergeSatisfyingTupleKeys)
	sort.Strings(failures)
	policyChanged := input.BaselinePolicyDigest != input.ProposedPolicyDigest
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.GuardID,
		State:         state,
		Summary: map[string]any{
			"admissionChangeCount":                len(input.AdmissionChanges),
			"declaredMergeObligationReceiptCount": countMergeObligationReceipts(input.MergeObligationReceiptRefs),
			"failureCount":                        len(failures),
			"newlyMergeSatisfyingTupleCount":      len(newlyMergeSatisfyingTupleKeys),
			"policyChanged":                       policyChanged,
			"selfProofReceiptCount":               len(selfProofReceipts),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "policy", Value: map[string]any{
				"baselinePolicyDigest": input.BaselinePolicyDigest,
				"nonClaimRefs":         admit.StringSliceToAny(input.NonClaimRefs),
				"policyChangeDigest":   input.PolicyChangeDigest,
				"policyChangeId":       input.PolicyChangeID,
				"policyId":             input.PolicyID,
				"policyOwner":          input.PolicyOwner,
				"policySurfaceRefs":    admit.StringSliceToAny(input.PolicySurfaceRefs),
				"proposedPolicyDigest": input.ProposedPolicyDigest,
			}},
			{Key: "selfProofReceipts", Value: selfProofReceiptDiagnostics(selfProofReceipts)},
		},
		RuleResults: ruleResults(failures),
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
		return admittedInput{}, fmt.Errorf("producer policy self-proof input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"admissionChanges", "baselinePolicyDigest", "guardId", "mergeObligationReceiptRefs", "nonClaimRefs", "nonClaims", "policyChangeDigest", "policyChangeId", "policyId", "policyOwner", "policySurfaceRefs", "proposedPolicyDigest", "schemaVersion"}, "producer policy self-proof input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("producer policy self-proof schemaVersion must be 1")
	}
	policyChangeID, err := admit.RuleID(record["policyChangeId"], "producer policy self-proof policyChangeId")
	if err != nil {
		return admittedInput{}, err
	}
	admissionChanges, err := admissionChanges(record["admissionChanges"])
	if err != nil {
		return admittedInput{}, err
	}
	receiptRefs, err := receiptRefs(record["mergeObligationReceiptRefs"], policyChangeID)
	if err != nil {
		return admittedInput{}, err
	}
	if err := assertUnique(admissionChangeIDs(admissionChanges), "producer policy self-proof admission change ids"); err != nil {
		return admittedInput{}, err
	}
	if err := assertUnique(receiptIDs(receiptRefs), "producer policy self-proof receipt ids"); err != nil {
		return admittedInput{}, err
	}
	guardID, err := admit.RuleID(record["guardId"], "producer policy self-proof guardId")
	if err != nil {
		return admittedInput{}, err
	}
	policyID, err := admit.RuleID(record["policyId"], "producer policy self-proof policyId")
	if err != nil {
		return admittedInput{}, err
	}
	policySurfaceRefs, err := sortedPaths(record["policySurfaceRefs"], "producer policy self-proof policySurfaceRefs", false)
	if err != nil {
		return admittedInput{}, err
	}
	policyOwner, err := admit.NonEmptyText(record["policyOwner"], "producer policy self-proof policyOwner")
	if err != nil {
		return admittedInput{}, err
	}
	baselinePolicyDigest, err := digest(record["baselinePolicyDigest"], "producer policy self-proof baselinePolicyDigest")
	if err != nil {
		return admittedInput{}, err
	}
	proposedPolicyDigest, err := digest(record["proposedPolicyDigest"], "producer policy self-proof proposedPolicyDigest")
	if err != nil {
		return admittedInput{}, err
	}
	policyChangeDigest, err := digest(record["policyChangeDigest"], "producer policy self-proof policyChangeDigest")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaimRefs, err := sortedRuleIDs(record["nonClaimRefs"], "producer policy self-proof nonClaimRefs", true)
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "producer policy self-proof nonClaims", true)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		AdmissionChanges:           admissionChanges,
		BaselinePolicyDigest:       baselinePolicyDigest,
		GuardID:                    guardID,
		MergeObligationReceiptRefs: receiptRefs,
		NonClaimRefs:               nonClaimRefs,
		NonClaims:                  nonClaims,
		PolicyChangeDigest:         policyChangeDigest,
		PolicyChangeID:             policyChangeID,
		PolicyID:                   policyID,
		PolicyOwner:                policyOwner,
		PolicySurfaceRefs:          policySurfaceRefs,
		ProposedPolicyDigest:       proposedPolicyDigest,
	}, nil
}

func admissionChanges(raw any) ([]admissionChange, error) {
	records, err := arrayOfRecords(raw, "producer policy self-proof admissionChanges")
	if err != nil {
		return nil, err
	}
	result := make([]admissionChange, 0, len(records))
	for _, record := range records {
		item, err := admitAdmissionChange(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ChangeID < result[right].ChangeID
	})
	return result, nil
}

func admitAdmissionChange(record map[string]any) (admissionChange, error) {
	if err := admit.KnownKeys(record, []string{"artifactRetentionRuleRef", "changeId", "changeKind", "environmentClass", "evidenceRefs", "fromAdmissionLevel", "nonClaim", "nonClaimRefs", "producerClass", "producerId", "proofClass", "provenanceRuleRef", "receiptKind", "toAdmissionLevel"}, "producer policy self-proof admission change"); err != nil {
		return admissionChange{}, err
	}
	changeID, err := admit.RuleID(record["changeId"], "producer policy self-proof admissionChange.changeId")
	if err != nil {
		return admissionChange{}, err
	}
	changeKind, err := enum(record["changeKind"], changeKindSet, changeKinds, "producer policy self-proof admissionChange.changeKind")
	if err != nil {
		return admissionChange{}, err
	}
	producerID, err := admit.RuleID(record["producerId"], "producer policy self-proof admissionChange.producerId")
	if err != nil {
		return admissionChange{}, err
	}
	producerClass, err := admit.RuleID(record["producerClass"], "producer policy self-proof admissionChange.producerClass")
	if err != nil {
		return admissionChange{}, err
	}
	proofClass, err := admit.RuleID(record["proofClass"], "producer policy self-proof admissionChange.proofClass")
	if err != nil {
		return admissionChange{}, err
	}
	receiptKind, err := admit.RuleID(record["receiptKind"], "producer policy self-proof admissionChange.receiptKind")
	if err != nil {
		return admissionChange{}, err
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], "producer policy self-proof admissionChange.environmentClass")
	if err != nil {
		return admissionChange{}, err
	}
	provenanceRuleRef, err := pathField(record["provenanceRuleRef"], "producer policy self-proof admissionChange.provenanceRuleRef")
	if err != nil {
		return admissionChange{}, err
	}
	artifactRetentionRuleRef, err := pathField(record["artifactRetentionRuleRef"], "producer policy self-proof admissionChange.artifactRetentionRuleRef")
	if err != nil {
		return admissionChange{}, err
	}
	fromAdmissionLevel, err := optionalAdmissionLevel(record, "fromAdmissionLevel", "producer policy self-proof admissionChange.fromAdmissionLevel")
	if err != nil {
		return admissionChange{}, err
	}
	toAdmissionLevel, err := enum(record["toAdmissionLevel"], admissionLevelSet, admissionLevels, "producer policy self-proof admissionChange.toAdmissionLevel")
	if err != nil {
		return admissionChange{}, err
	}
	evidenceRefs, err := sortedPaths(record["evidenceRefs"], "producer policy self-proof admissionChange.evidenceRefs", false)
	if err != nil {
		return admissionChange{}, err
	}
	nonClaimRefs, err := sortedRuleIDs(record["nonClaimRefs"], "producer policy self-proof admissionChange.nonClaimRefs", true)
	if err != nil {
		return admissionChange{}, err
	}
	nonClaim, err := admit.NonEmptyText(record["nonClaim"], "producer policy self-proof admissionChange.nonClaim")
	if err != nil {
		return admissionChange{}, err
	}
	return admissionChange{
		ArtifactRetentionRuleRef: artifactRetentionRuleRef,
		ChangeID:                 changeID,
		ChangeKind:               changeKind,
		EnvironmentClass:         environmentClass,
		EvidenceRefs:             evidenceRefs,
		FromAdmissionLevel:       fromAdmissionLevel,
		NonClaim:                 nonClaim,
		NonClaimRefs:             nonClaimRefs,
		ProducerClass:            producerClass,
		ProducerID:               producerID,
		ProofClass:               proofClass,
		ProvenanceRuleRef:        provenanceRuleRef,
		ReceiptKind:              receiptKind,
		ToAdmissionLevel:         toAdmissionLevel,
	}, nil
}

func receiptRefs(raw any, policyChangeID string) ([]receiptRef, error) {
	records, err := arrayOfRecords(raw, "producer policy self-proof mergeObligationReceiptRefs")
	if err != nil {
		return nil, err
	}
	result := make([]receiptRef, 0, len(records))
	for _, record := range records {
		item, err := admitReceiptRef(record, policyChangeID)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ReceiptID < result[right].ReceiptID
	})
	return result, nil
}

func admitReceiptRef(record map[string]any, policyChangeID string) (receiptRef, error) {
	if err := admit.KnownKeys(record, []string{"artifactRetentionRuleRef", "environmentClass", "evidenceRef", "nonClaim", "nonClaimRefs", "producerAdmissionClass", "producerClass", "producerId", "proofClass", "proofReceiptDigest", "proofReceiptRef", "provenanceRuleRef", "receiptId", "receiptKind", "receiptStatus", "satisfiesMergeObligation", "usedForPolicyChangeId"}, "producer policy self-proof receipt ref"); err != nil {
		return receiptRef{}, err
	}
	usedForPolicyChangeID, err := admit.RuleID(record["usedForPolicyChangeId"], "producer policy self-proof receipt.usedForPolicyChangeId")
	if err != nil {
		return receiptRef{}, err
	}
	if usedForPolicyChangeID != policyChangeID {
		return receiptRef{}, fmt.Errorf("producer policy self-proof receipt.usedForPolicyChangeId must match policyChangeId")
	}
	satisfiesMergeObligation, err := admit.Bool(record["satisfiesMergeObligation"], "producer policy self-proof receipt.satisfiesMergeObligation")
	if err != nil {
		return receiptRef{}, err
	}
	receiptID, err := admit.RuleID(record["receiptId"], "producer policy self-proof receipt.receiptId")
	if err != nil {
		return receiptRef{}, err
	}
	producerID, err := admit.RuleID(record["producerId"], "producer policy self-proof receipt.producerId")
	if err != nil {
		return receiptRef{}, err
	}
	producerClass, err := admit.RuleID(record["producerClass"], "producer policy self-proof receipt.producerClass")
	if err != nil {
		return receiptRef{}, err
	}
	proofClass, err := admit.RuleID(record["proofClass"], "producer policy self-proof receipt.proofClass")
	if err != nil {
		return receiptRef{}, err
	}
	receiptKind, err := admit.RuleID(record["receiptKind"], "producer policy self-proof receipt.receiptKind")
	if err != nil {
		return receiptRef{}, err
	}
	environmentClass, err := admit.RuleID(record["environmentClass"], "producer policy self-proof receipt.environmentClass")
	if err != nil {
		return receiptRef{}, err
	}
	provenanceRuleRef, err := pathField(record["provenanceRuleRef"], "producer policy self-proof receipt.provenanceRuleRef")
	if err != nil {
		return receiptRef{}, err
	}
	artifactRetentionRuleRef, err := pathField(record["artifactRetentionRuleRef"], "producer policy self-proof receipt.artifactRetentionRuleRef")
	if err != nil {
		return receiptRef{}, err
	}
	producerAdmissionClass, err := enum(record["producerAdmissionClass"], admissionLevelSet, admissionLevels, "producer policy self-proof receipt.producerAdmissionClass")
	if err != nil {
		return receiptRef{}, err
	}
	receiptStatus, err := enum(record["receiptStatus"], receiptStatusSet, receiptStatuses, "producer policy self-proof receipt.receiptStatus")
	if err != nil {
		return receiptRef{}, err
	}
	proofReceiptRef, err := pathField(record["proofReceiptRef"], "producer policy self-proof receipt.proofReceiptRef")
	if err != nil {
		return receiptRef{}, err
	}
	proofReceiptDigest, err := digest(record["proofReceiptDigest"], "producer policy self-proof receipt.proofReceiptDigest")
	if err != nil {
		return receiptRef{}, err
	}
	evidenceRef, err := pathField(record["evidenceRef"], "producer policy self-proof receipt.evidenceRef")
	if err != nil {
		return receiptRef{}, err
	}
	nonClaimRefs, err := sortedRuleIDs(record["nonClaimRefs"], "producer policy self-proof receipt.nonClaimRefs", true)
	if err != nil {
		return receiptRef{}, err
	}
	nonClaim, err := admit.NonEmptyText(record["nonClaim"], "producer policy self-proof receipt.nonClaim")
	if err != nil {
		return receiptRef{}, err
	}
	return receiptRef{
		ArtifactRetentionRuleRef: artifactRetentionRuleRef,
		EnvironmentClass:         environmentClass,
		EvidenceRef:              evidenceRef,
		NonClaim:                 nonClaim,
		NonClaimRefs:             nonClaimRefs,
		ProducerAdmissionClass:   producerAdmissionClass,
		ProducerClass:            producerClass,
		ProducerID:               producerID,
		ProofClass:               proofClass,
		ProofReceiptDigest:       proofReceiptDigest,
		ProofReceiptRef:          proofReceiptRef,
		ProvenanceRuleRef:        provenanceRuleRef,
		ReceiptID:                receiptID,
		ReceiptKind:              receiptKind,
		ReceiptStatus:            receiptStatus,
		SatisfiesMergeObligation: satisfiesMergeObligation,
		UsedForPolicyChangeID:    usedForPolicyChangeID,
	}, nil
}

func selfProofFailures(input admittedInput, newlyMergeSatisfyingTupleKeys map[string]struct{}) []string {
	failures := []string{}
	if input.BaselinePolicyDigest == input.ProposedPolicyDigest && len(input.AdmissionChanges) > 0 {
		failures = append(failures, "unchanged producer policy declares admission changes")
	}
	for _, change := range input.AdmissionChanges {
		if change.ChangeKind == "add_producer" && change.FromAdmissionLevel != nil {
			failures = append(failures, fmt.Sprintf("admission change %s add_producer must start without an admission level", change.ChangeID))
		}
		if change.ChangeKind == "promote_to_merge_satisfying" && change.ToAdmissionLevel != "merge_satisfying" {
			failures = append(failures, fmt.Sprintf("admission change %s promotion does not target merge_satisfying", change.ChangeID))
		}
		if change.ChangeKind == "promote_to_merge_satisfying" && change.FromAdmissionLevel != nil && *change.FromAdmissionLevel == change.ToAdmissionLevel {
			failures = append(failures, fmt.Sprintf("admission change %s does not change admission level", change.ChangeID))
		}
	}
	for _, receipt := range input.MergeObligationReceiptRefs {
		if !receipt.SatisfiesMergeObligation {
			continue
		}
		if receipt.ReceiptStatus != "passed" {
			failures = append(failures, fmt.Sprintf("merge-obligation receipt %s is not passed", receipt.ReceiptID))
		}
		if receipt.ProducerAdmissionClass != "merge_satisfying" {
			failures = append(failures, fmt.Sprintf("merge-obligation receipt %s does not use a merge_satisfying producer class", receipt.ReceiptID))
		}
		key := receiptTupleKey(receipt)
		if _, ok := newlyMergeSatisfyingTupleKeys[key]; ok {
			failures = append(failures, fmt.Sprintf("merge-obligation receipt %s uses newly admitted producer tuple: %s", receipt.ReceiptID, key))
		}
	}
	return failures
}

func ruleResults(failures []string) []report.RuleResult {
	return []report.RuleResult{
		{
			RuleID:      "proofkit.producer-policy-self-proof.boundary",
			Status:      "passed",
			Message:     "proofkit validates caller-provided producer-policy self-proof facts without authenticating producers or approving merge",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.producer-policy-self-proof.receipts",
			Status:      statusFailedIf(len(failures) > 0),
			Message:     "merge-obligation receipt refs must not use producer tuples newly admitted by the same producer-policy change",
			Diagnostics: failureDiagnostics(failures),
		},
	}
}

func selfProofReceiptDiagnostics(receipts []receiptRef) []any {
	result := make([]any, 0, len(receipts))
	for _, receipt := range receipts {
		result = append(result, map[string]any{
			"artifactRetentionRuleRef": receipt.ArtifactRetentionRuleRef,
			"environmentClass":         receipt.EnvironmentClass,
			"nonClaimRefs":             admit.StringSliceToAny(receipt.NonClaimRefs),
			"producerClass":            receipt.ProducerClass,
			"producerId":               receipt.ProducerID,
			"proofClass":               receipt.ProofClass,
			"proofReceiptDigest":       receipt.ProofReceiptDigest,
			"proofReceiptRef":          receipt.ProofReceiptRef,
			"provenanceRuleRef":        receipt.ProvenanceRuleRef,
			"receiptId":                receipt.ReceiptID,
			"receiptKind":              receipt.ReceiptKind,
		})
	}
	return result
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: failure})
	}
	return diagnostics
}

func admissionTupleKey(change admissionChange) string {
	return join([]string{
		change.ProducerID,
		change.ProducerClass,
		change.ProofClass,
		change.ReceiptKind,
		change.EnvironmentClass,
		change.ProvenanceRuleRef,
		change.ArtifactRetentionRuleRef,
		change.ToAdmissionLevel,
	}, "|")
}

func receiptTupleKey(receipt receiptRef) string {
	return join([]string{
		receipt.ProducerID,
		receipt.ProducerClass,
		receipt.ProofClass,
		receipt.ReceiptKind,
		receipt.EnvironmentClass,
		receipt.ProvenanceRuleRef,
		receipt.ArtifactRetentionRuleRef,
		receipt.ProducerAdmissionClass,
	}, "|")
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.RuleID)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.NonEmptyText)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, func(value any, itemContext string) (string, error) {
		return pathField(value, itemContext)
	})
}

func sortedMapped(raw any, context string, allowEmpty bool, mapper func(any, string) (string, error)) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := mapper(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return preserveSortedUnique(result, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := range values {
		if values[index] != sorted[index] || (index > 0 && values[index-1] == values[index]) {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func arrayOfRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		result = append(result, record)
	}
	return result, nil
}

func optionalAdmissionLevel(record map[string]any, key string, context string) (*string, error) {
	raw, ok := record[key]
	if !ok {
		return nil, fmt.Errorf("%s must be one of: %s", context, join(admissionLevels, ", "))
	}
	if raw == nil {
		return nil, nil
	}
	value, err := enum(raw, admissionLevelSet, admissionLevels, context)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return value, nil
}

func pathField(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func assertUnique(values []string, context string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s must be unique", context)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func admissionChangeIDs(changes []admissionChange) []string {
	result := make([]string, 0, len(changes))
	for _, change := range changes {
		result = append(result, change.ChangeID)
	}
	return result
}

func receiptIDs(receipts []receiptRef) []string {
	result := make([]string, 0, len(receipts))
	for _, receipt := range receipts {
		result = append(result, receipt.ReceiptID)
	}
	return result
}

func countMergeObligationReceipts(receipts []receiptRef) int {
	count := 0
	for _, receipt := range receipts {
		if receipt.SatisfiesMergeObligation {
			count++
		}
	}
	return count
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered, ", "))
	}
	return value, nil
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func join(values []string, separator string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += separator + value
	}
	return result
}
