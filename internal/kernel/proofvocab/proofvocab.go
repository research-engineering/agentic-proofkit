package proofvocab

var receiptStatuses = []string{"blocked", "failed", "not_run", "passed"}

var mergeSatisfactionClasses = []string{"advisory", "merge_satisfying"}

var obligationClasses = []string{"advisory", "blocking", "deferred"}

var obligationDecisionStates = []string{
	"invalid_producer",
	"invalid_receipt",
	"stale_receipt",
	"failed",
	"missing_receipt",
	"blocked_missing_precondition",
	"unavailable_live",
	"unknown_scope",
	"deferred_admitted",
	"advisory_skipped",
	"not_applicable",
	"satisfied",
}

var selectiveEdgeClasses = []string{
	"command_environment_registry",
	"dynamic_or_unknown",
	"generated_source",
	"package_reverse_dependency",
	"public_export_api",
	"requirement_binding",
	"source_owner_mapping",
	"witness_selector",
	"workspace_script",
}

const (
	selectiveEdgeCoverageCoveredByFallback = "covered_by_declared_fallback"
	selectiveEdgeCoverageUncovered         = "uncovered"
)

var selectiveEdgeCoverageStates = []string{selectiveEdgeCoverageCoveredByFallback, selectiveEdgeCoverageUncovered}

func ReceiptStatuses() []string {
	return clone(receiptStatuses)
}

func ReceiptStatusSet() map[string]struct{} {
	return set(receiptStatuses)
}

func MergeSatisfactionClasses() []string {
	return clone(mergeSatisfactionClasses)
}

func MergeSatisfactionClassSet() map[string]struct{} {
	return set(mergeSatisfactionClasses)
}

func ObligationClasses() []string {
	return clone(obligationClasses)
}

func ObligationClassSet() map[string]struct{} {
	return set(obligationClasses)
}

func ObligationDecisionStates() []string {
	return clone(obligationDecisionStates)
}

func ObligationDecisionStateSet() map[string]struct{} {
	return set(obligationDecisionStates)
}

func ObligationDecisionStateRank(state string) int {
	for index, value := range obligationDecisionStates {
		if value == state {
			return index
		}
	}
	return len(obligationDecisionStates)
}

func SelectiveEdgeClasses() []string {
	return clone(selectiveEdgeClasses)
}

func SelectiveEdgeClassSet() map[string]struct{} {
	return set(selectiveEdgeClasses)
}

func SelectiveEdgeCoverageStates() []string {
	return clone(selectiveEdgeCoverageStates)
}

func SelectiveEdgeCoverageStateSet() map[string]struct{} {
	return set(selectiveEdgeCoverageStates)
}

func SelectiveEdgeCoverageCoveredByFallback() string {
	return selectiveEdgeCoverageCoveredByFallback
}

func SelectiveEdgeCoverageUncovered() string {
	return selectiveEdgeCoverageUncovered
}

func clone(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func set(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
