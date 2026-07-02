package proofvocab

import "testing"

func TestObligationDecisionStateRankPreservesFailureSeverityOrder(t *testing.T) {
	if ObligationDecisionStateRank("invalid_producer") >= ObligationDecisionStateRank("satisfied") {
		t.Fatalf("invalid_producer must rank before satisfied")
	}
	if ObligationDecisionStateRank("unknown") != len(ObligationDecisionStates()) {
		t.Fatalf("unknown states must rank after admitted states")
	}
}

func TestVocabularyAccessorsReturnCopies(t *testing.T) {
	statuses := ReceiptStatuses()
	statuses[0] = "mutated"
	if ReceiptStatuses()[0] == "mutated" {
		t.Fatalf("ReceiptStatuses returned mutable owner slice")
	}
	statusSet := ReceiptStatusSet()
	delete(statusSet, "passed")
	if _, ok := ReceiptStatusSet()["passed"]; !ok {
		t.Fatalf("ReceiptStatusSet returned mutable owner set")
	}
	classes := MergeSatisfactionClasses()
	classes[0] = "mutated"
	if MergeSatisfactionClasses()[0] == "mutated" {
		t.Fatalf("MergeSatisfactionClasses returned mutable owner slice")
	}
	classSet := MergeSatisfactionClassSet()
	delete(classSet, "merge_satisfying")
	if _, ok := MergeSatisfactionClassSet()["merge_satisfying"]; !ok {
		t.Fatalf("MergeSatisfactionClassSet returned mutable owner set")
	}
	edgeClasses := SelectiveEdgeClasses()
	edgeClasses[0] = "mutated"
	if SelectiveEdgeClasses()[0] == "mutated" {
		t.Fatalf("SelectiveEdgeClasses returned mutable owner slice")
	}
	edgeClassSet := SelectiveEdgeClassSet()
	delete(edgeClassSet, "dynamic_or_unknown")
	if _, ok := SelectiveEdgeClassSet()["dynamic_or_unknown"]; !ok {
		t.Fatalf("SelectiveEdgeClassSet returned mutable owner set")
	}
	coverageStates := SelectiveEdgeCoverageStates()
	coverageStates[0] = "mutated"
	if SelectiveEdgeCoverageStates()[0] == "mutated" {
		t.Fatalf("SelectiveEdgeCoverageStates returned mutable owner slice")
	}
	coverageStateSet := SelectiveEdgeCoverageStateSet()
	delete(coverageStateSet, "uncovered")
	if _, ok := SelectiveEdgeCoverageStateSet()["uncovered"]; !ok {
		t.Fatalf("SelectiveEdgeCoverageStateSet returned mutable owner set")
	}
	obligationClasses := ObligationClasses()
	obligationClasses[0] = "mutated"
	if ObligationClasses()[0] == "mutated" {
		t.Fatalf("ObligationClasses returned mutable owner slice")
	}
	obligationClassSet := ObligationClassSet()
	delete(obligationClassSet, "blocking")
	if _, ok := ObligationClassSet()["blocking"]; !ok {
		t.Fatalf("ObligationClassSet returned mutable owner set")
	}
	decisionStates := ObligationDecisionStates()
	decisionStates[0] = "mutated"
	if ObligationDecisionStates()[0] == "mutated" {
		t.Fatalf("ObligationDecisionStates returned mutable owner slice")
	}
	decisionStateSet := ObligationDecisionStateSet()
	delete(decisionStateSet, "satisfied")
	if _, ok := ObligationDecisionStateSet()["satisfied"]; !ok {
		t.Fatalf("ObligationDecisionStateSet returned mutable owner set")
	}
}
