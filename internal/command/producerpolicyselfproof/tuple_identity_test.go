package producerpolicyselfproof

import "testing"

func TestProducerTupleIdentityKeepsAllEightCoordinates(t *testing.T) {
	change := admissionChange{ProducerID: "producer", ProducerClass: "class", ProofClass: "proof", ReceiptKind: "receipt", EnvironmentClass: "environment", ProvenanceRuleRef: "docs/provenance", ArtifactRetentionRuleRef: "docs/retention", ToAdmissionLevel: "merge_satisfying"}
	want := producerTuple{"producer", "class", "proof", "receipt", "environment", "docs/provenance", "docs/retention", "merge_satisfying"}
	if admissionTupleKey(change) != want {
		t.Fatal("admission tuple lost or reordered a coordinate")
	}
	receipt := receiptRef{ProducerID: "producer", ProducerClass: "class", ProofClass: "proof", ReceiptKind: "receipt", EnvironmentClass: "environment", ProvenanceRuleRef: "docs/provenance", ArtifactRetentionRuleRef: "docs/retention", ProducerAdmissionClass: "merge_satisfying"}
	if receiptTupleKey(receipt) != want {
		t.Fatal("receipt tuple lost or reordered a coordinate")
	}
	for index := range want {
		other := receipt
		fields := []*string{&other.ProducerID, &other.ProducerClass, &other.ProofClass, &other.ReceiptKind, &other.EnvironmentClass, &other.ProvenanceRuleRef, &other.ArtifactRetentionRuleRef, &other.ProducerAdmissionClass}
		*fields[index] += ".other"
		if receiptTupleKey(other) == want {
			t.Fatalf("coordinate %d does not distinguish tuples", index)
		}
	}
}

func TestBuildDistinguishesCollidingJoinedPathTuples(t *testing.T) {
	input := validProducerPolicySelfProofInput()
	change := input["admissionChanges"].([]any)[0].(map[string]any)
	receipt := input["mergeObligationReceiptRefs"].([]any)[0].(map[string]any)
	receipt["producerId"] = change["producerId"]
	change["provenanceRuleRef"], change["artifactRetentionRuleRef"] = "docs/a|b", "docs/c"
	receipt["provenanceRuleRef"], receipt["artifactRetentionRuleRef"] = "docs/a", "b|docs/c"
	record, code, err := Build(input)
	if err != nil || code != 0 || record.State != "passed" || record.Summary["selfProofReceiptCount"] != 0 {
		t.Fatalf("distinct admitted tuples were conflated: code=%d err=%v report=%#v", code, err, record)
	}
	receipt["provenanceRuleRef"], receipt["artifactRetentionRuleRef"] = change["provenanceRuleRef"], change["artifactRetentionRuleRef"]
	record, code, err = Build(input)
	if err != nil || code != 1 || record.State != "failed" || record.Summary["selfProofReceiptCount"] != 1 {
		t.Fatalf("identical tuple escaped self-proof detection: code=%d err=%v report=%#v", code, err, record)
	}
	other := producerAdmissionChange()
	other["changeId"] = "proofkit.test.change.other"
	other["provenanceRuleRef"], other["artifactRetentionRuleRef"] = "docs/a", "b|docs/c"
	input["admissionChanges"] = []any{change, other}
	record, _, err = Build(input)
	if err != nil || record.Summary["newlyMergeSatisfyingTupleCount"] != 2 {
		t.Fatalf("distinct admitted changes were collapsed: err=%v report=%#v", err, record)
	}
}
