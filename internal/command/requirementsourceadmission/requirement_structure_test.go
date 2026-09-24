package requirementsourceadmission

import (
	"reflect"
	"testing"
)

func TestAtomicRequirementStructurePreservesPresenceAndOwnerProjection(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil {
		t.Fatal(err)
	}
	requirement := result.Source.Requirements()[0]
	for _, deferred := range []bool{false, true} {
		if deferred {
			requirement.Deferral = &Deferral{OwnerID: "owner", RiskAcceptedBy: "owner", ReviewCondition: "Review before release.", ExpiryRef: "review.next", MergePolicy: "owner_review", EvidenceRefs: []string{"review.proof"}}
		}
		value := RequirementValue(requirement)
		if err := RequirementShape().CheckGenerated(value, "requirement"); err != nil {
			t.Fatal(err)
		}
		wire := outputWire(t, value)
		admitted, err := RequirementShape().Admit(wire, "requirement")
		if err != nil || !reflect.DeepEqual(admitted, wire) {
			t.Fatalf("atomic projection changed: %v", err)
		}
		if _, present := value["deferral"]; present != deferred {
			t.Fatal("absent deferral changed presence")
		}
		for key := range value {
			mutated := outputWire(t, value)
			delete(mutated, key)
			err := RequirementShape().CheckGenerated(mutated, "requirement")
			if (err == nil) != (key == "deferral") {
				t.Fatalf("unexpected requiredness for %s: %v", key, err)
			}
		}
		value["deferral"] = nil
		if err := RequirementShape().CheckGenerated(value, "requirement"); err == nil {
			t.Fatal("null substituted for absent or object deferral")
		}
	}
}
