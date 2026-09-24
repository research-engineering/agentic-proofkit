package requirementsourceadmission

import "testing"

func TestBindingRequirementLinksPreserveSourceOwnedFields(t *testing.T) {
	result, err := Evaluate(validSource())
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("source admission: %v", err)
	}
	sources := []Source{result.Source}
	valid := BindingRequirementLink{
		RequirementID: "REQ-PROOFKIT-SOURCE-001", OwnerID: "proofkit.test",
		ClaimLevel: "blocking", SpecPath: "docs/specs/proofkit-test/requirements.v2.json",
	}
	if err := AdmitBindingRequirementLinks(sources, []BindingRequirementLink{valid}); err != nil {
		t.Fatalf("matching source-owned fields rejected: %v", err)
	}
	for _, mutate := range []func(*BindingRequirementLink){
		func(link *BindingRequirementLink) { link.RequirementID = "REQ-UNKNOWN" },
		func(link *BindingRequirementLink) { link.OwnerID = "another.owner" },
		func(link *BindingRequirementLink) { link.ClaimLevel = "advisory" },
		func(link *BindingRequirementLink) { link.SpecPath = "docs/specs/other/requirements.v2.json" },
	} {
		wrong := valid
		mutate(&wrong)
		if err := AdmitBindingRequirementLinks(sources, []BindingRequirementLink{wrong}); err == nil {
			t.Fatalf("inconsistent binding link admitted: %+v", wrong)
		}
	}
}
