package requirementsourcemodel

import "testing"

func TestDanglingNonClaimDiagnosticsRetainOrigin(t *testing.T) {
	for _, item := range []struct {
		name   string
		path   string
		mutate func(*Draft)
	}{
		{"source", "sourceNonClaimRefs", func(d *Draft) { d.SourceNonClaimRefs = append(d.SourceNonClaimRefs, "NCL-MISSING") }},
		{"requirement", `requirements["REQ-MODEL-001"].nonClaimRefs`, func(d *Draft) {
			d.Groups[0].Members[0].Fields.NonClaimRefs.Value = append(d.Groups[0].Members[0].Fields.NonClaimRefs.Value, "NCL-MISSING")
		}},
		{"scenario", `scenarios["SCN-MODEL-REQUEST"].nonClaimRefs`, func(d *Draft) { d.Scenarios[0].NonClaimRefs = append(d.Scenarios[0].NonClaimRefs, "NCL-MISSING") }},
		{"derivation", `derivations["DRV-MODEL-001"].nonClaimRefs`, func(d *Draft) { d.Derivations[0].NonClaimRefs = append(d.Derivations[0].NonClaimRefs, "NCL-MISSING") }},
	} {
		t.Run(item.name, func(t *testing.T) {
			draft := validDraft()
			item.mutate(&draft)
			_, err := Normalize(draft)
			validation, ok := err.(*ValidationError)
			if !ok || validation.Code != "dangling_nonclaim_ref" || validation.Path != item.path {
				t.Fatalf("Normalize() = %v, want dangling reference at %s", err, item.path)
			}
			draft.NonClaimDefinitions = append(draft.NonClaimDefinitions, NonClaimDefinition{NonClaimID: "NCL-MISSING", Statement: "A reference does not prove behavior."})
			if _, err := Normalize(draft); err != nil {
				t.Fatalf("resolved reference control: %v", err)
			}
		})
	}
}
