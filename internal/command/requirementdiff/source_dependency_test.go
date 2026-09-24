package requirementdiff

import (
	"encoding/json"
	"testing"
)

func TestNamedNonClaimMeaningProducesSemanticDiff(t *testing.T) {
	base := contextFixture(t, "The service accepts admitted requests.")
	source := base["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	source["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-SCOPE", "statement": "This requirement does not cover untrusted clients."}}
	diffSourceGroup(base)["members"].([]any)[0].(map[string]any)["fields"].(map[string]any)["nonClaimRefs"] = []any{"NCL-SCOPE"}
	resignContextFixture(t, base)
	current := cloneRequirementRecord(t, base)
	input := map[string]any{"schemaVersion": json.Number("3"), "diffId": "source.dependency.diff", "baseContext": base, "currentContext": current}
	control, err := Build(input)
	if err != nil || len(control["changes"].([]any)) != 0 {
		t.Fatalf("unchanged source changed diff: %v", err)
	}
	next := current["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)
	next["nonClaimDefinitions"].([]any)[0].(map[string]any)["statement"] = "This requirement does not cover trusted clients."
	current["sources"].([]any)[0].(map[string]any)["currentDigest"] = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	resignContextFixture(t, current)
	output, err := Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output["changes"].([]any)) == 0 {
		t.Fatal("referenced denial changed meaning but semantic diff is empty")
	}
}
