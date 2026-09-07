package adoptionmaterialization

import (
	"bytes"
	"reflect"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

func TestProjectProjectionPreservesIndependentChildExpectations(t *testing.T) {
	raw := projectionFixtureRequest(t)
	manifest, records := projectFixtureRecords(t, raw)
	admitted, err := AdmitMaterializedProject(manifest, records)
	if err != nil || !admitted.ClosureAdmitted || admitted.Project == nil {
		t.Fatalf("project admission failed: %#v, %v", admitted, err)
	}
	value, err := admitted.Project.JSONValue()
	if err != nil {
		t.Fatal(err)
	}
	expectedInventory := cloneValue(t, raw["testEvidenceInventory"].(map[string]any)["record"]).(map[string]any)
	expectedInventory["nonClaims"] = []any{
		"Pilot inventory fixture does not execute native tests.",
		"Test evidence inventory reports do not approve merge, release, rollout, or repository policy.",
		"Test evidence inventory reports do not authenticate runner output or receipt producers.",
		"Test evidence inventory reports do not execute native tests.",
		"Test evidence inventory reports do not prove repository inventory completeness.",
		"Test evidence inventory reports do not resolve selectors or review caller-authored oracle quality.",
		"Test evidence inventory reports do not verify that a caller-declared falsifier supersession dominates the superseded falsifier.",
	}
	expected := map[string]any{
		"manifest":              manifest.JSONValue(),
		"proofBinding":          raw["requirementProofBinding"].(map[string]any)["record"],
		"requirementSources":    raw["requirementSources"],
		"testEvidenceInventory": expectedInventory,
	}
	if !reflect.DeepEqual(value, expected) {
		t.Fatal("project projection differs from independently authored child fields")
	}
	replayed, err := AdmitProject(value)
	if err != nil {
		t.Fatal(err)
	}
	replayedValue, err := replayed.JSONValue()
	if err != nil || !reflect.DeepEqual(replayedValue, expected) {
		t.Fatalf("project replay lost canonical child fields: %v", err)
	}
	// Mutate both a projection and all original input carriers after admission.
	value["requirementSources"].([]any)[0].(map[string]any)["nonClaims"].([]any)[0] = "Changed source restriction."
	value["proofBinding"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["witnessSelectors"].([]any)[0].(map[string]any)["selector"] = "ChangedSelector"
	value["testEvidenceInventory"].(map[string]any)["entries"].([]any)[0].(map[string]any)["qualityFindings"].([]any)[0].(map[string]any)["nonClaims"].([]any)[0] = "Changed finding restriction."
	value["manifest"].(map[string]any)["routes"].([]any)[0].(map[string]any)["path"] = "changed"
	for index := range records {
		clear(records[index].Content)
	}
	manifest.Routes[0].Path = "changed"
	for _, project := range []*Project{admitted.Project, replayed} {
		fresh, err := project.JSONValue()
		if err != nil || !reflect.DeepEqual(fresh, expected) {
			t.Fatalf("retained project aliases caller data: %v", err)
		}
	}
}

func TestProjectProjectionRejectsZeroAndIncompleteProjects(t *testing.T) {
	for _, project := range []*Project{nil, {}} {
		if value, err := project.JSONValue(); err == nil || value != nil {
			t.Fatal("zero project produced an authoritative projection")
		}
	}
	manifest, records := projectFixtureRecords(t, projectionFixtureRequest(t))
	for _, count := range []int{0, 1, len(records) - 1} {
		result, err := AdmitMaterializedProject(manifest, records[:count])
		if err != nil || result.Project != nil || result.ClosureEvaluated || result.ClosureAdmitted {
			t.Fatalf("partial project retained semantic data: %#v, %v", result, err)
		}
	}
	for index := range records {
		mutant := snapshotRoutedProjectRecords(records)
		mutant[index].Content[0] ^= 1
		result, err := AdmitMaterializedProject(manifest, mutant)
		if err != nil || result.Project != nil || result.ClosureEvaluated || result.ClosureAdmitted {
			t.Fatalf("digest-mismatched project retained semantic data: %#v, %v", result, err)
		}
	}
}

func TestProjectReplayRejectsChangedProjectionOperands(t *testing.T) {
	manifest, records := projectFixtureRecords(t, projectionFixtureRequest(t))
	admitted, err := AdmitMaterializedProject(manifest, records)
	if err != nil || admitted.Project == nil {
		t.Fatal("positive project prerequisite failed")
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"source", func(value map[string]any) {
			value["requirementSources"].([]any)[0].(map[string]any)["nonClaims"] = []any{"Different source restriction."}
		}},
		{"binding", func(value map[string]any) {
			value["proofBinding"].(map[string]any)["nonClaims"] = []any{"Different binding restriction."}
		}},
		{"inventory", func(value map[string]any) {
			value["testEvidenceInventory"].(map[string]any)["nonClaims"] = []any{"Different inventory restriction."}
		}},
		{"project identity", func(value map[string]any) { value["manifest"].(map[string]any)["projectId"] = "different.project" }},
		{"duplicate source", func(value map[string]any) {
			sources := value["requirementSources"].([]any)
			value["requirementSources"] = append(sources, sources[0])
		}},
		{"unknown field", func(value map[string]any) { value["unowned"] = true }},
	}
	for _, key := range []string{"manifest", "proofBinding", "requirementSources", "testEvidenceInventory"} {
		tests = append(tests, struct {
			name   string
			mutate func(map[string]any)
		}{"missing " + key, func(value map[string]any) { delete(value, key) }})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := admitted.Project.JSONValue()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			if project, err := AdmitProject(value); err == nil || project != nil {
				t.Fatal("changed project operand survived owner replay")
			}
		})
	}
	if project, err := AdmitProject(nil); err == nil || project != nil {
		t.Fatal("non-object project survived replay")
	}
}

func TestProjectRetentionRejectsDigestMatchedCrossRecordContradiction(t *testing.T) {
	request, err := admitRequest(projectionFixtureRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	// Change only the cross-owner relation, then recompute every byte identity.
	request.Binding.Requirements[0].OwnerID = "different.owner"
	artifacts, err := childArtifacts(request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildManifest(request, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	records := routedRecords(artifacts)
	result, err := AdmitMaterializedProject(manifest, records)
	if err != nil || !result.ClosureEvaluated || result.ClosureAdmitted || result.Project != nil {
		t.Fatalf("cross-record contradiction was not isolated: %#v, %v", result, err)
	}
	for _, child := range result.Records {
		if !child.Admitted || !child.DigestMatches {
			t.Fatal("negative fixture failed before cross-record closure")
		}
	}
	projection := map[string]any{"manifest": manifest.JSONValue()}
	for _, artifact := range artifacts {
		raw, err := admission.DecodeJSON(bytes.NewReader(artifact.Content), int64(len(artifact.Content)))
		if err != nil {
			t.Fatal(err)
		}
		switch artifact.Kind {
		case ArtifactRequirementSource:
			projection["requirementSources"] = []any{raw}
		case ArtifactRequirementBinding:
			projection["proofBinding"] = raw
		case ArtifactTestInventory:
			projection["testEvidenceInventory"] = raw
		}
	}
	if project, err := AdmitProject(projection); err == nil || project != nil {
		t.Fatal("projection replay admitted the same cross-record contradiction")
	}
}

func projectionFixtureRequest(t *testing.T) map[string]any {
	t.Helper()
	raw := validRequest(t, t.TempDir())
	source := raw["requirementSources"].([]any)[0].(map[string]any)
	requirement := source["requirements"].([]any)[0].(map[string]any)
	requirement["claimLevel"] = "deferred"
	requirement["nonClaimRefs"] = []any{"pilot.nonclaim.execution"}
	requirement["deferral"] = map[string]any{
		"evidenceRefs": []any{"docs/evidence/pilot.md"}, "expiryRef": "pilot.expiry.review",
		"mergePolicy": "pilot.merge.policy", "ownerId": "pilot.owner",
		"reviewCondition": "Revisit after independent consumer evidence.", "riskAcceptedBy": "pilot.reviewer",
	}
	binding := raw["requirementProofBinding"].(map[string]any)["record"].(map[string]any)
	binding["requirements"].([]any)[0].(map[string]any)["claimLevel"] = "deferred"
	binding["bindings"].([]any)[0].(map[string]any)["witnessSelectors"] = []any{map[string]any{
		"command": "go test ./internal/pilot -run TestMaterialization", "selector": "TestMaterialization",
	}}
	inventory := raw["testEvidenceInventory"].(map[string]any)["record"].(map[string]any)
	inventory["ownerId"] = "pilot.inventory.owner"
	inventory["sourceId"] = "pilot.inventory.source"
	inventory["entries"].([]any)[0].(map[string]any)["qualityFindings"] = []any{map[string]any{
		"class": "missing_edge", "evidenceRefs": []any{"proof.pilot.quality"}, "findingId": "pilot.quality.candidate",
		"nonClaims": []any{"Candidate finding is not an owner verdict."}, "ownerReviewState": "candidate", "severity": "warning",
	}}
	return raw
}

func projectFixtureRecords(t *testing.T, raw map[string]any) (Manifest, []RoutedProjectRecord) {
	t.Helper()
	request, err := admitRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := childArtifacts(request)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := buildManifest(request, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, routedRecords(artifacts)
}

func routedRecords(artifacts []artifact) []RoutedProjectRecord {
	records := make([]RoutedProjectRecord, 0, len(artifacts))
	for _, artifact := range artifacts {
		records = append(records, RoutedProjectRecord{Content: artifact.Content, Path: artifact.Path})
	}
	// Input arrival order is not a second canonical route order.
	sort.Slice(records, func(left, right int) bool { return records[left].Path > records[right].Path })
	return records
}
