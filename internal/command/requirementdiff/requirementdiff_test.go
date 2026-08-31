package requirementdiff

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
)

func TestBuildClassifiesOwnerAwareRequirementChanges(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.070793924321910266811017548213459952142613821158702213873670242368963866904489")
	baseline := contextFixture(t, "The system preserves the baseline.")
	current := contextFixture(t, "The system preserves the revised invariant.")
	output, err := Build(map[string]any{"schemaVersion": json.Number("2"), "diffId": "consumer.requirement.diff", "baseContext": baseline, "currentContext": current, "query": map[string]any{"requirementIds": []any{"REQ-CONSUMER-001"}}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if output["changeCount"] != 1 {
		t.Fatalf("changeCount = %v, want 1", output["changeCount"])
	}
	change := output["changes"].([]any)[0].(map[string]any)
	if change["changeClass"] != "scalar_changed" {
		t.Fatalf("change class = %v", change["changeClass"])
	}
	if change["jsonPointer"] != "/requirements/REQ-CONSUMER-001/invariant" {
		t.Fatalf("change pointer = %v", change["jsonPointer"])
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
		t.Fatalf("AdmitOutput() error = %v", err)
	}
	decoded.(map[string]any)["changes"].([]any)[0].(map[string]any)["after"] = "tampered without updating identity"
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted changed semantic facts under a stale changeId")
	}
}

func TestDigestCoverageAdaptersPreserveSemanticDiffV2(t *testing.T) {
	baseV2 := contextFixture(t, "The system preserves the baseline.")
	currentV2 := contextFixture(t, "The system preserves the revised invariant.")
	v2Input := map[string]any{"baseContext": baseV2, "currentContext": currentV2, "diffId": "consumer.digest-coverage.diff", "schemaVersion": json.Number("2")}
	v2Output, err := Build(v2Input)
	if err != nil {
		t.Fatal(err)
	}
	if v2Output["schemaVersion"] != json.Number("2") || v2Output["baseExpectedDigestCoverage"] != "none" || v2Output["currentExpectedDigestCoverage"] != "none" {
		t.Fatalf("semantic diff did not emit v2 digest coverage: %#v", v2Output)
	}

	baseV1 := v1DiffContextFixture(t, baseV2)
	currentV1 := v1DiffContextFixture(t, currentV2)
	v1Output, err := Build(map[string]any{"baseContext": baseV1, "currentContext": currentV1, "diffId": "consumer.digest-coverage.diff", "schemaVersion": json.Number("1")})
	if err != nil {
		t.Fatalf("Build(v1) error = %v", err)
	}
	if got, want := stableBytes(t, v1Output), stableBytes(t, v2Output); !bytes.Equal(got, want) {
		t.Fatalf("v1 input normalized to a different semantic diff\n got: %s\nwant: %s", got, want)
	}

	var v1WireOutput map[string]any
	for _, mapping := range []struct {
		legacy string
		v2     string
	}{
		{legacy: "unverified", v2: "none"},
		{legacy: "partially_verified", v2: "partial"},
		{legacy: "verified", v2: "all"},
	} {
		expectedV2 := cloneRequirementRecord(t, v2Output)
		expectedV2["baseExpectedDigestCoverage"] = mapping.v2
		expectedV2["currentExpectedDigestCoverage"] = mapping.v2
		v1WireOutput = cloneRequirementRecord(t, expectedV2)
		delete(v1WireOutput, "baseExpectedDigestCoverage")
		delete(v1WireOutput, "currentExpectedDigestCoverage")
		v1WireOutput["baseBaselineVerification"] = mapping.legacy
		v1WireOutput["currentBaselineVerification"] = mapping.legacy
		v1WireOutput["schemaVersion"] = json.Number("1")
		normalized, err := AdmitOutput(v1WireOutput, currentV2["snapshotId"].(string))
		if err != nil {
			t.Fatalf("AdmitOutput(v1 %s) error = %v", mapping.legacy, err)
		}
		if got, want := stableBytes(t, normalized), stableBytes(t, expectedV2); !bytes.Equal(got, want) {
			t.Fatalf("v1 %s output normalized to a different semantic record\n got: %s\nwant: %s", mapping.legacy, got, want)
		}
	}

	if _, err := Build(map[string]any{"baseContext": baseV2, "currentContext": currentV2, "diffId": "consumer.mixed.diff", "schemaVersion": json.Number("1")}); err == nil {
		t.Fatal("Build accepted a v1 envelope with v2 contexts")
	}
	mixedOutput := cloneRequirementRecord(t, v2Output)
	mixedOutput["baseBaselineVerification"] = "unverified"
	if _, err := AdmitOutput(mixedOutput, currentV2["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted mixed v1/v2 digest coverage fields")
	}
	v1WireOutput["baseExpectedDigestCoverage"] = "all"
	if _, err := AdmitOutput(v1WireOutput, currentV2["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted mixed v1/v2 digest coverage fields under schema v1")
	}
}

func TestBuildOutputIsClosedUnderAdmissionForMultipleChanges(t *testing.T) {
	baseline := contextFixture(t, "The system preserves the baseline.")
	current := contextFixture(t, "The system preserves the revised invariant.")
	requirement := current["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["claimLevel"] = "advisory"
	requirement["nonClaims"] = []any{"The revised requirement does not approve merge."}
	requirement["ownerId"] = "consumer.next-owner"
	requirement["riskClass"] = "critical"
	requirement["updatePolicy"].(map[string]any)["reviewOwnerId"] = "consumer.next-owner"
	resignContextFixture(t, current)

	output, err := Build(map[string]any{"baseContext": baseline, "currentContext": current, "diffId": "consumer.multi-field.diff", "schemaVersion": json.Number("2")})
	if err != nil {
		t.Fatal(err)
	}
	if output["changeCount"] != 6 {
		t.Fatalf("changeCount = %v, want 6", output["changeCount"])
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
		t.Fatalf("producer output was rejected by its admission owner: %v", err)
	}
	changes := decoded.(map[string]any)["changes"].([]any)
	changes[0], changes[1] = changes[1], changes[0]
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted non-canonical semantic change order")
	}
}

func TestOwnerFilterPreservesStableIdentityAcrossOwnershipChange(t *testing.T) {
	baseline := contextFixture(t, "The system preserves the same invariant.")
	current := contextFixture(t, "The system preserves the same invariant.")
	requirement := current["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["ownerId"] = "consumer.next-owner"
	resignContextFixture(t, current)

	for _, item := range []struct {
		ownerID    string
		wantChange bool
	}{
		{ownerID: "consumer.owner", wantChange: true},
		{ownerID: "consumer.next-owner", wantChange: true},
		{ownerID: "consumer.unrelated-owner", wantChange: false},
	} {
		t.Run(item.ownerID, func(t *testing.T) {
			output, err := Build(map[string]any{
				"baseContext": baseline, "currentContext": current, "diffId": "consumer.owner-transition.diff", "schemaVersion": json.Number("2"),
				"query": map[string]any{"ownerIds": []any{item.ownerID}},
			})
			if err != nil {
				t.Fatal(err)
			}
			changes := output["changes"].([]any)
			if !item.wantChange {
				if len(changes) != 0 {
					t.Fatalf("unrelated owner selected changes: %#v", changes)
				}
				return
			}
			if len(changes) != 1 {
				t.Fatalf("changes = %#v, want one owner transition", changes)
			}
			change := changes[0].(map[string]any)
			if change["changeClass"] != "scalar_changed" || change["jsonPointer"] != "/requirements/REQ-CONSUMER-001/ownerId" || change["before"] != "consumer.owner" || change["after"] != "consumer.next-owner" {
				t.Fatalf("owner transition lost stable identity: %#v", change)
			}
		})
	}
}

func TestBuildCoversCompleteRequirementChangeAlgebra(t *testing.T) {
	commandcoverage.SemanticRoute(t, "proofkit.command_coverage.source_oracle.v1.020074570913264891573344859495254807591700934304007335407083834667788859243594")
	baseline := contextFixture(t, "The shared requirement remains stable.")
	current := contextFixture(t, "The shared requirement changes its invariant.")
	baseRequirements := baseline["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)
	currentRequirements := current["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)

	removed := cloneRequirementRecord(t, baseRequirements[0].(map[string]any))
	removed["requirementId"] = "REQ-CONSUMER-REMOVED"
	baseline["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"] = append(baseRequirements, removed)

	added := cloneRequirementRecord(t, currentRequirements[0].(map[string]any))
	added["requirementId"] = "REQ-CONSUMER-ADDED"
	added["invariant"] = "The added requirement remains independently identifiable."
	current["projections"].(map[string]any)["requirementSources"].([]any)[0].(map[string]any)["requirements"] = append(currentRequirements, added)

	shared := currentRequirements[0].(map[string]any)
	shared["claimLevel"] = "advisory"
	shared["nonClaimRefs"] = []any{"NC-CONSUMER-001", "NC-CONSUMER-002"}
	shared["updatePolicy"].(map[string]any)["requiresImpactDeclaration"] = false
	shared["lifecycle"] = map[string]any{
		"state":                     "superseded",
		"replacementRequirementIds": []any{"REQ-CONSUMER-ADDED"},
		"evidenceRefs":              []any{"consumer.lifecycle.transition"},
	}
	resignContextFixture(t, baseline)
	resignContextFixture(t, current)

	output, err := Build(map[string]any{
		"baseContext": baseline, "currentContext": current,
		"diffId": "consumer.complete-algebra.diff", "schemaVersion": json.Number("2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]bool{}
	pointers := map[string]string{}
	for _, raw := range output["changes"].([]any) {
		change := raw.(map[string]any)
		class := change["changeClass"].(string)
		classes[class] = true
		pointers[change["jsonPointer"].(string)] = class
	}
	for _, class := range []string{"entity_added", "entity_removed", "lifecycle_transition", "opaque_value_changed", "scalar_changed", "set_membership_changed"} {
		if !classes[class] {
			t.Fatalf("semantic diff omitted %s: %#v", class, output["changes"])
		}
	}
	for pointer, class := range map[string]string{
		"/requirements/REQ-CONSUMER-ADDED":            "entity_added",
		"/requirements/REQ-CONSUMER-REMOVED":          "entity_removed",
		"/requirements/REQ-CONSUMER-001/invariant":    "scalar_changed",
		"/requirements/REQ-CONSUMER-001/nonClaimRefs": "set_membership_changed",
		"/requirements/REQ-CONSUMER-001/updatePolicy": "opaque_value_changed",
		"/requirements/REQ-CONSUMER-001/lifecycle":    "lifecycle_transition",
	} {
		if pointers[pointer] != class {
			t.Fatalf("change %s class=%q, want %q", pointer, pointers[pointer], class)
		}
	}
	encoded, err := stablejson.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitOutput(decoded, current["snapshotId"].(string)); err != nil {
		t.Fatalf("complete semantic diff algebra is not closed under output admission: %v", err)
	}
}

func TestBuildIncludesDeferralAndAdmissionBindsChangeIdentity(t *testing.T) {
	base := deferredContextFixture(t, "Review after the migration window.")
	current := deferredContextFixture(t, "Review after the compatibility window.")
	output, err := Build(map[string]any{"baseContext": base, "currentContext": current, "diffId": "consumer.deferral.diff", "schemaVersion": json.Number("2")})
	if err != nil {
		t.Fatal(err)
	}
	if output["changeCount"] != 1 || output["changes"].([]any)[0].(map[string]any)["jsonPointer"] != "/requirements/REQ-CONSUMER-001/deferral" {
		t.Fatalf("deferral change was not projected: %#v", output)
	}
	encoded, _ := stablejson.Marshal(output)
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	tampered := decoded.(map[string]any)
	tampered["changes"].([]any)[0].(map[string]any)["changeId"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := AdmitOutput(tampered, current["snapshotId"].(string)); err == nil {
		t.Fatal("AdmitOutput accepted a changeId unrelated to the admitted change")
	}
}

func deferredContextFixture(t *testing.T, reviewCondition string) map[string]any {
	t.Helper()
	value := contextFixture(t, "The deferred contract remains explicit.")
	projections := value["projections"].(map[string]any)
	requirement := projections["requirementSources"].([]any)[0].(map[string]any)["requirements"].([]any)[0].(map[string]any)
	requirement["claimLevel"] = "deferred"
	requirement["deferral"] = map[string]any{"evidenceRefs": []any{"docs/evidence/deferral.json"}, "expiryRef": "consumer.expiry", "mergePolicy": "consumer.deferred", "ownerId": "consumer.owner", "reviewCondition": reviewCondition, "riskAcceptedBy": "consumer.owner"}
	identity := map[string]any{"catalogId": value["catalogId"], "projections": projections, "sources": []any{map[string]any{"currentDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "expectedDigest": "", "kind": "requirement_source", "nodeId": "spec.root", "path": "docs/specs/consumer/requirements.v1.json", "sourceRef": "consumer.requirements", "sourceRole": "requirements"}, map[string]any{"currentDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "expectedDigest": "", "kind": "spec_tree", "path": "proofkit/spec-tree.json", "sourceRef": "spec_tree:consumer.spec-tree"}}}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	value["snapshotId"] = digest.SHA256TextRef(string(encoded))
	return value
}

func contextFixture(t *testing.T, invariant string) map[string]any {
	t.Helper()
	projections := map[string]any{
		"specTree": treeFixture(),
		"requirementSources": []any{map[string]any{
			"schemaVersion": json.Number("1"), "sourceId": "consumer.requirements", "specPackagePath": "docs/specs/consumer", "overviewPath": "docs/specs/consumer/overview.md", "requirementsPath": "docs/specs/consumer/requirements.v1.json", "nonClaims": []any{"Consumer source does not approve merge."},
			"requirements": []any{map[string]any{"requirementId": "REQ-CONSUMER-001", "ownerId": "consumer.owner", "invariant": invariant, "claimLevel": "blocking", "riskClass": "high", "proofBindingRefs": []any{"proofkit/requirement-bindings.json"}, "nonClaimRefs": []any{"NC-CONSUMER-001"}, "nonClaims": []any{"This requirement does not approve merge."}, "lifecycle": map[string]any{"state": "active", "replacementRequirementIds": []any{}, "evidenceRefs": []any{}}, "updatePolicy": map[string]any{"reviewOwnerId": "consumer.owner", "requiresImpactDeclaration": true, "requiresProofBindingReview": true}}},
		}},
	}
	sources := []requirementcontext.Source{{CurrentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: "requirement_source", NodeID: "spec.root", Path: "docs/specs/consumer/requirements.v1.json", SourceRef: "consumer.requirements", SourceRole: "requirements"}, {CurrentDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Kind: "spec_tree", Path: "proofkit/spec-tree.json", SourceRef: "spec_tree:consumer.spec-tree"}}
	identity := map[string]any{"catalogId": "consumer.context", "projections": projections, "sources": []any{map[string]any{"currentDigest": sources[0].CurrentDigest, "expectedDigest": "", "kind": sources[0].Kind, "nodeId": sources[0].NodeID, "path": sources[0].Path, "sourceRef": sources[0].SourceRef, "sourceRole": sources[0].SourceRole}, map[string]any{"currentDigest": sources[1].CurrentDigest, "expectedDigest": "", "kind": sources[1].Kind, "path": sources[1].Path, "sourceRef": sources[1].SourceRef}}}
	encoded, err := stablejson.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	return requirementcontext.SnapshotValue(requirementcontext.Snapshot{CatalogID: "consumer.context", ExpectedDigestCoverage: "none", Projections: projections, SnapshotID: digest.SHA256TextRef(string(encoded)), Sources: sources})
}

func v1DiffContextFixture(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	v1 := cloneRequirementRecord(t, value)
	delete(v1, "expectedDigestCoverage")
	v1["baselineVerification"] = "unverified"
	v1["nonClaims"] = []any{
		"Requirement context is a derived projection and is not requirement, proof, coverage, merge, release, rollout, or readiness authority.",
		"Requirement context does not execute native witnesses or prove source freshness after composition.",
	}
	v1["schemaVersion"] = json.Number("1")
	return v1
}

func stableBytes(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func resignContextFixture(t *testing.T, value map[string]any) {
	t.Helper()
	identitySources := make([]any, 0, len(value["sources"].([]any)))
	for _, raw := range value["sources"].([]any) {
		source := raw.(map[string]any)
		identity := map[string]any{
			"currentDigest":  source["currentDigest"],
			"expectedDigest": "",
			"kind":           source["kind"],
			"path":           source["path"],
			"sourceRef":      source["sourceRef"],
		}
		for _, key := range []string{"expectedDigest", "nodeId", "sourceRole"} {
			if source[key] != nil {
				identity[key] = source[key]
			}
		}
		identitySources = append(identitySources, identity)
	}
	encoded, err := stablejson.Marshal(map[string]any{"catalogId": value["catalogId"], "projections": value["projections"], "sources": identitySources})
	if err != nil {
		t.Fatal(err)
	}
	value["snapshotId"] = digest.SHA256TextRef(string(encoded))
}

func cloneRequirementRecord(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	record, ok := decoded.(map[string]any)
	if !ok {
		t.Fatal("cloned requirement is not an object")
	}
	return record
}

func treeFixture() map[string]any {
	return map[string]any{"schemaVersion": json.Number("2"), "treeId": "consumer.spec-tree", "rootNodeId": "spec.root", "callerAnnotations": []any{}, "edges": []any{}, "overlays": []any{}, "nodes": []any{map[string]any{"nodeId": "spec.root", "nodeKind": "meta_spec", "label": "Root", "displayOrder": json.Number("1"), "callerAnnotations": []any{}, "sourceRefs": []any{map[string]any{"sourceRefId": "spec.root.requirements", "sourceRefKind": "source_id", "sourceRole": "requirements", "sourceId": "consumer.requirements"}}}}}
}
