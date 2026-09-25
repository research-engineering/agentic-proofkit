package bindingpartition

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func partitionRelationInput(mode string) map[string]any {
	raw := validBindingPartitionInput(true)
	reference := raw["routeReferences"].([]any)[0].(map[string]any)
	reference["delegationRefs"] = []any{"delegation.primary"}
	delegation := map[string]any{
		"delegationRef": "delegation.primary", "fromOwnerId": "owner.secondary", "fromSurfaceId": "surface.secondary", "toOwnerId": "owner.primary", "toSurfaceId": "surface.primary",
		"proofRouteRefs": []any{"route.primary"}, "evidenceRefs": []any{"proof/delegation.json"}, "reviewConditionRef": nil, "nonClaims": []any{"Delegation fixture does not authenticate evidence."},
	}
	raw["delegations"] = []any{delegation}
	raw["surfaceThresholds"] = []any{map[string]any{"surfaceId": "surface.primary", "maxCohesionGroupCount": json.Number("1"), "maxOwnedProofRouteCount": json.Number("1"), "maxOwnedSelectorCount": json.Number("1")}}
	switch mode {
	case "dense", "mixed-negative":
		raw["proofRouteRefs"] = []any{"route.extra", "route.primary"}
		raw["routeOwners"] = append(raw["routeOwners"].([]any), map[string]any{"proofRouteRef": "route.extra", "ownerId": "owner.primary", "surfaceId": "surface.primary", "selectorRefs": []any{"selector.primary"}, "cohesionGroupId": "group.extra"})
		delegation["proofRouteRefs"] = []any{"route.extra", "route.primary"}
		raw["routeReferences"] = append(raw["routeReferences"].([]any), map[string]any{"referenceId": "reference.extra", "referrerOwnerId": "owner.secondary", "referrerSurfaceId": "surface.secondary", "proofRouteRef": "route.extra", "delegationRefs": []any{"delegation.primary"}})
	case "no-match":
		reference["delegationRefs"] = []any{"delegation.missing"}
	case "mismatch":
		delegation["toOwnerId"] = "owner.wrong"
	case "extra":
		reference["delegationRefs"] = []any{"delegation.missing", "delegation.primary"}
	case "same-surface":
		reference["referrerOwnerId"] = "owner.primary"
		reference["referrerSurfaceId"] = "surface.primary"
	case "ambiguous":
		raw["routeOwners"] = append(raw["routeOwners"].([]any), raw["routeOwners"].([]any)[0])
	case "unknown":
		reference["proofRouteRef"] = "route.unknown"
		reference["referrerSurfaceId"] = "surface.unknown"
	}
	if mode == "mixed-negative" {
		raw["routeOwners"] = append(raw["routeOwners"].([]any), raw["routeOwners"].([]any)[0])
		raw["bindingSurfaces"].([]any)[1].(map[string]any)["selectorRefs"] = []any{"selector.primary"}
		reference["delegationRefs"] = []any{"delegation.missing", "delegation.primary"}
		extra := raw["routeOwners"].([]any)[1].(map[string]any)
		extra["ownerId"] = "owner.wrong"
		extra["selectorRefs"] = []any{"selector.unknown"}
	}
	return raw
}

func TestPartitionRelationFullOutputParity(t *testing.T) {
	// Complete report plus exit code, captured at base 27fcb8e.
	wants := map[string]string{
		"sparse":         "4af488a26c6db9d01a8af332851a88dff37e3293d1a423955c75c4ae96f65d6a",
		"dense":          "b6c632df17061084f9ab931c9d31b6026131970c451d75b008f24182945db0ca",
		"no-match":       "793374f54c9ace54188a1316746a78e42c7a106259c2d11491906bf01a12241f",
		"mismatch":       "34ba1cd1165927444987abe62a7b6d534d7e91a5fc1999e1d62e4d675ab38f3a",
		"extra":          "efeefe8783c6a6e48aa8d53daec811059c4284c5690480123af95af01b64f78e",
		"same-surface":   "96216fa481af34e85e1e287002967110ffc160513bdcb9cf775b75618ae6eaad",
		"ambiguous":      "adbba209af2ac08fa97623ca00f43c251498d8ba1978e112c9b2bb447eea7b14",
		"unknown":        "11e41628c86eb994baf6213c0018da66f82d9e249669ec877bf6a90f420d94f5",
		"mixed-negative": "0fe9d27ff5a6b37e0a0a8089b3d403f5faf6c8c8f61c98eb1393e66152a2a020",
	}
	findings := map[string]string{"dense": "exceeds caller maxOwnedProofRouteCount: 2 > 1", "no-match": "crosses owner or surface without exact delegation", "mismatch": "has unmatched delegationRefs: delegation.primary", "extra": "has unmatched delegationRefs: delegation.missing", "same-surface": "declares delegationRefs for same-owner same-surface route", "ambiguous": "has more than one canonical route owner", "unknown": "points at an unowned proofRouteRef", "mixed-negative": "is declared by multiple surfaces"}
	for _, name := range []string{"sparse", "dense", "no-match", "mismatch", "extra", "same-surface", "ambiguous", "unknown", "mixed-negative"} {
		t.Run(name, func(t *testing.T) {
			raw := partitionRelationInput(name)
			before, _ := json.Marshal(raw)
			record, code, err := Build(raw)
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(raw)
			if string(before) != string(after) {
				t.Fatal("Build mutated caller input")
			}
			encoded, err := json.Marshal([]any{record, code})
			if err != nil {
				t.Fatal(err)
			}
			if name == "sparse" {
				if code != 0 || record.State != "passed" {
					t.Fatalf("positive fixture failed: %s", encoded)
				}
			} else if code != 1 || record.State != "failed" || !strings.Contains(string(encoded), strings.ReplaceAll(findings[name], ">", "\\u003e")) {
				t.Fatalf("missing negative finding %q: %s", findings[name], encoded)
			}
			got := fmt.Sprintf("%x", sha256.Sum256(encoded))
			if got != wants[name] {
				t.Fatalf("full output digest = %s", got)
			}
		})
	}
}

func TestPartitionRelationAdmissionUniqueness(t *testing.T) {
	for _, key := range []string{"bindingSurfaces", "delegations"} {
		t.Run(key, func(t *testing.T) {
			raw := partitionRelationInput("sparse")
			items := raw[key].([]any)
			raw[key] = append(items, items[0])
			if _, _, err := Build(raw); err == nil {
				t.Fatalf("duplicate %s admitted", key)
			}
		})
	}
}
