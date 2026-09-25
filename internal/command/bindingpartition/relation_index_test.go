package bindingpartition

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPartitionRelationIndexKeepsEveryOwner(t *testing.T) {
	for _, mode := range []string{"sparse", "dense", "ambiguous", "mixed-negative", "unknown"} {
		input, err := admitInput(partitionRelationInput(mode))
		if err != nil {
			t.Fatal(err)
		}
		index := indexPartitionRelations(input)
		for _, surface := range input.BindingSurfaces {
			want := []routeOwnerInput{}
			for _, owner := range input.RouteOwners {
				if owner.SurfaceID == surface.SurfaceID {
					want = append(want, owner)
				}
			}
			got := index.ownersBySurface[surface.SurfaceID]
			if len(got) != len(want) || len(got) > 0 && !reflect.DeepEqual(got, want) {
				t.Fatalf("%s lost/reordered owner records", mode)
			}
			for _, selector := range surface.SelectorRefs {
				if _, ok := index.selectorsBySurface[surface.SurfaceID][selector]; !ok {
					t.Fatalf("lost selector %s", selector)
				}
			}
		}
		for _, delegation := range input.Delegations {
			if !reflect.DeepEqual(index.delegationsByRef[delegation.DelegationRef], delegation) {
				t.Fatal("changed delegation")
			}
		}
	}
}

func TestPartitionIndexedDelegationRequiresEveryCoordinate(t *testing.T) {
	for _, key := range []string{"delegationRef", "fromOwnerId", "fromSurfaceId", "toOwnerId", "toSurfaceId", "proofRouteRefs"} {
		t.Run(key, func(t *testing.T) {
			raw := partitionRelationInput("sparse")
			delegation := raw["delegations"].([]any)[0].(map[string]any)
			if key == "proofRouteRefs" {
				delegation[key] = []any{"route.wrong"}
			} else {
				delegation[key] = "coordinate.wrong"
			}
			record, code, err := Build(raw)
			if err != nil {
				t.Fatal(err)
			}
			if code != 1 || !strings.Contains(fmt.Sprint(record), "crosses owner or surface without exact delegation") {
				t.Fatalf("ignored %s: %#v", key, record)
			}
		})
	}
}

func partitionIndexFixture(surfaces, owners, delegations, refsPerReference int, mode string) admittedInput {
	input := admittedInput{}
	for i := 0; i < surfaces; i++ {
		selectors := []string{}
		for j := 0; j < 16; j++ {
			selectors = append(selectors, fmt.Sprintf("selector.%04d.%04d", i, j))
		}
		input.BindingSurfaces = append(input.BindingSurfaces, surfaceInput{SurfaceID: fmt.Sprintf("surface.%04d", i), OwnerID: fmt.Sprintf("owner.%04d", i), SelectorRefs: selectors})
	}
	for i := 0; i < owners; i++ {
		surface := input.BindingSurfaces[i%surfaces]
		input.RouteOwners = append(input.RouteOwners, routeOwnerInput{ProofRouteRef: fmt.Sprintf("route.%04d", i), OwnerID: surface.OwnerID, SurfaceID: surface.SurfaceID, SelectorRefs: surface.SelectorRefs[:1]})
	}
	for i := 0; i < delegations; i++ {
		owner := input.RouteOwners[i%owners]
		input.Delegations = append(input.Delegations, delegationInput{DelegationRef: fmt.Sprintf("delegation.%04d", i), FromOwnerID: "referrer.owner", FromSurfaceID: "referrer.surface", ToOwnerID: owner.OwnerID, ToSurfaceID: owner.SurfaceID, ProofRouteRefs: []string{owner.ProofRouteRef}})
	}
	for i, owner := range input.RouteOwners {
		refs := []string{}
		for j := 0; j < refsPerReference; j++ {
			ref := input.Delegations[(i+j)%delegations].DelegationRef
			if mode == "no-match" {
				ref = "missing." + ref
			}
			refs = append(refs, ref)
		}
		input.RouteReferences = append(input.RouteReferences, routeReferenceInput{ProofRouteRef: owner.ProofRouteRef, ReferrerOwnerID: "referrer.owner", ReferrerSurfaceID: "referrer.surface", DelegationRefs: refs})
	}
	return input
}

// Measure only the three changed joins; report policy and rendering are not
// timed. Shared route-owner and surface lookups are prepared outside timing.
func partitionJoinCount(input admittedInput, ownersByRef map[string][]routeOwnerInput, surfacesByID map[string]surfaceInput, index *partitionRelationIndex) int {
	count := 0
	for _, surface := range input.BindingSurfaces {
		if index != nil {
			count += len(index.ownersBySurface[surface.SurfaceID])
			continue
		}
		owned := []routeOwnerInput{}
		for _, owner := range input.RouteOwners {
			if owner.SurfaceID == surface.SurfaceID {
				owned = append(owned, owner)
			}
		}
		count += len(owned)
	}
	for _, owner := range input.RouteOwners {
		var selectors map[string]struct{}
		if index != nil {
			selectors = index.selectorsBySurface[owner.SurfaceID]
		} else {
			selectors = map[string]struct{}{}
			for _, ref := range surfacesByID[owner.SurfaceID].SelectorRefs {
				selectors[ref] = struct{}{}
			}
		}
		for _, ref := range owner.SelectorRefs {
			if _, ok := selectors[ref]; ok {
				count++
			}
		}
	}
	for _, reference := range input.RouteReferences {
		owner := ownersByRef[reference.ProofRouteRef][0]
		for _, ref := range reference.DelegationRefs {
			if index != nil {
				if delegation, ok := index.delegationsByRef[ref]; ok && delegationMatchesReference(delegation, reference, owner, ref) {
					count++
				}
			} else {
				for _, delegation := range input.Delegations {
					if delegationMatchesReference(delegation, reference, owner, ref) {
						count++
						break
					}
				}
			}
		}
	}
	return count
}

var partitionBenchmarkSink int

func BenchmarkPartitionRelations(b *testing.B) {
	for _, size := range [][4]int{{8, 32, 32, 1}, {32, 32, 32, 1}, {8, 128, 32, 1}, {8, 32, 256, 1}, {8, 32, 32, 16}} {
		for _, mode := range []string{"matched", "no-match"} {
			input := partitionIndexFixture(size[0], size[1], size[2], size[3], mode)
			owners := mapRouteOwners(input.RouteOwners)
			surfaces := map[string]surfaceInput{}
			for _, surface := range input.BindingSurfaces {
				surfaces[surface.SurfaceID] = surface
			}
			index := indexPartitionRelations(input)
			if partitionJoinCount(input, owners, surfaces, &index) != partitionJoinCount(input, owners, surfaces, nil) {
				b.Fatal("join count differs from baseline")
			}
			name := fmt.Sprintf("S%d-O%d-D%d-F%d/%s", size[0], size[1], size[2], size[3], mode)
			b.Run(name+"/setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					index := indexPartitionRelations(input)
					partitionBenchmarkSink = len(index.ownersBySurface) + len(index.delegationsByRef) + len(index.selectorsBySurface)
				}
			})
			b.Run(name+"/baseline", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					partitionBenchmarkSink = partitionJoinCount(input, owners, surfaces, nil)
				}
			})
			b.Run(name+"/indexed-with-setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					index := indexPartitionRelations(input)
					partitionBenchmarkSink = partitionJoinCount(input, owners, surfaces, &index)
				}
			})
		}
	}
}
