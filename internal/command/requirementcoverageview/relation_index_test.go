package requirementcoverageview

import (
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
)

func baselineInventoryRelation(entries []testevidenceinventory.Entry, ref string, kind int) []testevidenceinventory.Entry {
	result := []testevidenceinventory.Entry{}
	for _, entry := range entries {
		refs := entry.RequirementRefs
		if kind == 1 {
			refs = entry.OwnerInvariantRefs
		}
		if kind == 2 {
			refs = entry.CommandRefs
		}
		for _, candidate := range refs {
			if candidate == ref {
				result = append(result, entry)
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TestID < result[j].TestID })
	return result
}

func inventoryRelationQueries(input compositeInput) [3]map[string]struct{} {
	owners := mapSet(input.CoverageUniverse.OwnerIDs)
	requirements := mapSet(scopedSourceRequirementIDs(input.Source, owners))
	invariants := map[string]struct{}{}
	for _, invariant := range input.OwnerInvariantRegistry.Invariants {
		if inOwnerScope(invariant.OwnerID, owners) {
			invariants[invariant.OwnerInvariantID] = struct{}{}
		}
	}
	commands := mapSet(scopedProofCommandIDs(input, owners))
	for _, command := range input.CoverageUniverse.CommandRefs {
		commands[command] = struct{}{}
	}
	return [3]map[string]struct{}{requirements, invariants, commands}
}

func TestInventoryRelationIndexPreservesAdmittedEntries(t *testing.T) {
	for _, mode := range []string{"sparse", "dense", "no-match", "failed", "mixed-negative", "owner-scope", "compact"} {
		t.Run(mode, func(t *testing.T) {
			input, err := admitCompositeInput(relationParityInput(t, mode))
			if err != nil {
				t.Fatal(err)
			}
			entries := input.Inventory.Inventory.Entries
			queries := inventoryRelationQueries(input)
			index := indexInventoryRelations(entries, queries[0], queries[1], queries[2])
			for kind, byRef := range []map[string][]testevidenceinventory.Entry{index.byRequirement, index.byOwnerInvariant, index.byCommand} {
				for ref := range byRef {
					if _, queried := queries[kind][ref]; !queried {
						t.Fatalf("kind=%d materialized unqueried ref=%s", kind, ref)
					}
				}
				for ref := range queries[kind] {
					got, want := byRef[ref], baselineInventoryRelation(entries, ref, kind)
					if len(got) != len(want) || len(got) > 0 && !reflect.DeepEqual(got, want) {
						t.Fatalf("kind=%d ref=%s: indexed=%#v baseline=%#v", kind, ref, got, want)
					}
				}
			}
		})
	}
}

func TestInventoryRelationIndexExcludesUnqueriedRefs(t *testing.T) {
	input, err := admitCompositeInput(queryScopedRelationInput(t))
	if err != nil {
		t.Fatal(err)
	}
	entries := input.Inventory.Inventory.Entries
	queries := inventoryRelationQueries(input)
	wantQueries := [3]map[string]struct{}{
		mapSet([]string{"REQ-PROOFKIT-COVERAGE-001", "REQ-PROOFKIT-COVERAGE-002"}),
		mapSet([]string{"invariant.1", "invariant.2"}),
		mapSet([]string{"command.1", "command.2", "command.declared"}),
	}
	if !reflect.DeepEqual(queries, wantQueries) {
		t.Fatalf("projection queries = %#v, want %#v", queries, wantQueries)
	}
	excluded := [3][]string{
		{"REQ-PROOFKIT-COVERAGE-003", "REQ-UNKNOWN"},
		{"invariant.3", "invariant.unknown"},
		{"command.3", "command.unknown"},
	}
	index := indexInventoryRelations(entries, queries[0], queries[1], queries[2])
	for kind, byRef := range []map[string][]testevidenceinventory.Entry{index.byRequirement, index.byOwnerInvariant, index.byCommand} {
		if len(byRef) != len(wantQueries[kind]) {
			t.Errorf("kind=%d buckets=%d, want %d", kind, len(byRef), len(wantQueries[kind]))
		}
		for ref := range wantQueries[kind] {
			if want := baselineInventoryRelation(entries, ref, kind); !reflect.DeepEqual(byRef[ref], want) {
				t.Errorf("kind=%d ref=%s differs from original scan: got %#v want %#v", kind, ref, byRef[ref], want)
			}
		}
		for _, ref := range excluded[kind] {
			if len(baselineInventoryRelation(entries, ref, kind)) == 0 {
				t.Fatalf("kind=%d ref=%s has no inventory matches; exclusion test is vacuous", kind, ref)
			}
			if _, present := byRef[ref]; present {
				t.Errorf("kind=%d materialized unqueried ref=%s", kind, ref)
			}
		}
	}
	for emptyKind := range queries {
		scoped := queries
		scoped[emptyKind] = nil
		index := indexInventoryRelations(entries, scoped[0], scoped[1], scoped[2])
		for kind, byRef := range []map[string][]testevidenceinventory.Entry{index.byRequirement, index.byOwnerInvariant, index.byCommand} {
			if kind == emptyKind {
				if len(byRef) != 0 {
					t.Errorf("empty query domain kind=%d has %d buckets", kind, len(byRef))
				}
				continue
			}
			for ref := range scoped[kind] {
				if !reflect.DeepEqual(byRef[ref], baselineInventoryRelation(entries, ref, kind)) {
					t.Errorf("empty kind=%d changed kind=%d ref=%s", emptyKind, kind, ref)
				}
			}
		}
	}
}

func TestInventoryRelationAdmissionRejectsDuplicateRefsAndTestIDs(t *testing.T) {
	for _, key := range []string{"requirementRefs", "ownerInvariantRefs", "commandRefs", "testId"} {
		t.Run(key, func(t *testing.T) {
			raw := relationParityInput(t, "sparse")
			entries := raw["testEvidenceInventory"].(map[string]any)["entries"].([]any)
			entry := entries[0].(map[string]any)
			if key == "testId" {
				entry[key] = entries[1].(map[string]any)[key]
			} else {
				refs := entry[key].([]any)
				entry[key] = append(refs, refs[0])
			}
			if _, err := admitCompositeInput(raw); err == nil {
				t.Fatalf("duplicate %s admitted", key)
			}
		})
	}
}

func inventoryRelationFixture(tests, queries, refsPerTest int, mode string) ([]testevidenceinventory.Entry, []string) {
	refs := make([]string, queries)
	for i := range refs {
		refs[i] = fmt.Sprintf("ref.%04d", i)
	}
	entries := make([]testevidenceinventory.Entry, tests)
	for i := range entries {
		entryRefs := []string{}
		for j := 0; j < refsPerTest; j++ {
			ref := refs[(i+j)%queries]
			if mode == "no-match" {
				ref = "unknown." + ref
			}
			entryRefs = append(entryRefs, ref)
		}
		sort.Strings(entryRefs)
		entries[i] = testevidenceinventory.Entry{TestID: fmt.Sprintf("test.%04d", i), RequirementRefs: entryRefs, OwnerInvariantRefs: entryRefs, CommandRefs: entryRefs}
	}
	return entries, refs
}

var inventoryBenchmarkSink int
var inventoryQueryBenchmarkSink [3]map[string]struct{}

func BenchmarkInventoryRelations(b *testing.B) {
	for _, size := range [][3]int{{32, 32, 1}, {128, 32, 1}, {32, 128, 1}, {32, 32, 16}} {
		for _, mode := range []string{"matched", "no-match"} {
			entries, refs := inventoryRelationFixture(size[0], size[1], size[2], mode)
			name := fmt.Sprintf("T%d-Q%d-F%d/%s", size[0], size[1], size[2], mode)
			// Fixtures stand in for admitted input. All setup/combined variants
			// include three distinct query sets, already needed by build diagnostics.
			b.Run(name+"/query-set-preparation", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					inventoryQueryBenchmarkSink = [3]map[string]struct{}{mapSet(refs), mapSet(refs), mapSet(refs)}
				}
			})
			b.Run(name+"/setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					queries := [3]map[string]struct{}{mapSet(refs), mapSet(refs), mapSet(refs)}
					index := indexInventoryRelations(entries, queries[0], queries[1], queries[2])
					inventoryQueryBenchmarkSink = queries
					inventoryBenchmarkSink = len(index.byRequirement) + len(index.byOwnerInvariant) + len(index.byCommand)
				}
			})
			b.Run(name+"/baseline-with-setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					queries := [3]map[string]struct{}{mapSet(refs), mapSet(refs), mapSet(refs)}
					count := 0
					for kind := 0; kind < 3; kind++ {
						for _, ref := range refs {
							count += len(baselineInventoryRelation(entries, ref, kind))
						}
					}
					inventoryQueryBenchmarkSink = queries
					inventoryBenchmarkSink = count
				}
			})
			b.Run(name+"/indexed-with-setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					queries := [3]map[string]struct{}{mapSet(refs), mapSet(refs), mapSet(refs)}
					index := indexInventoryRelations(entries, queries[0], queries[1], queries[2])
					count := 0
					for _, ref := range refs {
						count += len(index.byRequirement[ref]) + len(index.byOwnerInvariant[ref]) + len(index.byCommand[ref])
					}
					inventoryQueryBenchmarkSink = queries
					inventoryBenchmarkSink = count
				}
			})
		}
	}
}
