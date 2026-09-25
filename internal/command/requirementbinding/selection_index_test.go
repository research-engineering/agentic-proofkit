package requirementbinding

import (
	"fmt"
	"reflect"
	"testing"
)

func selectionIndexFixture(requirements, paths, bindings int, mode string) Input {
	input := Input{}
	for i := 0; i < requirements; i++ {
		input.Requirements = append(input.Requirements, Requirement{RequirementID: fmt.Sprintf("REQ-%04d", i), OwnerID: fmt.Sprintf("owner.%04d", i), SpecPath: fmt.Sprintf("spec/%04d.json", i)})
	}
	for i := 0; i < bindings; i++ {
		input.Bindings = append(input.Bindings, Binding{RequirementID: input.Requirements[i%requirements].RequirementID, WitnessPath: fmt.Sprintf("test/%04d.go", i)})
	}
	if mode == "all" {
		return input
	}
	for i := 0; i < paths; i++ {
		input.Selection.ChangedPaths = append(input.Selection.ChangedPaths, fmt.Sprintf("missing/%04d.go", i))
	}
	if mode == "sparse" {
		input.Selection.ChangedPaths[paths-1] = input.Bindings[bindings-1].WitnessPath
	}
	if mode == "dense" || mode == "late-miss" {
		for _, requirement := range input.Requirements {
			input.Selection.RequirementIDs = append(input.Selection.RequirementIDs, requirement.RequirementID)
		}
		if mode == "late-miss" {
			input.Selection.RequirementIDs = input.Selection.RequirementIDs[:len(input.Selection.RequirementIDs)-1]
		}
	}
	return input
}

func TestSelectionIndexMatchesBaselineDomains(t *testing.T) {
	for _, mode := range []string{"all", "sparse", "dense", "no-match", "late-miss"} {
		for _, size := range [][3]int{{7, 3, 11}, {29, 3, 11}, {7, 17, 11}, {7, 3, 41}} {
			input := selectionIndexFixture(size[0], size[1], size[2], mode)
			index := indexRequirementSelection(input.Selection, input.Bindings)
			for _, requirement := range input.Requirements {
				if got, want := isSelectedRequirement(requirement, &index), baselineSelectedRequirement(requirement, input.Bindings, input.Selection); got != want {
					t.Fatalf("%s %v %s: indexed=%t baseline=%t", mode, size, requirement.RequirementID, got, want)
				}
			}
		}
	}
}

func TestEmptySelectionDoesNotBuildRelationMaps(t *testing.T) {
	input := selectionIndexFixture(16, 8, 128, "all")
	index := indexRequirementSelection(input.Selection, input.Bindings)
	if !index.all || index.requirementIDs != nil || index.ownerIDs != nil || index.changedPaths != nil {
		t.Fatalf("empty selection built indexes: %#v", index)
	}
	allocations := testing.AllocsPerRun(10, func() { _ = indexRequirementSelection(input.Selection, input.Bindings) })
	if allocations != 0 {
		t.Fatalf("empty selection allocated: %v", allocations)
	}
}

func selectionEarlyExitInput(mode string) Input {
	input := selectionIndexFixture(32, 8, 512, "dense")
	switch mode {
	case "empty-input":
		return Input{}
	case "all":
		input.Selection = Selection{}
	case "id-only":
		input.Selection.ChangedPaths = nil
	case "owner":
		input.Selection.RequirementIDs = nil
		for _, requirement := range input.Requirements {
			input.Selection.OwnerIDs = append(input.Selection.OwnerIDs, requirement.OwnerID)
		}
	case "spec":
		input.Selection.RequirementIDs = nil
		for _, requirement := range input.Requirements {
			input.Selection.ChangedPaths = append(input.Selection.ChangedPaths, requirement.SpecPath)
		}
	}
	return input
}

func TestSelectionEarlyExitsDoNotBuildRelationMaps(t *testing.T) {
	for _, mode := range []string{"empty-input", "all", "dense", "id-only", "owner", "spec"} {
		t.Run(mode, func(t *testing.T) {
			input := selectionEarlyExitInput(mode)
			index := indexRequirementSelection(input.Selection, input.Bindings)
			if index.requirementIDs != nil || index.ownerIDs != nil || index.changedPaths != nil {
				t.Error("constructor built unused relation maps")
			}
			for _, requirement := range input.Requirements {
				if !isSelectedRequirement(requirement, &index) || !baselineSelectedRequirement(requirement, input.Bindings, input.Selection) {
					t.Fatalf("early exit did not select %s", requirement.RequirementID)
				}
				if index.requirementIDs != nil || index.ownerIDs != nil || index.changedPaths != nil {
					t.Fatalf("early exit for %s built unused relation maps", requirement.RequirementID)
				}
			}
		})
	}
}

func TestSelectionEarlyExitQueryAllocations(t *testing.T) {
	for _, mode := range []string{"empty-input", "all", "dense", "id-only", "owner", "spec"} {
		t.Run(mode, func(t *testing.T) {
			input := selectionEarlyExitInput(mode)
			allocations := testing.AllocsPerRun(100, func() {
				index := indexRequirementSelection(input.Selection, input.Bindings)
				count := 0
				for _, requirement := range input.Requirements {
					if isSelectedRequirement(requirement, &index) {
						count++
					}
				}
				selectionBenchmarkSink = count
			})
			if selectionBenchmarkSink != len(input.Requirements) || allocations != 0 {
				t.Fatalf("construction plus queries: selected=%d want=%d allocations=%v want=0", selectionBenchmarkSink, len(input.Requirements), allocations)
			}
		})
	}
}

func TestSelectionDirectThenWitnessBuildsOnce(t *testing.T) {
	input := selectionParityInput()
	input.Selection = Selection{RequirementIDs: []string{"REQ-A"}, OwnerIDs: []string{"owner.d"}, ChangedPaths: []string{"spec/shared.json", "test/b.go"}}
	index := indexRequirementSelection(input.Selection, input.Bindings)
	if !isSelectedRequirement(input.Requirements[0], &index) {
		t.Fatal("first direct query was not selected")
	}
	if index.requirementIDs != nil || index.ownerIDs != nil || index.changedPaths != nil {
		t.Error("first direct query built unused relation maps")
	}
	if !isSelectedRequirement(input.Requirements[1], &index) {
		t.Fatal("second witness query was not selected")
	}
	if !reflect.DeepEqual(index.requirementIDs, map[string]struct{}{"REQ-A": {}, "REQ-B": {}}) ||
		!reflect.DeepEqual(index.ownerIDs, map[string]struct{}{"owner.d": {}}) ||
		!reflect.DeepEqual(index.changedPaths, map[string]struct{}{"test/b.go": {}, "spec/shared.json": {}}) {
		t.Fatalf("first witness query did not build the complete original maps: %#v", index)
	}
	identities := fmt.Sprintf("%p/%p/%p", index.requirementIDs, index.ownerIDs, index.changedPaths)
	for pass := 0; pass < 3; pass++ {
		for _, requirement := range input.Requirements {
			if got, want := isSelectedRequirement(requirement, &index), baselineSelectedRequirement(requirement, input.Bindings, input.Selection); got != want {
				t.Fatalf("reused query %s: selected=%t baseline=%t", requirement.RequirementID, got, want)
			}
		}
	}
	if got := fmt.Sprintf("%p/%p/%p", index.requirementIDs, index.ownerIDs, index.changedPaths); got != identities {
		t.Fatal("queries replaced initialized relation maps")
	}
	allocations := testing.AllocsPerRun(100, func() {
		count := 0
		for _, requirement := range input.Requirements {
			if isSelectedRequirement(requirement, &index) {
				count++
			}
		}
		selectionBenchmarkSink = count
	})
	if selectionBenchmarkSink != 4 || allocations != 0 {
		t.Fatalf("reused queries: selected=%d allocations=%v", selectionBenchmarkSink, allocations)
	}
}

func TestSelectionUnansweredQueryBuildsRelationMaps(t *testing.T) {
	for _, mode := range []string{"witness", "no-match", "no-bindings", "id-miss", "owner-miss"} {
		t.Run(mode, func(t *testing.T) {
			input := selectionParityInput()
			input.Selection.ChangedPaths = []string{"missing.go"}
			switch mode {
			case "witness":
				input.Selection.ChangedPaths = []string{"test/shared.go"}
			case "no-bindings":
				input.Bindings = nil
			case "id-miss":
				input.Selection = Selection{RequirementIDs: []string{"REQ-UNKNOWN"}}
			case "owner-miss":
				input.Selection = Selection{OwnerIDs: []string{"owner.unknown"}}
			}
			index := indexRequirementSelection(input.Selection, input.Bindings)
			if index.requirementIDs != nil || index.ownerIDs != nil || index.changedPaths != nil {
				t.Error("constructor built relation maps before the first query")
			}
			got := isSelectedRequirement(input.Requirements[0], &index)
			if got != (mode == "witness") || got != baselineSelectedRequirement(input.Requirements[0], input.Bindings, input.Selection) {
				t.Fatalf("unanswered query selected=%t", got)
			}
			if index.requirementIDs == nil || index.ownerIDs == nil || index.changedPaths == nil {
				t.Fatal("unanswered query did not initialize all relation maps")
			}
		})
	}
}

var selectionBenchmarkSink int

func BenchmarkSelectionRelations(b *testing.B) {
	for _, size := range [][3]int{{32, 8, 64}, {128, 8, 64}, {32, 64, 64}, {32, 8, 512}, {4096, 8, 64}} {
		for _, mode := range []string{"all", "sparse", "dense", "no-match", "late-miss"} {
			input := selectionIndexFixture(size[0], size[1], size[2], mode)
			name := fmt.Sprintf("R%d-C%d-B%d/%s", size[0], size[1], size[2], mode)
			b.Run(name+"/setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					index := indexRequirementSelection(input.Selection, input.Bindings)
					selectionBenchmarkSink = len(index.requirementIDs)
				}
			})
			b.Run(name+"/baseline", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					count := 0
					for _, requirement := range input.Requirements {
						if baselineSelectedRequirement(requirement, input.Bindings, input.Selection) {
							count++
						}
					}
					selectionBenchmarkSink = count
				}
			})
			b.Run(name+"/indexed-with-setup", func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					index := indexRequirementSelection(input.Selection, input.Bindings)
					count := 0
					for _, requirement := range input.Requirements {
						if isSelectedRequirement(requirement, &index) {
							count++
						}
					}
					selectionBenchmarkSink = count
				}
			})
		}
	}
}
