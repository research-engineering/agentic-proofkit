package requirementcoverageview

import (
	"slices"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
)

func TestCoverageStateLedgerExactlyCoversEvidenceVocabulary(t *testing.T) {
	classes := make([]string, 0, len(coverageStateDescriptors))
	requirementStates := map[string]struct{}{}
	requirementPriorities := map[int]struct{}{}
	for _, descriptor := range coverageStateDescriptors {
		if _, duplicate := requirementStates[descriptor.requirementState]; duplicate {
			t.Fatalf("duplicate requirement coverage state %q", descriptor.requirementState)
		}
		requirementStates[descriptor.requirementState] = struct{}{}
		if descriptor.evidenceClass == "" {
			continue
		}
		classes = append(classes, descriptor.evidenceClass)
		if _, duplicate := requirementPriorities[descriptor.requirementPriority]; duplicate {
			t.Fatalf("duplicate evidence requirement priority %d", descriptor.requirementPriority)
		}
		requirementPriorities[descriptor.requirementPriority] = struct{}{}
		if !descriptor.requirementAdmissible || !descriptor.ownerInvariantAdmissible || descriptor.commandState == "" {
			t.Fatalf("evidence class %q lacks a complete coverage projection", descriptor.evidenceClass)
		}
	}
	sort.Strings(classes)
	if want := testevidenceinventory.EvidenceClasses(); !slices.Equal(classes, want) {
		t.Fatalf("coverage evidence classes=%v, want inventory-owned vocabulary %v", classes, want)
	}
}
