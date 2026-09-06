package browserfixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
)

func TestLookupWorkspacePreservesFullCohortAndHierarchy(t *testing.T) {
	workspace, err := LookupWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := requirementcontext.AdmitSnapshot(workspace["context"])
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tree.Nodes) != 517 || len(snapshot.Tree.Edges) != 516 || len(snapshot.RequirementSources) != 3 || len(snapshot.RequirementSources[1].Requirements) != 130 {
		t.Fatal("lookup fixture lost its independent cohort or hierarchy")
	}
}

func TestCapacityWorkspaceReachesTheAdmittedNodeCeiling(t *testing.T) {
	workspace, err := CapacityWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := requirementcontext.AdmitSnapshot(workspace["context"])
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tree.Nodes) != 4096 || len(snapshot.Tree.Edges) != 4095 || len(snapshot.RequirementSources) != 3 || len(snapshot.RequirementSources[1].Requirements) != 130 {
		t.Fatal("capacity fixture lost its maximum topology or independent source cohort")
	}
}
