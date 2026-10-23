package browserfixture

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
)

// The committed README project is a complete admitted project for the same
// project path the view command uses.
func TestReadmeProjectMaterializesAnAdmittedViewProject(t *testing.T) {
	directory := t.TempDir()
	if err := MaterializeReadmeProject(directory); err != nil {
		t.Fatal(err)
	}
	plan, exit, err := requirementbrowser.BuildProjectPlan(t.Context(), directory, requirementbrowser.Options{})
	if err != nil || exit != 0 {
		t.Fatalf("README project plan exit=%d err=%v", exit, err)
	}
	if plan["view"] != "workspace" || plan["renderedViewKind"] != "proofkit.requirement-workspace" || plan["renderedAuthority"] != "presentation_adapter" {
		t.Fatalf("README project plan lost its project workspace: view=%v kind=%v authority=%v", plan["view"], plan["renderedViewKind"], plan["renderedAuthority"])
	}
}
