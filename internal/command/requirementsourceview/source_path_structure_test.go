package requirementsourceview

import "testing"

func TestSourceViewOutputStructureRejectsRetiredRequirementPath(t *testing.T) {
	shape := sourceViewShape
	path, ok := shape.Property("requirementsPath")
	if !ok {
		t.Fatal("source view output has no requirements path")
	}
	if _, err := path.Admit("docs/specs/a/requirements.v2.json", "path"); err != nil {
		t.Fatal(err)
	}
	if _, err := path.Admit("docs/specs/a/requirements.v1.json", "path"); err == nil {
		t.Fatal("retired source path remained in the published output structure")
	}
}
