package requirementbrowser

import "testing"

func TestHandoffAnchorStructureMatchesProducedCoordinateIdentity(t *testing.T) {
	anchor := anchorValue(workspaceAnchor{
		AnchorID: "anchor.one", JSONPointer: "/requirements/REQ-ONE/invariant",
		RequirementID: "REQ-ONE", SourceID: "source.one", SourceDigest: "sha256:fixture",
	})
	if err := anchorShape.CheckGenerated(anchor, "handoff anchor"); err != nil {
		t.Fatal(err)
	}
	anchor["coordinateSpace"] = "source_wire"
	if err := anchorShape.CheckGenerated(anchor, "handoff anchor"); err == nil {
		t.Fatal("old source-wire coordinate space was admitted")
	}
	anchor["coordinateSpace"] = resolvedRequirementCoordinateSpace
	delete(anchor, "sourceId")
	if err := anchorShape.CheckGenerated(anchor, "handoff anchor"); err == nil {
		t.Fatal("handoff anchor lost source identity")
	}
}
