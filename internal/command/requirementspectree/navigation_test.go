package requirementspectree

import (
	"encoding/json"
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"
)

func TestTreeHierarchyResolvesEachNamedNode(t *testing.T) {
	input := validTreeInput()
	input["nodes"] = append(input["nodes"].([]any), nodeRecord("module.second", "module_spec", "Second module", 2, sourceIDRef("source.second", "spec.second")))
	input["edges"] = append(input["edges"].([]any), map[string]any{"parentNodeId": "meta", "childNodeId": "module.second"})
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	rendered, exit, err := BuildViewHTML(input)
	if err != nil || exit != 0 {
		t.Fatalf("render: exit=%d error=%v", exit, err)
	}
	document, err := nethtml.Parse(strings.NewReader(rendered))
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string]*nethtml.Node{}
	links := map[string]string{}
	for node := range document.Descendants() {
		if node.Type != nethtml.ElementNode {
			continue
		}
		for _, attribute := range node.Attr {
			if attribute.Key == "id" {
				if anchors[attribute.Val] != nil {
					t.Fatalf("duplicate DOM ID %q", attribute.Val)
				}
				anchors[attribute.Val] = node
			}
			if node.Data == "a" && attribute.Key == "href" && node.FirstChild != nil {
				links[strings.TrimSpace(node.FirstChild.Data)] = strings.TrimPrefix(attribute.Val, "#")
			}
		}
	}
	for label, id := range map[string]string{"Module specification": "module", "Second module": "module.second"} {
		target := anchors[links[label]]
		if target == nil || target.Data != "article" {
			t.Fatalf("node %q must target its own record, got fragment %q", label, links[label])
		}
		var recordID string
		for element := range target.Descendants() {
			for _, attribute := range element.Attr {
				if attribute.Key == "class" && attribute.Val == "proofkit-id" && element.FirstChild != nil {
					recordID = element.FirstChild.Data
				}
			}
		}
		if recordID != id {
			t.Fatalf("node %q targets record %q, want %q", label, recordID, id)
		}
	}
	if links["Module specification"] == links["Second module"] {
		t.Fatal("sibling nodes must not share a group destination")
	}
	after, err := json.Marshal(input)
	if err != nil || string(before) != string(after) {
		t.Fatal("view rendering changed caller input")
	}
}
