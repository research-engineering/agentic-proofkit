package browserdoc

import (
	"strings"
	"testing"

	nethtml "golang.org/x/net/html"
)

func TestCardAnchorIsOptionalAndEscaped(t *testing.T) {
	card := Card{ID: "record", Title: "Name", SearchText: "find", Body: Text("Body")}
	want := "<article class=\"card\" data-proofkit-card data-search=\"find\">\n<h2><span class=\"proofkit-id\">record</span><span class=\"proofkit-title\">Name</span></h2>\nBody\n</article>"
	if got := browserCard(card); got != want {
		t.Fatalf("unanchored card changed: %s", got)
	}
	card.AnchorID = "quoted\" & <tag>"
	output := browserCard(card)
	document, err := nethtml.Parse(strings.NewReader(output))
	if err != nil {
		t.Fatal(err)
	}
	var article *nethtml.Node
	for node := range document.Descendants() {
		if node.Type == nethtml.ElementNode && node.Data == "article" {
			if article != nil {
				t.Fatal("anchor text introduced another article")
			}
			article = node
		}
		if node.Type == nethtml.ElementNode && (node.Data == "tag" || node.Data == "script") {
			t.Fatal("anchor text became markup")
		}
	}
	if article == nil {
		t.Fatal("card article is missing")
	}
	var anchor string
	for _, attribute := range article.Attr {
		if attribute.Key == "id" {
			anchor = attribute.Val
		}
	}
	if anchor != card.AnchorID || strings.Contains(output, `id="quoted" & <tag>"`) {
		t.Fatal("anchor did not preserve its escaped attribute value")
	}
}
