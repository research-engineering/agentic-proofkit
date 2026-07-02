package browserdoc

import (
	"strings"
	"testing"
)

func TestHTMLUsesTypedFragmentsAndEscapesCallerText(t *testing.T) {
	payload := `<script>alert(1)</script><img src=x onerror=alert(1)>`
	output := HTML(Document{
		Title:     payload,
		Authority: "presentation_only",
		SummaryItems: []SummaryItem{
			Summary("Summary", payload, false),
			Summary("Code", "docs/evil<script>.json", true),
		},
		HierarchySections: []HierarchySection{{
			Title: payload,
			Items: []HierarchyItem{{Label: payload, Detail: payload, Href: "javascript:alert(1)"}},
		}},
		Filters: []Filter{NewFilter(`bad" onmouseover="x`, "Unsafe filter", []string{payload})},
		Cards: []Card{{
			ID:         "REQ-1",
			Title:      payload,
			GroupID:    "a.b",
			GroupLabel: payload,
			Body: DefinitionList(
				Definition("Text", Text(payload)),
				Definition("Code", Code(payload)),
				Definition("List", ListOrNone([]string{payload}, false)),
			),
			SearchText: payload,
			FilterValues: []FilterValue{{
				Key:   `bad" onmouseover="x`,
				Value: payload,
			}},
		}},
		Table: &Table{
			Columns: []Column{{Key: "value", Label: payload}},
			Rows: []Row{{
				Cells:        []Cell{{Key: "value", Value: Text(payload)}},
				SearchText:   payload,
				FilterValues: []FilterValue{{Key: `bad" onmouseover="x`, Value: payload}},
			}},
		},
		ExportFiles: []ExportFile{Export("HTML", "../unsafe/<script>.html", payload)},
		NonClaims:   []string{payload},
	})
	for _, forbidden := range []string{
		"<script>alert(1)</script>",
		"<img src=x",
		"javascript:alert",
		`onmouseover=`,
		`../unsafe`,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("HTML output contains unsafe payload %q:\n%s", forbidden, output)
		}
	}
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"data-filter-invalid-filter-key-",
		"data-download-file=\"unsafe-script-.html\"",
		"data-proofkit-download",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("HTML output missing %q:\n%s", want, output)
		}
	}
}

func TestFragmentIDPreventsSanitizedAnchorCollisions(t *testing.T) {
	left := FragmentID("module.a")
	right := FragmentID("module-a")
	if left == right {
		t.Fatalf("FragmentID collision: %s", left)
	}
	if again := FragmentID("module.a"); again != left {
		t.Fatalf("FragmentID not stable: %s != %s", again, left)
	}
}

func TestSafeFileNameRejectsPathSemantics(t *testing.T) {
	cases := map[string]string{
		"../module.html":         "module.html",
		"..":                     "proofkit-rendered-view",
		"docs/spec tree/view.md": "docs-spec-tree-view.md",
		`docs\spec<script>.html`: "docs-spec-script-.html",
	}
	for input, want := range cases {
		if got := SafeFileName(input); got != want {
			t.Fatalf("SafeFileName(%q)=%q want %q", input, got, want)
		}
	}
}

func TestHTMLIsByteStable(t *testing.T) {
	document := Document{
		Title:     "Stable",
		Authority: "presentation_only",
		Filters:   []Filter{NewFilter("owner", "Owner", []string{"b", "a", "a"})},
		Cards: []Card{
			{ID: "REQ-2", Title: "Second", GroupID: "group", GroupLabel: "Group", Body: Text("body"), SearchText: "second", FilterValues: []FilterValue{{Key: "owner", Value: "b"}}},
			{ID: "REQ-1", Title: "First", GroupID: "group", GroupLabel: "Group", Body: Text("body"), SearchText: "first", FilterValues: []FilterValue{{Key: "owner", Value: "a"}}},
		},
		NonClaims: []string{"Presentation only."},
	}
	if left, right := HTML(document), HTML(document); left != right {
		t.Fatalf("HTML output is not byte-stable")
	}
}

func TestCardGroupsUseTotalOrderingWhenLabelsMatch(t *testing.T) {
	document := Document{
		Title:     "Stable groups",
		Authority: "presentation_only",
		Cards: []Card{
			{ID: "REQ-2", Title: "Second", GroupID: "zeta", GroupLabel: "Same", Body: Text("body"), SearchText: "second"},
			{ID: "REQ-1", Title: "First", GroupID: "alpha", GroupLabel: "Same", Body: Text("body"), SearchText: "first"},
		},
	}
	output := HTML(document)
	left := strings.Index(output, `id="proofkit-alpha-`)
	right := strings.Index(output, `id="proofkit-zeta-`)
	if left < 0 || right < 0 || left > right {
		t.Fatalf("card groups are not sorted by label then stable group id:\n%s", output)
	}
}
