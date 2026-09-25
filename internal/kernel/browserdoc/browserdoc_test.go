package browserdoc

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestSearchTextPreservesOriginalUnicodeAndCase(t *testing.T) {
	values := []string{"\u039f\u0394\u039f\u03a3", "\u0130stanbul", "ASCII", "Cafe\u0301", `<script>"&`}
	want := strings.Join(values, " ")
	if got := SearchText(values); got != want {
		t.Fatalf("SearchText changed original text: got %q want %q", got, want)
	}
	output := HTML(Document{
		Cards: []Card{{SearchText: want}},
		Table: &Table{Rows: []Row{{SearchText: want}}},
	})
	if got := strings.Count(output, `data-search="`+Escape(want)+`"`); got != 2 {
		t.Fatalf("card and table must preserve escaped original search text; got %d copies", got)
	}
}

func TestFragmentIDRetainsExactKeyIdentity(t *testing.T) {
	keys := []string{"", "module.a", "module-a", "A", "a", " a ", "\u00e9", "e\u0301", "\u039f\u0394\u039f\u03a3", "\U0001f680", `\"<>&/#?`, strings.Repeat("long/", 1000)}
	seen := map[string]string{}
	for _, key := range keys {
		id := FragmentID(key)
		if !regexp.MustCompile(`^proofkit-[A-Za-z0-9_-]*$`).MatchString(id) || safeHref("#"+id) != "#"+id {
			t.Fatalf("unsafe fragment for %q: %q", key, id)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "proofkit-"))
		if err != nil || string(decoded) != key {
			t.Fatalf("fragment does not roundtrip exact key %q: %q, %v", key, decoded, err)
		}
		if previous, exists := seen[id]; exists {
			t.Fatalf("distinct keys share fragment: %q and %q", previous, key)
		}
		seen[id] = key
		if FragmentID(key) != id {
			t.Fatal("equal inputs must retain identical fragments")
		}
	}
}

func TestFragmentIDSeparatesConcreteFNVCollisionAndHierarchyTargets(t *testing.T) {
	keys := []string{strings.Repeat("a", 64) + "c505dab8819802af", strings.Repeat("a", 64) + "23792f9a63c822bf"}
	if stableSuffix(keys[0]) != "a17402fc" || stableSuffix(keys[1]) != "a17402fc" {
		t.Fatal("fixture must retain the concrete legacy FNV collision")
	}
	if FragmentID(keys[0]) == FragmentID(keys[1]) {
		t.Fatalf("distinct keys collide: %s", FragmentID(keys[0]))
	}
	document := Document{HierarchySections: []HierarchySection{{Title: "Groups"}}}
	for _, key := range keys {
		document.Cards = append(document.Cards, Card{GroupID: key, GroupLabel: "Same label"})
		document.HierarchySections[0].Items = append(document.HierarchySections[0].Items, HierarchyItem{Label: key, Href: "#" + FragmentID(key)})
	}
	output := HTML(document)
	for _, key := range keys {
		id := FragmentID(key)
		if strings.Count(output, `id="`+id+`"`) != 1 || strings.Count(output, `href="#`+id+`"`) != 1 {
			t.Fatalf("hierarchy key %q must resolve to exactly one target", key)
		}
	}
	if HTML(document) != output {
		t.Fatal("full links must be deterministic")
	}
}

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
	left := strings.Index(output, `id="`+FragmentID("alpha")+`"`)
	right := strings.Index(output, `id="`+FragmentID("zeta")+`"`)
	if left < 0 || right < 0 || left > right {
		t.Fatalf("card groups are not sorted by label then stable group id:\n%s", output)
	}
}
