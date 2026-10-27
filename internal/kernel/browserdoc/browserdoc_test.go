package browserdoc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestFilterAttributesPreserveEveryValueInCardsAndRows(t *testing.T) {
	values := []string{"overview", "requirements", "quote\" brackets[,] & <tag>", "\u03bb"}
	filters := []FilterValue{{Key: "source-role", Values: values}, {Key: "empty"}}
	output := HTML(Document{
		Cards: []Card{{ID: "node", Title: "Fixture", GroupID: "group", FilterValues: filters}},
		Table: &Table{Columns: []Column{{Key: "id", Label: "ID"}}, Rows: []Row{{Cells: []Cell{{Key: "id", Value: Code("node")}}, FilterValues: filters}}},
	})
	attributes := regexp.MustCompile(` data-filter-source-role="([^"]*)"`).FindAllStringSubmatch(output, -1)
	if len(attributes) != 2 || strings.Contains(output, " data-filter-empty=") {
		t.Fatalf("expected one value set per card/row and no empty-set attribute, got %d sets", len(attributes))
	}
	for _, attribute := range attributes {
		var decoded []string
		if err := json.Unmarshal([]byte(html.UnescapeString(attribute[1])), &decoded); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(decoded, values) {
			t.Fatalf("filter value set lost meaning: got %q, want %q", decoded, values)
		}
	}
}

func TestScriptHashSourceCommitsToExactEmittedBytes(t *testing.T) {
	source, err := os.ReadFile("browser.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []Document{
		{},
		{Title: "<script>different()</script>", Cards: []Card{{Body: Text("</script>")}}, Table: &Table{}},
	} {
		output := HTML(document)
		scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`).FindAllStringSubmatch(output, -1)
		if len(scripts) != 1 || scripts[0][1] != "" || scripts[0][2] != string(source) {
			t.Fatal("HTML must emit exactly the unchanged embedded script")
		}
		digest := sha256.Sum256([]byte(scripts[0][2]))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
		if got := ScriptHashSource(); got != want {
			t.Fatalf("script commitment=%q, want actual emitted bytes %q", got, want)
		}
		for _, changed := range []string{scripts[0][2] + "\n", "different()"} {
			other := sha256.Sum256([]byte(changed))
			if want == "'sha256-"+base64.StdEncoding.EncodeToString(other[:])+"'" {
				t.Fatal("script commitment admitted different bytes")
			}
		}
	}
}

// The token stylesheet is the embedded file byte for byte, and every page's
// only style element holds it followed by the static style.
func TestTokenStylesheetIsTheEmbeddedFileAndOpensTheOnlyStyle(t *testing.T) {
	source, err := os.ReadFile("tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	if TokenStylesheet() != string(source) || len(source) == 0 {
		t.Fatal("TokenStylesheet must return the exact bytes of tokens.css")
	}
	for _, document := range []Document{
		{},
		{Title: "<style>different</style>", Cards: []Card{{Body: Text("</style>")}}, Table: &Table{}},
	} {
		output := HTML(document)
		styles := regexp.MustCompile(`(?is)<style\b([^>]*)>(.*?)</style\s*>`).FindAllStringSubmatch(output, -1)
		if len(styles) != 1 || styles[0][1] != "" || styles[0][2] != string(source)+css() {
			t.Fatal("HTML must emit exactly one style element holding the token stylesheet and then the static style")
		}
	}
}

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
				Key:    `bad" onmouseover="x`,
				Values: []string{payload},
			}},
		}},
		Table: &Table{
			Columns: []Column{{Key: "value", Label: payload}},
			Rows: []Row{{
				Cells:        []Cell{{Key: "value", Value: Text(payload)}},
				SearchText:   payload,
				FilterValues: []FilterValue{{Key: `bad" onmouseover="x`, Values: []string{payload}}},
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
			{ID: "REQ-2", Title: "Second", GroupID: "group", GroupLabel: "Group", Body: Text("body"), SearchText: "second", FilterValues: []FilterValue{{Key: "owner", Values: []string{"b"}}}},
			{ID: "REQ-1", Title: "First", GroupID: "group", GroupLabel: "Group", Body: Text("body"), SearchText: "first", FilterValues: []FilterValue{{Key: "owner", Values: []string{"a"}}}},
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

// An in-page link and its anchored target derive from one key through
// FragmentID, so caller text never reaches the id or href attribute.
func TestInPageLinksResolveToTheirAnchoredDetails(t *testing.T) {
	key := `scenario:"<a&b>`
	target := AnchoredDetails(key, "<summary> & text", Text("body")).html
	links := InPageLinkListOrNone([]InPageLink{{Label: "<b>SCN</b>", TargetKey: key}}).html
	id := FragmentID(key)
	if !strings.HasPrefix(target, `<details id="`+id+`"><summary>&lt;summary&gt; &amp; text</summary>`) {
		t.Fatalf("anchored details = %q", target)
	}
	if links != `<ul><li><a href="#`+id+`"><code>&lt;b&gt;SCN&lt;/b&gt;</code></a></li></ul>` || safeHref("#"+id) != "#"+id {
		t.Fatalf("in-page links = %q", links)
	}
	if InPageLinkListOrNone(nil).html != ListOrNone(nil, true).html {
		t.Fatal("an empty link list must render like an empty code list")
	}
	if strings.TrimPrefix(target, `<details id="`+id+`">`) != strings.TrimPrefix(Details("<summary> & text", Text("body")).html, "<details>") {
		t.Fatal("anchored details must differ from details only by the id")
	}
}

// A status badge always names its state in text; the state only selects the
// tone, and a state outside the tone table gets the neutral info tone.
func TestStatusNamesTheStateInTextAndSelectsAClosedTone(t *testing.T) {
	for value, want := range map[string]string{
		"passed":         `<span class="status-badge" data-status="passed">passed</span>`,
		"failed":         `<span class="status-badge" data-status="failed">failed</span>`,
		"blocked":        `<span class="status-badge" data-status="blocked">blocked</span>`,
		"warning":        `<span class="status-badge" data-status="warning">warning</span>`,
		"witness_backed": `<span class="status-badge" data-status="info">witness_backed</span>`,
		"Failed":         `<span class="status-badge" data-status="info">Failed</span>`,
		"<b>&\"":         `<span class="status-badge" data-status="info">&lt;b&gt;&amp;&#34;</span>`,
	} {
		if got := Status(value).html; got != want {
			t.Errorf("Status(%q) = %s, want %s", value, got, want)
		}
	}
}

func TestTableCellsBreakOnlyAtSeparatorsAndLongRuns(t *testing.T) {
	hash := "bef7043a7ad46d3a65098986129e4e6208af005ff8cc3a6b9d08d6616a303fa0"
	for fragment, want := range map[string]string{
		"REQ-BROWSER-COVERAGE-001":                      "REQ-<wbr>BROWSER-<wbr>COVERAGE-001",
		"<code>test.browser.coverage.semantic</code>":   "<code>test.<wbr>browser.<wbr>coverage.<wbr>semantic</code>",
		"mapped_to_declared_route":                      "mapped_<wbr>to_<wbr>declared_<wbr>route",
		"go test ./internal/command/requirementbrowser": "go test ./<wbr>internal/<wbr>command/<wbr>requirementbrowser",
		"browser_coverage_test.go::falsification":       "browser_<wbr>coverage_<wbr>test.<wbr>go::<wbr>falsification",
		`<a href="#a.b-c"><code>x.y</code></a>`:         `<a href="#a.b-c"><code>x.<wbr>y</code></a>`,
		"a.&lt;b &amp;b.c":                              "a.&lt;b &amp;b.<wbr>c",
		"1.5 v2.json 0.17.0":                            "1.5 v2.<wbr>json 0.17.0",
		"\u03a9.\u0394":                                 "\u03a9.<wbr>\u0394",
		"sha256:" + hash:                                "sha256:<wbr>" + hash[0:12] + "<wbr>" + hash[12:24] + "<wbr>" + hash[24:36] + "<wbr>" + hash[36:48] + "<wbr>" + hash[48:60] + "<wbr>" + hash[60:],
		strings.Repeat("a", 24):                         strings.Repeat("a", 24),
		strings.Repeat("a", 25):                         strings.Repeat("a", 12) + "<wbr>" + strings.Repeat("a", 12) + "<wbr>a",
		strings.Repeat("a", 36):                         strings.Repeat("a", 12) + "<wbr>" + strings.Repeat("a", 12) + "<wbr>" + strings.Repeat("a", 12),
		"<ul><li>a.b</li></ul>":                         "<ul><li>a.<wbr>b</li></ul>",
		"":                                              "",
	} {
		if got := breakOpportunities(fragment); got != want {
			t.Errorf("breakOpportunities(%q) = %q, want %q", fragment, got, want)
		}
	}
	// Only table cells carry the break opportunities; headings, cards and
	// summaries render their text unchanged.
	output := HTML(Document{
		Title:        "a.b",
		SummaryItems: []SummaryItem{Summary("x.y", "p.q", true)},
		Cards:        []Card{{ID: "c.d", Title: "e.f", Body: Code("g.h")}},
		Table:        &Table{Columns: []Column{{Key: "v", Label: "k.l"}}, Rows: []Row{{Cells: []Cell{TableCell("v", "m.n", true)}}}},
	})
	if got := strings.Count(output, "<wbr>"); got != 1 || !strings.Contains(output, "<td><code>m.<wbr>n</code></td>") {
		t.Fatalf("rendered HTML holds %d break opportunities, want exactly the table cell's:\n%s", got, output)
	}
}
