package requirementsourceview

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

func declaredSourceFixture() map[string]any {
	input := validRequirementSource()
	group := input["groups"].([]any)[0].(map[string]any)
	group["statementStem"] = "The renderer must"
	group["sharedPremises"] = []any{"The caller selected this source."}
	first := viewTestMember(input)
	first["statementCompletion"] = "preserve groups."
	second := viewTestMember(validRequirementSource())
	second["requirementId"], second["statementCompletion"] = "REQ-PROOFKIT-VIEW-002", "preserve declared scenarios."
	group["members"] = []any{first, second}
	input["nonClaimDefinitions"] = []any{map[string]any{"nonClaimId": "NCL-VIEW", "statement": "Source declarations are not executed evidence."}}
	input["sourceNonClaimRefs"] = []any{"NCL-VIEW"}
	input["vocabulary"] = []any{map[string]any{"termId": "TERM-VIEW", "kind": "subject", "label": "Renderer <input>", "definition": "The caller's <script> vocabulary stays text."}}
	input["scenarios"] = []any{map[string]any{
		"scenarioId": "SCN-VIEW", "requirementIds": []any{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"},
		"parameters": []any{"surface"}, "preconditions": []any{"The ${surface} view is open."},
		"actionSequence":       []any{"Submit Z first.", "Inspect A second."},
		"expectedObservations": []any{"The value remains <input>."}, "forbiddenObservations": []any{"The source becomes execution proof."},
		"examples": []any{
			map[string]any{"exampleId": "EX-VIEW-1", "values": map[string]any{"surface": "primary <input>"}},
			map[string]any{"exampleId": "EX-VIEW-2", "values": map[string]any{"surface": "secondary"}},
		},
		"vocabularyRefs": []any{"TERM-VIEW"}, "nonClaimRefs": []any{"NCL-VIEW"},
	}}
	input["derivations"] = []any{map[string]any{
		"derivationId": "DRV-VIEW", "sourceKind": "owner_decision",
		"sourceRef": map[string]any{"objectFormat": "sha1", "commitOid": strings.Repeat("a", 40), "path": "docs/decisions/view.md", "sha256": strings.Repeat("b", 64)},
		"selector":  map[string]any{"start": "7", "end": "19"}, "requirementIds": []any{"REQ-PROOFKIT-VIEW-002"}, "nonClaimRefs": []any{"NCL-VIEW"},
	}}
	return input
}

func TestCompleteSourceViewPreservesDeclarationsAndGroupMembership(t *testing.T) {
	input := declaredSourceFixture()
	output, exit, err := BuildJSON(input)
	if err != nil || exit != 0 {
		t.Fatalf("source declarations: %v, %d", err, exit)
	}
	view := output.(map[string]any)
	for _, key := range []string{"vocabulary", "scenarios", "derivations", "nonClaimDefinitions", "sourceNonClaimRefs"} {
		if !reflect.DeepEqual(view[key], input[key]) {
			t.Fatalf("complete declaration fields changed: %s", key)
		}
	}
	wantGroups := []any{map[string]any{"groupId": "RGRP-VIEW", "statementStem": "The renderer must", "sharedPremises": []any{"The caller selected this source."}, "requirementIds": []any{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"}}}
	if !reflect.DeepEqual(view["groups"], wantGroups) {
		t.Fatal("group index changed membership, context or identity")
	}
	rows := view["requirements"].([]any)
	if len(rows) != 2 || rows[0].(map[string]any)["invariant"] != "The renderer must preserve groups." || rows[1].(map[string]any)["invariant"] != "The renderer must preserve declared scenarios." {
		t.Fatal("group view weakened complete atomic requirements")
	}
	sections := sourceDeclarationSections(view)
	want := []declarationRecord{{"DRV-VIEW", []declarationField{
		{"Source kind", []string{"owner_decision"}, true},
		{"Object format", []string{"sha1"}, true},
		{"Commit OID", []string{strings.Repeat("a", 40)}, true},
		{"Path", []string{"docs/decisions/view.md"}, true},
		{"SHA-256", []string{strings.Repeat("b", 64)}, true},
		{"Selector start", []string{"7"}, true},
		{"Selector end", []string{"19"}, true},
		{"Requirements", []string{"REQ-PROOFKIT-VIEW-002"}, true},
		{"Source-local non-claim refs", []string{"NCL-VIEW"}, true},
	}}}
	if !reflect.DeepEqual(sections[3].records, want) {
		t.Fatal("derivation human projection lost coordinates or roles")
	}
	byRequirement := scenariosByRequirement(view)
	for _, requirementID := range []string{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"} {
		if linked := byRequirement[requirementID]; !reflect.DeepEqual(linked.linkedIDs, []string{"SCN-VIEW"}) || len(linked.nested) != 0 {
			t.Fatalf("%s scenarios = %+v, want the shared scenario listed by ID only", requirementID, linked)
		}
	}
	if sections[2].title != "Shared Scenarios" || !sections[2].linkTargets || len(sections[2].records) != 1 || !reflect.DeepEqual(sections[2].records[0].fields, []declarationField{
		{"Requirements", []string{"REQ-PROOFKIT-VIEW-001", "REQ-PROOFKIT-VIEW-002"}, true},
		{"Parameters", []string{"surface"}, true},
		{"Preconditions", []string{"The ${surface} view is open."}, false},
		{"Action sequence", []string{"1. Submit Z first.", "2. Inspect A second."}, false},
		{"Expected observations", []string{"The value remains <input>."}, false},
		{"Forbidden observations", []string{"The source becomes execution proof."}, false},
		{"Vocabulary references", []string{"TERM-VIEW"}, true},
		{"Source-local non-claim refs", []string{"NCL-VIEW"}, true},
		{"Example EX-VIEW-1", []string{"surface: primary <input>"}, false},
		{"Example EX-VIEW-2", []string{"surface: secondary"}, false},
	}) {
		t.Fatal("scenario human projection lost a field, example parameter or action order")
	}
	if !reflect.DeepEqual(view["scenarios"], input["scenarios"]) {
		t.Fatal("formatting action ordinals mutated canonical scenario values")
	}
	input["vocabulary"].([]any)[0].(map[string]any)["label"] = "Changed caller input."
	if view["vocabulary"].([]any)[0].(map[string]any)["label"] != "Renderer <input>" {
		t.Fatal("view aliases untrusted caller input")
	}
}

func TestSourceDeclarationRenderersRetainFieldsAndEscapeText(t *testing.T) {
	input := declaredSourceFixture()
	for name, render := range map[string]func(any) (string, int, error){"markdown": BuildMarkdown, "html": BuildHTML} {
		document, exit, err := render(input)
		if err != nil || exit != 0 {
			t.Fatalf("%s: %v", name, err)
		}
		for _, required := range []string{"Source Groups", "Vocabulary", "Scenarios", "Declared Derivations", "RGRP-VIEW", "TERM-VIEW", "SCN-VIEW", "EX-VIEW", "DRV-VIEW", "NCL-VIEW", "Selector start", "Selector end", "Submit Z first", "Inspect A second", "primary &lt;input&gt;", strings.Repeat("a", 40), strings.Repeat("b", 64)} {
			if !strings.Contains(document, required) && !(name == "markdown" && strings.Contains(document, strings.ReplaceAll(required, "-", `\-`))) {
				t.Fatalf("%s omitted %q", name, required)
			}
		}
		if strings.Contains(document, "<input>") || strings.Contains(document, "<script> vocabulary") {
			t.Fatalf("%s admitted raw caller markup", name)
		}
		if strings.Index(document, "Submit Z first") >= strings.Index(document, "Inspect A second") {
			t.Fatal("ordered actions were sorted")
		}
		if name == "html" {
			for _, key := range []string{"source-group:RGRP-VIEW", "scenario:SCN-VIEW"} {
				anchor := browserdoc.FragmentID(key)
				if strings.Count(document, `id="`+anchor+`"`) != 1 || !strings.Contains(document, `href="#`+anchor+`"`) {
					t.Fatalf("in-page navigation to %s does not resolve to one target", key)
				}
			}
		}
	}
}

func TestSourceViewAbsentDeclarationsAreExplicitEmptyArrays(t *testing.T) {
	output, exit, err := BuildJSON(validRequirementSource())
	if err != nil || exit != 0 {
		t.Fatal(err)
	}
	view := output.(map[string]any)
	for _, key := range []string{"vocabulary", "scenarios", "derivations", "nonClaimDefinitions", "sourceNonClaimRefs"} {
		if !reflect.DeepEqual(view[key], []any{}) {
			t.Fatalf("absent %s did not project as an empty array", key)
		}
	}
}

// Every requirement lists all its scenarios by ID. A scenario's full record
// renders exactly once: under its requirement when it links to exactly one,
// otherwise in the shared scenarios section. HTML links each listed ID to that
// record in the page.
func TestSourceRenderersNestSingleRequirementScenariosAndListSharedOnes(t *testing.T) {
	input := declaredSourceFixture()
	input["scenarios"] = append([]any{map[string]any{
		"scenarioId": "SCN-ONLY", "requirementIds": []any{"REQ-PROOFKIT-VIEW-001"}, "parameters": []any{},
		"preconditions": []any{"The source is admitted."}, "actionSequence": []any{"Open the only requirement."},
		"expectedObservations": []any{"Only one requirement shows this record."}, "forbiddenObservations": []any{},
		"examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
	}}, input["scenarios"].([]any)...)
	markdown, _, err := BuildMarkdown(input)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(markdown, "### REQ-PROOFKIT-VIEW-001")
	second := strings.Index(markdown, "### REQ-PROOFKIT-VIEW-002")
	declarations := strings.Index(markdown, "## Named Source Boundaries")
	if first < 0 || second < first || declarations < second {
		t.Fatalf("requirement sections not found in order: %d %d %d", first, second, declarations)
	}
	if section := markdown[first:second]; !strings.Contains(section, "Scenarios:\n\n- `SCN-ONLY`\n- `SCN-VIEW`\n\n#### SCN\\-ONLY") || strings.Contains(section, "SCN\\-VIEW") {
		t.Fatalf("first requirement must list both scenarios and nest only its own:\n%s", section)
	}
	if section := markdown[second:declarations]; !strings.Contains(section, "Scenarios:\n\n- `SCN-VIEW`\n\n") || strings.Contains(section, "####") {
		t.Fatalf("second requirement must list the shared scenario without its record:\n%s", section)
	}
	shared := strings.Index(markdown, "## Shared Scenarios")
	if shared < declarations || !strings.Contains(markdown[shared:], "### SCN\\-VIEW") {
		t.Fatal("the shared scenario record is not in the shared scenarios section")
	}
	for _, record := range []string{markdownfmt.Text("Only one requirement shows this record."), markdownfmt.Text("The source becomes execution proof."), "SCN\\-ONLY\n", "SCN\\-VIEW\n"} {
		if strings.Count(markdown, record) != 1 {
			t.Fatalf("Markdown renders %q %d times, want once", record, strings.Count(markdown, record))
		}
	}

	html, _, err := BuildHTML(input)
	if err != nil {
		t.Fatal(err)
	}
	only, view := browserdoc.FragmentID("scenario:SCN-ONLY"), browserdoc.FragmentID("scenario:SCN-VIEW")
	cards := map[string]string{}
	for _, card := range strings.Split(html, "<article class=\"card\"")[1:] {
		card, _, _ = strings.Cut(card, "</article>")
		id, _, _ := strings.Cut(card[strings.Index(card, "proofkit-id\">")+len("proofkit-id\">"):], "<")
		cards[id] = card
	}
	link := func(anchor, label string) string {
		return `<li><a href="#` + anchor + `"><code>` + label + `</code></a></li>`
	}
	if card := cards["REQ-PROOFKIT-VIEW-001"]; !strings.Contains(card, "<h3>Scenarios</h3>\n<ul>"+link(only, "SCN-ONLY")+link(view, "SCN-VIEW")+"</ul>") || !strings.Contains(card, `<details id="`+only+`"><summary>SCN-ONLY</summary>`) || strings.Contains(card, `id="`+view+`"`) {
		t.Fatal("first card must link both scenarios and hold only its own record")
	}
	if card := cards["REQ-PROOFKIT-VIEW-002"]; !strings.Contains(card, "<h3>Scenarios</h3>\n<ul>"+link(view, "SCN-VIEW")+"</ul>") || strings.Contains(card, "<details") {
		t.Fatal("second card must link the shared scenario without its record")
	}
	summary, _, _ := strings.Cut(html[strings.Index(html, "<section class=\"summary\""):], "</section>")
	if !strings.Contains(summary, "<dt>Shared Scenarios</dt><dd><details id=\""+view+"\"><summary>SCN-VIEW</summary>") {
		t.Fatal("the shared scenario record must be a link target outside a collapsed wrapper")
	}
	for _, text := range []string{"Only one requirement shows this record.", "The source becomes execution proof.", `id="` + only + `"`, `id="` + view + `"`} {
		if strings.Count(html, text) != 1 {
			t.Fatalf("HTML renders %q %d times, want once", text, strings.Count(html, text))
		}
	}
	if strings.Contains(html, "Declared Scenarios") || strings.Contains(markdown, "Declared Scenarios") {
		t.Fatal("scenarios are still listed apart from their requirements")
	}
	plain, _, err := BuildMarkdown(validRequirementSource())
	if err != nil || !strings.Contains(plain, "Scenarios:\n\nNone.\n") {
		t.Fatal("a requirement without scenarios must state None")
	}
}

// One scenario linked to N requirements renders its record once; each further
// linked requirement adds its own section plus the scenario and requirement
// IDs, never another copy of the scenario, so rendered size is affine in N and
// independent of the scenario's text size per link.
func TestSourceRenderersGrowByIDsPerLinkedRequirement(t *testing.T) {
	const scenarioID = "SCN-BULKY"
	observation := "The bulky observation renders once." + strings.Repeat(" word", 64<<10/5)
	source := func(requirements int, linked bool) map[string]any {
		input := validRequirementSource()
		members, ids := []any{}, []any{}
		for index := range requirements {
			member := viewTestMember(validRequirementSource())
			member["requirementId"] = fmt.Sprintf("REQ-PROOFKIT-VIEW-%03d", index+1)
			members, ids = append(members, member), append(ids, member["requirementId"])
		}
		input["groups"].([]any)[0].(map[string]any)["members"] = members
		if linked {
			input["scenarios"] = []any{map[string]any{
				"scenarioId": scenarioID, "requirementIds": ids, "parameters": []any{},
				"preconditions": []any{"The source is admitted."}, "actionSequence": []any{"Open every requirement."},
				"expectedObservations": []any{observation}, "forbiddenObservations": []any{},
				"examples": []any{}, "vocabularyRefs": []any{}, "nonClaimRefs": []any{},
			}}
		}
		return input
	}
	perLinkBound := 16 * (len(scenarioID) + len("REQ-PROOFKIT-VIEW-001"))
	for name, render := range map[string]func(any) (string, int, error){"markdown": BuildMarkdown, "html": BuildHTML} {
		overhead := map[int]int{}
		for _, requirements := range []int{2, 9, 16} {
			with, _, err := render(source(requirements, true))
			if err != nil {
				t.Fatalf("%s with %d requirements: %v", name, requirements, err)
			}
			without, _, err := render(source(requirements, false))
			if err != nil {
				t.Fatal(err)
			}
			rendered := observation
			if name == "markdown" {
				rendered = markdownfmt.Text(observation)
			}
			if count := strings.Count(with, rendered); count != 1 {
				t.Fatalf("%s with %d linked requirements renders the scenario record %d times, want once", name, requirements, count)
			}
			overhead[requirements] = len(with) - len(without)
		}
		perLink := (overhead[16] - overhead[9]) / 7
		if overhead[16]-overhead[9] != overhead[9]-overhead[2] || perLink > perLinkBound {
			t.Fatalf("%s scenario overhead for 2, 9 and 16 requirements = %v; want affine growth of at most %d bytes per link", name, overhead, perLinkBound)
		}
	}
}
