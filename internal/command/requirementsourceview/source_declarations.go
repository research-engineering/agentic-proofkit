package requirementsourceview

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

// A group index is presentation support, not a reconstructed editable source.
func sourceGroupIndex(source map[string]any) []any {
	groups := []any{}
	for _, raw := range anyArray(source["groups"]) {
		group := raw.(map[string]any)
		ids := []any{}
		for _, member := range group["members"].([]any) {
			ids = append(ids, member.(map[string]any)["requirementId"])
		}
		groups = append(groups, map[string]any{
			"groupId": group["groupId"], "statementStem": group["statementStem"],
			"sharedPremises": group["sharedPremises"], "requirementIds": ids,
		})
	}
	return groups
}

type declarationField struct {
	label  string
	values []string
	code   bool
}

type declarationRecord struct {
	id     string
	fields []declarationField
}

type declarationSection struct {
	title   string
	records []declarationRecord
	// linkTargets marks scenario records that in-page links reach: each renders
	// as an anchored details outside a collapsed section wrapper.
	linkTargets bool
}

// One field inventory feeds both human renderers. It preserves ordered source
// actions and complete provenance coordinates without promoting declarations.
func sourceDeclarationSections(view map[string]any) []declarationSection {
	groups := declarationSection{title: "Source Groups"}
	for _, raw := range anyArray(view["groups"]) {
		row := raw.(map[string]any)
		groups.records = append(groups.records, declarationRecord{stringValue(row["groupId"]), []declarationField{
			{"Statement stem", []string{stringValue(row["statementStem"])}, false},
			{"Shared premises", stringArray(row["sharedPremises"]), false},
			{"Requirements", stringArray(row["requirementIds"]), true},
		}})
	}
	vocabulary := declarationSection{title: "Vocabulary"}
	for _, raw := range anyArray(view["vocabulary"]) {
		row := raw.(map[string]any)
		vocabulary.records = append(vocabulary.records, declarationRecord{stringValue(row["termId"]), []declarationField{
			{"Kind", []string{stringValue(row["kind"])}, true},
			{"Label", []string{stringValue(row["label"])}, false},
			{"Definition", []string{stringValue(row["definition"])}, false},
		}})
	}
	shared := declarationSection{title: "Shared Scenarios", linkTargets: true}
	for _, raw := range anyArray(view["scenarios"]) {
		row := raw.(map[string]any)
		if !nestsUnderOneRequirement(row) {
			shared.records = append(shared.records, scenarioRecord(row))
		}
	}
	derivations := declarationSection{title: "Declared Derivations"}
	for _, raw := range anyArray(view["derivations"]) {
		row := raw.(map[string]any)
		ref, selector := row["sourceRef"].(map[string]any), row["selector"].(map[string]any)
		derivations.records = append(derivations.records, declarationRecord{stringValue(row["derivationId"]), []declarationField{
			{"Source kind", []string{stringValue(row["sourceKind"])}, true},
			{"Object format", []string{stringValue(ref["objectFormat"])}, true},
			{"Commit OID", []string{stringValue(ref["commitOid"])}, true},
			{"Path", []string{stringValue(ref["path"])}, true},
			{"SHA-256", []string{stringValue(ref["sha256"])}, true},
			{"Selector start", []string{stringValue(selector["start"])}, true},
			{"Selector end", []string{stringValue(selector["end"])}, true},
			{"Requirements", stringArray(row["requirementIds"]), true},
			{"Source-local non-claim refs", stringArray(row["nonClaimRefs"]), true},
		}})
	}
	return []declarationSection{groups, vocabulary, shared, derivations}
}

// scenarioRecord is the one human field inventory of a canonical scenario.
func scenarioRecord(row map[string]any) declarationRecord {
	actions := stringArray(row["actionSequence"])
	for i := range actions {
		actions[i] = fmt.Sprintf("%d. %s", i+1, actions[i])
	}
	fields := []declarationField{
		{"Requirements", stringArray(row["requirementIds"]), true},
		{"Parameters", stringArray(row["parameters"]), true},
		{"Preconditions", stringArray(row["preconditions"]), false},
		{"Action sequence", actions, false},
		{"Expected observations", stringArray(row["expectedObservations"]), false},
		{"Forbidden observations", stringArray(row["forbiddenObservations"]), false},
		{"Vocabulary references", stringArray(row["vocabularyRefs"]), true},
		{"Source-local non-claim refs", stringArray(row["nonClaimRefs"]), true},
	}
	examples := anyArray(row["examples"])
	if len(examples) == 0 {
		fields = append(fields, declarationField{label: "Examples"})
	}
	for _, raw := range examples {
		example := raw.(map[string]any)
		values := example["values"].(map[string]any)
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		pairs := make([]string, 0, len(keys))
		for _, key := range keys {
			pairs = append(pairs, key+": "+stringValue(values[key]))
		}
		fields = append(fields, declarationField{"Example " + stringValue(example["exampleId"]), pairs, false})
	}
	return declarationRecord{stringValue(row["scenarioId"]), fields}
}

// nestsUnderOneRequirement places a scenario's full record exactly once, so
// rendered size stays linear in the admitted source: under its requirement
// when it links to exactly one, otherwise in the shared scenarios section.
func nestsUnderOneRequirement(row map[string]any) bool {
	return len(anyArray(row["requirementIds"])) == 1
}

// scenarioTargetKey names the in-page target of a scenario's single record.
func scenarioTargetKey(scenarioID string) string {
	return "scenario:" + scenarioID
}

// requirementScenarios lists every scenario linked to one requirement by ID
// and holds the full records of those linked to it alone.
type requirementScenarios struct {
	linkedIDs []string
	nested    []declarationRecord
}

// scenariosByRequirement indexes scenarios by linked requirement in canonical
// scenario order. Admission rejects dangling links and empty link sets, so
// every scenario is listed under at least one requirement.
func scenariosByRequirement(view map[string]any) map[string]requirementScenarios {
	result := map[string]requirementScenarios{}
	for _, raw := range anyArray(view["scenarios"]) {
		row := raw.(map[string]any)
		requirementIDs := stringArray(row["requirementIds"])
		for _, requirementID := range requirementIDs {
			entry := result[requirementID]
			entry.linkedIDs = append(entry.linkedIDs, stringValue(row["scenarioId"]))
			result[requirementID] = entry
		}
		if nestsUnderOneRequirement(row) {
			entry := result[requirementIDs[0]]
			entry.nested = append(entry.nested, scenarioRecord(row))
			result[requirementIDs[0]] = entry
		}
	}
	return result
}

// scenarioLinksHTML links each scenario ID to its single record.
func scenarioLinksHTML(scenarioIDs []string) browserdoc.Fragment {
	links := make([]browserdoc.InPageLink, 0, len(scenarioIDs))
	for _, scenarioID := range scenarioIDs {
		links = append(links, browserdoc.InPageLink{Label: scenarioID, TargetKey: scenarioTargetKey(scenarioID)})
	}
	return browserdoc.InPageLinkListOrNone(links)
}

func declarationRecordMarkdown(record declarationRecord, level int) []string {
	lines := []string{strings.Repeat("#", level) + " " + markdownfmt.Text(record.id), ""}
	for _, field := range record.fields {
		lines = append(lines, markdownfmt.Text(field.label)+":", "")
		if len(field.values) == 0 {
			lines = append(lines, "None.")
		}
		for _, value := range field.values {
			text := markdownfmt.Text(value)
			if field.code {
				text = markdownfmt.CodeSpan(value)
			}
			lines = append(lines, "- "+text)
		}
		lines = append(lines, "")
	}
	return lines
}

func declarationRecordHTML(record declarationRecord) browserdoc.Fragment {
	return browserdoc.Details(record.id, declarationFieldsHTML(record))
}

func scenarioRecordHTML(record declarationRecord) browserdoc.Fragment {
	return browserdoc.AnchoredDetails(scenarioTargetKey(record.id), record.id, declarationFieldsHTML(record))
}

func declarationFieldsHTML(record declarationRecord) browserdoc.Fragment {
	fields := []browserdoc.DefinitionItem{}
	for _, field := range record.fields {
		fields = append(fields, browserdoc.Definition(field.label, browserdoc.ListOrNone(field.values, field.code)))
	}
	return browserdoc.DefinitionList(fields...)
}

func sourceDeclarationsMarkdown(view map[string]any) []string {
	lines := []string{"## Named Source Boundaries", "", inlineCodeListOrNone(stringArray(view["sourceNonClaimRefs"])), ""}
	for _, section := range sourceDeclarationSections(view) {
		if len(section.records) == 0 {
			continue
		}
		lines = append(lines, "## "+section.title, "")
		for _, record := range section.records {
			lines = append(lines, declarationRecordMarkdown(record, 3)...)
		}
	}
	return lines
}

func sourceDeclarationsSummary(view map[string]any) []browserdoc.SummaryItem {
	items := []browserdoc.SummaryItem{}
	if refs := stringArray(view["sourceNonClaimRefs"]); len(refs) > 0 {
		items = append(items, browserdoc.SummaryItem{Label: "Named source boundaries", Value: browserdoc.ListOrNone(refs, true)})
	}
	for _, section := range sourceDeclarationSections(view) {
		if len(section.records) == 0 {
			continue
		}
		parts := []browserdoc.Fragment{}
		for _, record := range section.records {
			if section.linkTargets {
				parts = append(parts, scenarioRecordHTML(record))
			} else {
				parts = append(parts, declarationRecordHTML(record))
			}
		}
		value := browserdoc.Details(section.title, parts...)
		if section.linkTargets {
			value = browserdoc.Concat(parts...)
		}
		items = append(items, browserdoc.SummaryItem{Label: section.title, Value: value})
	}
	return items
}

func sourceGroupLabel(group map[string]any) string {
	label := stringValue(group["groupId"])
	if stem := stringValue(group["statementStem"]); stem != "" {
		label += ": " + stem
	}
	return label
}

func sourceGroupHierarchy(groups []any) []browserdoc.HierarchyItem {
	items := make([]browserdoc.HierarchyItem, 0, len(groups))
	for _, raw := range groups {
		group := raw.(map[string]any)
		items = append(items, browserdoc.HierarchyItem{
			Label: sourceGroupLabel(group), Detail: fmt.Sprintf("%d requirement(s)", len(anyArray(group["requirementIds"]))),
			Href: "#" + browserdoc.FragmentID("source-group:"+stringValue(group["groupId"])),
		})
	}
	return items
}
