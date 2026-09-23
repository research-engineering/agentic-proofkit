package requirementsourceview

import (
	"fmt"
	"sort"

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
	scenarios := declarationSection{title: "Declared Scenarios"}
	for _, raw := range anyArray(view["scenarios"]) {
		row := raw.(map[string]any)
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
		scenarios.records = append(scenarios.records, declarationRecord{stringValue(row["scenarioId"]), fields})
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
	return []declarationSection{groups, vocabulary, scenarios, derivations}
}

func sourceDeclarationsMarkdown(view map[string]any) []string {
	lines := []string{"## Named Source Boundaries", "", inlineCodeListOrNone(stringArray(view["sourceNonClaimRefs"])), ""}
	for _, section := range sourceDeclarationSections(view) {
		if len(section.records) == 0 {
			continue
		}
		lines = append(lines, "## "+section.title, "")
		for _, record := range section.records {
			lines = append(lines, "### "+markdownfmt.Text(record.id), "")
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
			fields := []browserdoc.DefinitionItem{}
			for _, field := range record.fields {
				fields = append(fields, browserdoc.Definition(field.label, browserdoc.ListOrNone(field.values, field.code)))
			}
			parts = append(parts, browserdoc.Details(record.id, browserdoc.DefinitionList(fields...)))
		}
		items = append(items, browserdoc.SummaryItem{Label: section.title, Value: browserdoc.Details(section.title, parts...)})
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
