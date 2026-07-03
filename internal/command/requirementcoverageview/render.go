package requirementcoverageview

import (
	"fmt"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
	"sort"
	"strings"
)

func markdown(view map[string]any) string {
	lines := []string{
		"# Requirement Coverage View: " + markdownfmt.Text(stringValue(view["viewInputId"])),
		"",
		"Authority: " + markdownfmt.Text(stringValue(view["authority"])),
		"State: " + markdownfmt.Text(stringValue(view["state"])),
		"Completeness: " + markdownfmt.Text(stringValue(view["completenessDeclaration"])),
		fmt.Sprintf("Requirements: %d", intValue(view["requirementCoverageCount"])),
		fmt.Sprintf("Owner invariants: %d", intValue(view["ownerInvariantCoverageCount"])),
		fmt.Sprintf("Commands: %d", intValue(view["commandCoverageCount"])),
		fmt.Sprintf("Failures: %d", intValue(view["failureCount"])),
		fmt.Sprintf("Warnings: %d", intValue(view["warningCount"])),
		"",
		"## Requirements",
		"",
	}
	for _, raw := range anyArray(view["requirementCoverage"]) {
		requirement := raw.(map[string]any)
		lines = append(lines,
			"### "+markdownfmt.Text(stringValue(requirement["requirementId"])),
			"",
			markdownfmt.Text(stringValue(requirement["invariant"])),
			"",
			"- Owner: "+markdownfmt.Text(stringValue(requirement["ownerId"])),
			"- Coverage: "+markdownfmt.Text(stringValue(requirement["coverageState"])),
			"- Evidence class: "+markdownfmt.Text(stringValue(requirement["evidenceClass"])),
			"- Proof state: "+markdownfmt.Text(stringValue(requirement["proofState"])),
			"- Tests: "+markdownfmt.CodeListOrNone(stringArray(requirement["testIds"])),
			"- Commands: "+markdownfmt.CodeListOrNone(stringArray(requirement["commandIds"])),
			"- Witnesses: "+markdownfmt.CodeListOrNone(stringArray(requirement["witnessRefs"])),
			"- Witness selectors: "+markdownfmt.CodeListOrNone(stringArray(requirement["witnessSelectors"])),
			"",
		)
	}
	lines = append(lines, "## Owner Invariants", "")
	for _, raw := range anyArray(view["ownerInvariantCoverage"]) {
		invariant := raw.(map[string]any)
		lines = append(lines,
			"### "+markdownfmt.Text(stringValue(invariant["ownerInvariantId"])),
			"",
			markdownfmt.Text(stringValue(invariant["summary"])),
			"",
			"- Owner: "+markdownfmt.Text(stringValue(invariant["ownerId"])),
			"- Coverage: "+markdownfmt.Text(stringValue(invariant["coverageState"])),
			"- Evidence class: "+markdownfmt.Text(stringValue(invariant["evidenceClass"])),
			"- Tests: "+markdownfmt.CodeListOrNone(stringArray(invariant["testIds"])),
			"- Source: "+markdownfmt.CodeSpan(stringValue(invariant["sourcePath"])),
			"",
		)
	}
	lines = append(lines, "## Command Coverage", "")
	for _, raw := range anyArray(view["commandCoverage"]) {
		command := raw.(map[string]any)
		lines = append(lines,
			"- "+markdownfmt.CodeSpan(stringValue(command["commandId"]))+": "+markdownfmt.Text(stringValue(command["coverageState"]))+"; tests: "+markdownfmt.CodeListOrNone(stringArray(command["testIds"])),
		)
	}
	lines = append(lines, "", "## Dead Zones", "")
	for _, raw := range anyArray(view["deadZones"]) {
		zone := raw.(map[string]any)
		lines = append(lines,
			"- "+markdownfmt.Text(stringValue(zone["deadZoneKind"]))+": "+markdownfmt.CodeSpan(stringValue(zone["path"]))+" owned by "+markdownfmt.Text(stringValue(zone["ownerId"])),
		)
	}
	lines = append(lines, "", "## Failures", "")
	for _, failure := range stringArray(view["failures"]) {
		lines = append(lines, "- "+markdownfmt.Text(failure))
	}
	lines = append(lines, "", "## Warnings", "")
	for _, warning := range stringArray(view["warnings"]) {
		lines = append(lines, "- "+markdownfmt.Text(warning))
	}
	lines = append(lines, "", "## View Non-Claims", "")
	for _, claim := range stringArray(view["nonClaims"]) {
		lines = append(lines, "- "+markdownfmt.Text(claim))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}
func html(view map[string]any) string {
	requirements := anyArray(view["requirementCoverage"])
	cards := make([]browserdoc.Card, 0, len(requirements))
	rows := make([]browserdoc.Row, 0, len(requirements))
	owners := []string{}
	states := []string{}
	classes := []string{}
	for _, raw := range requirements {
		requirement := raw.(map[string]any)
		owner := stringValue(requirement["ownerId"])
		state := stringValue(requirement["coverageState"])
		class := stringValue(requirement["evidenceClass"])
		owners = append(owners, owner)
		states = append(states, state)
		classes = append(classes, class)
		filters := []browserdoc.FilterValue{{Key: "owner", Value: owner}, {Key: "coverage-state", Value: state}, {Key: "evidence-class", Value: class}}
		search := browserdoc.SearchText(append([]string{
			stringValue(requirement["requirementId"]),
			stringValue(requirement["invariant"]),
			owner,
			state,
			class,
		}, append(append(stringArray(requirement["testIds"]), stringArray(requirement["commandIds"])...), stringArray(requirement["witnessRefs"])...)...))
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(requirement["requirementId"]),
			Title:        stringValue(requirement["invariant"]),
			GroupID:      "owner:" + owner,
			GroupLabel:   "Owner: " + owner,
			Body:         requirementBody(requirement),
			SearchText:   search,
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(requirement["requirementId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("requirement", stringValue(requirement["requirementId"]), true),
				browserdoc.TableCell("owner", owner, false),
				browserdoc.TableCell("coverage", state, false),
				browserdoc.TableCell("evidenceClass", class, false),
				{Key: "tests", Value: browserdoc.ListOrNone(stringArray(requirement["testIds"]), true)},
				{Key: "commands", Value: browserdoc.ListOrNone(stringArray(requirement["commandIds"]), true)},
			},
			SearchText:   search,
			FilterValues: filters,
		})
	}
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Requirement Coverage View: " + stringValue(view["viewInputId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("Coverage report state", stringValue(view["state"]), false),
			browserdoc.Summary("Caller-declared completeness scope", stringValue(view["completenessDeclaration"]), false),
			browserdoc.Summary("Requirements", fmt.Sprint(intValue(view["requirementCoverageCount"])), false),
			browserdoc.Summary("Owner invariants", fmt.Sprint(intValue(view["ownerInvariantCoverageCount"])), false),
			browserdoc.Summary("Commands", fmt.Sprint(intValue(view["commandCoverageCount"])), false),
			browserdoc.Summary("Failures", fmt.Sprint(intValue(view["failureCount"])), false),
			browserdoc.Summary("Warnings", fmt.Sprint(intValue(view["warningCount"])), false),
		},
		HierarchySections: []browserdoc.HierarchySection{
			{Title: "Owners", Items: ownerHierarchy(requirements)},
			{Title: "Owner invariants", Items: ownerInvariantHierarchy(anyArray(view["ownerInvariantCoverage"]))},
			{Title: "Command coverage", Items: commandHierarchy(anyArray(view["commandCoverage"]))},
			{Title: "Dead zones", Items: deadZoneHierarchy(anyArray(view["deadZones"]))},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("owner", "Owner", owners),
			browserdoc.NewFilter("coverage-state", "Coverage", states),
			browserdoc.NewFilter("evidence-class", "Evidence class", classes),
		},
		Cards: cards,
		Table: &browserdoc.Table{
			Columns: []browserdoc.Column{
				{Key: "requirement", Label: "Requirement"},
				{Key: "owner", Label: "Owner"},
				{Key: "coverage", Label: "Coverage"},
				{Key: "evidenceClass", Label: "Evidence"},
				{Key: "tests", Label: "Tests"},
				{Key: "commands", Label: "Commands"},
			},
			Rows: rows,
		},
		NonClaims: stringArray(view["nonClaims"]),
	})
}
func requirementBody(requirement map[string]any) browserdoc.Fragment {
	return browserdoc.Concat(
		browserdoc.DefinitionList(
			browserdoc.Definition("Owner", browserdoc.Text(stringValue(requirement["ownerId"]))),
			browserdoc.Definition("Coverage state", browserdoc.Text(stringValue(requirement["coverageState"]))),
			browserdoc.Definition("Evidence class", browserdoc.Text(stringValue(requirement["evidenceClass"]))),
			browserdoc.Definition("Proof state", browserdoc.Text(stringValue(requirement["proofState"]))),
			browserdoc.Definition("Tests", browserdoc.ListOrNone(stringArray(requirement["testIds"]), true)),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(requirement["commandIds"]), true)),
			browserdoc.Definition("Witness refs", browserdoc.ListOrNone(stringArray(requirement["witnessRefs"]), true)),
			browserdoc.Definition("Witness selectors", browserdoc.ListOrNone(stringArray(requirement["witnessSelectors"]), true)),
		),
		browserdoc.Details("Test evidence, scenarios, failures, and non-claims",
			browserdoc.Heading(3, "Test evidence"),
			testsHTML(anyArray(requirement["tests"])),
			browserdoc.Heading(3, "Scenarios"),
			scenariosHTML(anyArray(requirement["scenarios"])),
			browserdoc.Heading(3, "Failures"),
			browserdoc.ListOrNone(stringArray(requirement["failures"]), false),
			browserdoc.Heading(3, "Non-claims"),
			browserdoc.ListOrNone(stringArray(requirement["nonClaims"]), false),
		),
	)
}
func testsHTML(tests []any) browserdoc.Fragment {
	if len(tests) == 0 {
		return browserdoc.Text("none")
	}
	parts := []browserdoc.Fragment{}
	for _, raw := range tests {
		item := raw.(map[string]any)
		parts = append(parts, browserdoc.Section(stringValue(item["testId"]), browserdoc.DefinitionList(
			browserdoc.Definition("Evidence class", browserdoc.Text(stringValue(item["evidenceClass"]))),
			browserdoc.Definition("Selector", browserdoc.Code(stringValue(item["selector"]))),
			browserdoc.Definition("Source path", browserdoc.Code(stringValue(item["sourcePath"]))),
			browserdoc.Definition("Oracle", browserdoc.Text(stringValue(item["oracleSummary"]))),
			browserdoc.Definition("Falsifier", browserdoc.Text(stringValue(item["wrongImplementationClassId"]))),
			browserdoc.Definition("Quality findings", browserdoc.ListOrNone(qualityFindingLabels(anyArray(item["qualityFindings"])), true)),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(item["commandRefs"]), true)),
			browserdoc.Definition("Witnesses", browserdoc.ListOrNone(stringArray(item["witnessRefs"]), true)),
		)))
	}
	return browserdoc.Concat(parts...)
}
func qualityFindingLabels(findings []any) []string {
	labels := make([]string, 0, len(findings))
	for _, raw := range findings {
		finding := raw.(map[string]any)
		labels = append(labels, stringValue(finding["class"])+":"+stringValue(finding["findingId"]))
	}
	sort.Strings(labels)
	return labels
}
func scenariosHTML(scenarios []any) browserdoc.Fragment {
	if len(scenarios) == 0 {
		return browserdoc.Text("none")
	}
	parts := []browserdoc.Fragment{}
	for _, raw := range scenarios {
		item := raw.(map[string]any)
		parts = append(parts, browserdoc.Section(stringValue(item["scenarioId"]), browserdoc.DefinitionList(
			browserdoc.Definition("Witness", browserdoc.Text(stringValue(item["witnessId"]))),
			browserdoc.Definition("Witness kind", browserdoc.Text(stringValue(item["witnessKind"]))),
			browserdoc.Definition("Witness path", browserdoc.Code(stringValue(item["witnessPath"]))),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(item["commandIds"]), true)),
			browserdoc.Definition("Environments", browserdoc.ListOrNone(stringArray(item["environmentClasses"]), false)),
		)))
	}
	return browserdoc.Concat(parts...)
}
func ownerHierarchy(requirements []any) []browserdoc.HierarchyItem {
	counts := map[string]int{}
	for _, raw := range requirements {
		counts[stringValue(raw.(map[string]any)["ownerId"])]++
	}
	return hierarchyFromCounts(counts, "owner:")
}
func ownerInvariantHierarchy(invariants []any) []browserdoc.HierarchyItem {
	items := make([]browserdoc.HierarchyItem, 0, len(invariants))
	for _, raw := range invariants {
		invariant := raw.(map[string]any)
		items = append(items, browserdoc.HierarchyItem{
			Label:  stringValue(invariant["ownerInvariantId"]),
			Detail: stringValue(invariant["coverageState"]),
		})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Label < items[right].Label })
	return items
}
func commandHierarchy(commands []any) []browserdoc.HierarchyItem {
	items := make([]browserdoc.HierarchyItem, 0, len(commands))
	for _, raw := range commands {
		command := raw.(map[string]any)
		items = append(items, browserdoc.HierarchyItem{
			Label:  stringValue(command["commandId"]),
			Detail: stringValue(command["coverageState"]),
		})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Label < items[right].Label })
	return items
}
func deadZoneHierarchy(zones []any) []browserdoc.HierarchyItem {
	items := make([]browserdoc.HierarchyItem, 0, len(zones))
	for _, raw := range zones {
		zone := raw.(map[string]any)
		items = append(items, browserdoc.HierarchyItem{
			Label:  stringValue(zone["path"]),
			Detail: stringValue(zone["deadZoneKind"]),
		})
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Label < items[right].Label })
	return items
}
func hierarchyFromCounts(counts map[string]int, anchorPrefix string) []browserdoc.HierarchyItem {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]browserdoc.HierarchyItem, 0, len(keys))
	for _, key := range keys {
		items = append(items, browserdoc.HierarchyItem{
			Detail: fmt.Sprintf("%d requirement(s)", counts[key]),
			Href:   "#" + browserdoc.FragmentID(anchorPrefix+key),
			Label:  key,
		})
	}
	return items
}
