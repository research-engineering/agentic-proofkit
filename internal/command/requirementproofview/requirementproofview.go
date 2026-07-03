package requirementproofview

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

type Options struct {
	Scope                   string
	LocalEnvironmentClasses []string
}

var defaultNonClaims = []string{
	"Requirement proof views are rendered lookup products only.",
	"Requirement proof views do not own requirement meaning.",
	"Requirement proof views do not execute native witnesses.",
	"Requirement proof views do not prove receipt freshness, command success, merge approval, or rollout readiness.",
}

func IsCompact(raw any) bool {
	record, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	return record["schema_version"] != nil && record["contract_kind"] == "requirement_proof_binding"
}

func BuildJSON(raw any, options Options) (any, int, error) {
	view, err := build(raw, options)
	if err != nil {
		return nil, 1, err
	}
	return view, 0, nil
}

func BuildMarkdown(raw any, options Options) (string, int, error) {
	view, err := build(raw, options)
	if err != nil {
		return "", 1, err
	}
	if stringValue(view["viewKind"]) == "proofkit.compact-requirement-proof-view" {
		return compactMarkdown(view) + "\n", 0, nil
	}
	return markdown(view) + "\n", 0, nil
}

func BuildHTML(raw any, options Options) (string, int, error) {
	view, err := build(raw, options)
	if err != nil {
		return "", 1, err
	}
	if stringValue(view["viewKind"]) == "proofkit.compact-requirement-proof-view" {
		return compactHTML(view), 0, nil
	}
	return html(view), 0, nil
}

func build(raw any, options Options) (map[string]any, error) {
	if IsCompact(raw) {
		return compactView(raw, options)
	}
	return structuredView(raw, options)
}

func structuredView(raw any, options Options) (map[string]any, error) {
	scope := options.Scope
	if scope == "" {
		scope = "slice"
	}
	if scope != "graph" && scope != "slice" {
		return nil, fmt.Errorf("--scope must be graph or slice")
	}
	result, err := requirementbinding.Build(raw)
	if err != nil {
		return nil, err
	}
	if result.Record.State != "passed" {
		return nil, fmt.Errorf("cannot build requirement proof view from failed requirement proof bindings")
	}
	var requirements []any
	omitted := 0
	if scope == "graph" {
		requirements = anyArray(result.Graph["requirements"])
	} else {
		requirements = anyArray(result.Slice["selectedRequirements"])
		omitted = intValue(result.Slice["omittedRequirementCount"])
	}
	viewRequirements := make([]any, 0, len(requirements))
	commandSet := map[string]struct{}{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		view := structuredRequirement(requirement)
		viewRequirements = append(viewRequirements, view)
		for _, commandID := range stringArray(view["commandIds"]) {
			commandSet[commandID] = struct{}{}
		}
	}
	nonClaims := append([]string{}, defaultNonClaims...)
	nonClaims = append(nonClaims, stringArray(result.Graph["nonClaims"])...)
	return map[string]any{
		"authority":               "lookup_only",
		"bindingId":               result.Graph["bindingId"],
		"commandCount":            len(commandSet),
		"nonClaims":               admit.StringSliceToAny(sortedUnique(nonClaims)),
		"omittedRequirementCount": omitted,
		"requirementCount":        len(viewRequirements),
		"requirements":            viewRequirements,
		"schemaVersion":           1,
		"scope":                   scope,
		"viewKind":                "proofkit.requirement-proof-view",
	}, nil
}

func structuredRequirement(requirement map[string]any) map[string]any {
	scenarios := anyArray(requirement["scenarios"])
	viewScenarios := make([]any, 0, len(scenarios))
	commandIDs := []string{}
	environmentClasses := []string{}
	witnessPaths := []string{}
	for _, item := range scenarios {
		scenario := item.(map[string]any)
		commandIDs = append(commandIDs, stringArray(scenario["commandIds"])...)
		environmentClasses = append(environmentClasses, stringArray(scenario["environmentClasses"])...)
		witnessPaths = append(witnessPaths, stringValue(scenario["witnessPath"]))
		viewScenarios = append(viewScenarios, map[string]any{
			"commandIds":         admit.StringSliceToAny(sortedUnique(stringArray(scenario["commandIds"]))),
			"environmentClasses": admit.StringSliceToAny(sortedUnique(stringArray(scenario["environmentClasses"]))),
			"scenarioId":         scenario["scenarioId"],
			"witnessId":          scenario["witnessId"],
			"witnessKind":        scenario["witnessKind"],
			"witnessPath":        scenario["witnessPath"],
		})
	}
	return map[string]any{
		"claimLevel":         requirement["claimLevel"],
		"commandIds":         admit.StringSliceToAny(sortedUnique(commandIDs)),
		"environmentClasses": admit.StringSliceToAny(sortedUnique(environmentClasses)),
		"nonClaims":          admit.StringSliceToAny(sortedUnique(stringArray(requirement["nonClaims"]))),
		"ownerId":            requirement["ownerId"],
		"proofState":         requirement["proofState"],
		"requirementId":      requirement["requirementId"],
		"scenarioCount":      len(scenarios),
		"scenarios":          viewScenarios,
		"specPath":           requirement["specPath"],
		"witnessPaths":       admit.StringSliceToAny(sortedUnique(witnessPaths)),
	}
}

func compactView(raw any, options Options) (map[string]any, error) {
	projection, _, err := requirementbinding.BuildResolver(raw, requirementbinding.ResolverOptions{
		LocalEnvironmentClasses: options.LocalEnvironmentClasses,
	})
	if err != nil {
		return nil, err
	}
	record := projection.(map[string]any)
	requirements := anyArray(record["requirements"])
	viewRequirements := make([]any, 0, len(requirements))
	commandSet := map[string]struct{}{}
	preconditioned := 0
	for _, item := range requirements {
		requirement := compactRequirement(item.(map[string]any))
		viewRequirements = append(viewRequirements, requirement)
		if bool, _ := requirement["preconditioned"].(bool); bool {
			preconditioned++
		}
		for _, command := range stringArray(requirement["verifyCommands"]) {
			commandSet[command] = struct{}{}
		}
	}
	nonClaims := append([]string{}, defaultNonClaims...)
	nonClaims = append(nonClaims, stringArray(record["nonClaims"])...)
	nonClaims = append(nonClaims,
		"Compact requirement proof views are rendered from explicit compact contract facts only.",
		"Compact requirement proof views do not infer spec paths, owner routes, or local environment policy.",
	)
	return map[string]any{
		"authority":                      "lookup_only",
		"commandCount":                   len(commandSet),
		"contractId":                     record["contractId"],
		"localEnvironmentPolicy":         record["localEnvironmentPolicy"],
		"nonClaims":                      admit.StringSliceToAny(sortedUnique(nonClaims)),
		"preconditionedRequirementCount": preconditioned,
		"requirementCount":               len(viewRequirements),
		"requirements":                   viewRequirements,
		"schemaVersion":                  1,
		"viewKind":                       "proofkit.compact-requirement-proof-view",
	}, nil
}

func compactRequirement(requirement map[string]any) map[string]any {
	witnesses := requirement["testWitnesses"].(map[string]any)
	positive := compactWitness(witnesses["positive"].(map[string]any))
	falsification := compactWitness(witnesses["falsification"].(map[string]any))
	return map[string]any{
		"blockingStatus":             requirement["blockingStatus"],
		"falsificationWitness":       falsification,
		"invariantRole":              requirement["invariantRole"],
		"mutationResistanceState":    requirement["mutationResistanceContext"].(map[string]any)["mutationResistanceState"],
		"ownedInvariant":             requirement["ownedInvariant"],
		"positiveWitness":            positive,
		"preconditioned":             requirement["preconditioned"],
		"proofContractState":         requirement["proofContractState"],
		"requiredEnvironmentClasses": requirement["requiredEnvironmentClasses"],
		"requirementId":              requirement["requirementId"],
		"scenarioId":                 requirement["scenarioId"],
		"surfaceId":                  requirement["surfaceId"],
		"verifyCommands":             requirement["verifyCommands"],
		"witnessSelectors": admit.StringSliceToAny(sortedUnique([]string{
			stringValue(positive["selector"]),
			stringValue(falsification["selector"]),
		})),
	}
}

func compactWitness(witness map[string]any) map[string]any {
	return map[string]any{
		"environmentClasses": witness["environmentClasses"],
		"selector":           witness["selector"],
		"verifyCommands":     witness["verifyCommandRefs"],
	}
}

func markdown(view map[string]any) string {
	lines := []string{
		"# Requirement Proof View: " + markdownText(stringValue(view["bindingId"])),
		"",
		"Authority: " + markdownText(stringValue(view["authority"])),
		"Scope: " + markdownText(stringValue(view["scope"])),
		fmt.Sprintf("Requirements: %d", intValue(view["requirementCount"])),
		fmt.Sprintf("Omitted requirements: %d", intValue(view["omittedRequirementCount"])),
		fmt.Sprintf("Commands: %d", intValue(view["commandCount"])),
		"",
		"## Requirements",
		"",
	}
	requirements := anyArray(view["requirements"])
	if len(requirements) == 0 {
		lines = append(lines, "No requirements selected.", "")
	} else {
		for _, item := range requirements {
			requirement := item.(map[string]any)
			lines = append(lines,
				"### "+markdownText(stringValue(requirement["requirementId"])),
				"",
				"- Owner: "+markdownText(stringValue(requirement["ownerId"])),
				"- Spec: "+inlineCode(stringValue(requirement["specPath"])),
				"- Claim level: "+markdownText(stringValue(requirement["claimLevel"])),
				"- Proof state: "+markdownText(stringValue(requirement["proofState"])),
				fmt.Sprintf("- Scenarios: %d", intValue(requirement["scenarioCount"])),
				"- Commands: "+inlineCodeListOrNone(stringArray(requirement["commandIds"])),
				"- Environments: "+plainListOrNone(stringArray(requirement["environmentClasses"])),
				"- Witness paths: "+inlineCodeListOrNone(stringArray(requirement["witnessPaths"])),
				"",
				"Non-claims:",
				"",
			)
			for _, claim := range stringArray(requirement["nonClaims"]) {
				lines = append(lines, "- "+markdownText(claim))
			}
			lines = append(lines, "")
		}
	}
	lines = append(lines, "## View Non-Claims", "")
	for _, claim := range stringArray(view["nonClaims"]) {
		lines = append(lines, "- "+markdownText(claim))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func compactMarkdown(view map[string]any) string {
	policy := view["localEnvironmentPolicy"].(map[string]any)
	lines := []string{
		"# Compact Requirement Proof View: " + markdownText(stringValue(view["contractId"])),
		"",
		"Authority: " + markdownText(stringValue(view["authority"])),
		fmt.Sprintf("Requirements: %d", intValue(view["requirementCount"])),
		fmt.Sprintf("Preconditioned requirements: %d", intValue(view["preconditionedRequirementCount"])),
		fmt.Sprintf("Commands: %d", intValue(view["commandCount"])),
		"Local environment policy: " + plainListOrNone(stringArray(policy["localEnvironmentClasses"])),
		"",
		"## Requirements",
		"",
	}
	requirements := anyArray(view["requirements"])
	if len(requirements) == 0 {
		lines = append(lines, "No requirements declared.", "")
	} else {
		for _, item := range requirements {
			requirement := item.(map[string]any)
			lines = append(lines,
				"### "+markdownText(stringValue(requirement["requirementId"])),
				"",
				"- Surface: "+markdownText(stringValue(requirement["surfaceId"])),
				"- Scenario: "+markdownText(stringValue(requirement["scenarioId"])),
				"- Invariant: "+markdownText(stringValue(requirement["ownedInvariant"])),
				"- Invariant role: "+markdownText(stringValue(requirement["invariantRole"])),
				"- Proof state: "+markdownText(stringValue(requirement["proofContractState"])),
				"- Blocking: "+markdownText(stringValue(requirement["blockingStatus"])),
				"- Preconditioned: "+fmt.Sprint(requirement["preconditioned"]),
				"- Mutation resistance: "+markdownText(stringValue(requirement["mutationResistanceState"])),
				"- Positive witness: "+inlineCode(stringValue(requirement["positiveWitness"].(map[string]any)["selector"])),
				"- Falsification witness: "+inlineCode(stringValue(requirement["falsificationWitness"].(map[string]any)["selector"])),
				"- Commands: "+inlineCodeListOrNone(stringArray(requirement["verifyCommands"])),
				"- Environments: "+plainListOrNone(stringArray(requirement["requiredEnvironmentClasses"])),
				"- Witness selectors: "+inlineCodeListOrNone(stringArray(requirement["witnessSelectors"])),
				"",
			)
		}
	}
	lines = append(lines, "## View Non-Claims", "")
	for _, claim := range stringArray(view["nonClaims"]) {
		lines = append(lines, "- "+markdownText(claim))
	}
	lines = append(lines, "")
	return strings.Join(lines, "\n")
}

func html(view map[string]any) string {
	requirements := anyArray(view["requirements"])
	cards := make([]browserdoc.Card, 0, len(requirements))
	rows := make([]browserdoc.Row, 0, len(requirements))
	owners := []string{}
	claimLevels := []string{}
	proofStates := []string{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		owner := stringValue(requirement["ownerId"])
		claim := stringValue(requirement["claimLevel"])
		proofState := stringValue(requirement["proofState"])
		owners = append(owners, owner)
		claimLevels = append(claimLevels, claim)
		proofStates = append(proofStates, proofState)
		filters := []browserdoc.FilterValue{{Key: "owner", Value: owner}, {Key: "claim-level", Value: claim}, {Key: "proof-state", Value: proofState}}
		search := browserdoc.SearchText(append([]string{
			stringValue(requirement["requirementId"]),
			owner,
			stringValue(requirement["specPath"]),
			claim,
			proofState,
		}, append(append(append(stringArray(requirement["commandIds"]), stringArray(requirement["environmentClasses"])...), stringArray(requirement["witnessPaths"])...), scenarioSearch(requirement)...)...))
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(requirement["requirementId"]),
			Title:        stringValue(requirement["specPath"]),
			GroupID:      "owner:" + owner,
			GroupLabel:   "Owner: " + owner,
			Body:         proofRequirementBody(requirement),
			SearchText:   search,
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(requirement["requirementId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("requirement", stringValue(requirement["requirementId"]), true),
				browserdoc.TableCell("owner", owner, false),
				browserdoc.TableCell("spec", stringValue(requirement["specPath"]), true),
				browserdoc.TableCell("claimLevel", claim, false),
				browserdoc.TableCell("proofState", proofState, false),
				browserdoc.TableCell("scenarios", fmt.Sprint(intValue(requirement["scenarioCount"])), false),
				{Key: "commands", Value: browserdoc.ListOrNone(stringArray(requirement["commandIds"]), true)},
			},
			SearchText:   browserdoc.SearchText(append([]string{stringValue(requirement["requirementId"]), owner, stringValue(requirement["specPath"]), claim, proofState}, append(stringArray(requirement["commandIds"]), scenarioIDs(requirement)...)...)),
			FilterValues: filters,
		})
	}
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Requirement Proof View: " + stringValue(view["bindingId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("Scope", stringValue(view["scope"]), false),
			browserdoc.Summary("Requirements", fmt.Sprint(intValue(view["requirementCount"])), false),
			browserdoc.Summary("Omitted requirements", fmt.Sprint(intValue(view["omittedRequirementCount"])), false),
			browserdoc.Summary("Commands", fmt.Sprint(intValue(view["commandCount"])), false),
		},
		HierarchySections: []browserdoc.HierarchySection{
			{Title: "Specification hierarchy", Items: specHierarchy(requirements)},
			{Title: "Owners", Items: ownerHierarchy(requirements)},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("owner", "Owner", owners),
			browserdoc.NewFilter("claim-level", "Claim level", claimLevels),
			browserdoc.NewFilter("proof-state", "Proof state", proofStates),
		},
		Cards: cards,
		Table: &browserdoc.Table{
			Columns: []browserdoc.Column{
				{Key: "requirement", Label: "Requirement"},
				{Key: "owner", Label: "Owner"},
				{Key: "spec", Label: "Spec"},
				{Key: "claimLevel", Label: "Claim"},
				{Key: "proofState", Label: "Proof"},
				{Key: "scenarios", Label: "Scenarios"},
				{Key: "commands", Label: "Commands"},
			},
			Rows: rows,
		},
		NonClaims: stringArray(view["nonClaims"]),
	})
}

func compactHTML(view map[string]any) string {
	requirements := anyArray(view["requirements"])
	cards := make([]browserdoc.Card, 0, len(requirements))
	rows := make([]browserdoc.Row, 0, len(requirements))
	surfaces := []string{}
	blockingValues := []string{}
	proofStates := []string{}
	preconditionedValues := []string{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		surface := stringValue(requirement["surfaceId"])
		blocking := stringValue(requirement["blockingStatus"])
		proofState := stringValue(requirement["proofContractState"])
		preconditioned := fmt.Sprint(requirement["preconditioned"])
		surfaces = append(surfaces, surface)
		blockingValues = append(blockingValues, blocking)
		proofStates = append(proofStates, proofState)
		preconditionedValues = append(preconditionedValues, preconditioned)
		filters := []browserdoc.FilterValue{{Key: "surface", Value: surface}, {Key: "blocking", Value: blocking}, {Key: "proof-state", Value: proofState}, {Key: "preconditioned", Value: preconditioned}}
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(requirement["requirementId"]),
			Title:        stringValue(requirement["ownedInvariant"]),
			GroupID:      "surface:" + surface,
			GroupLabel:   "Surface: " + surface,
			Body:         compactProofRequirementBody(requirement),
			SearchText:   browserdoc.SearchText(append([]string{stringValue(requirement["requirementId"]), surface, stringValue(requirement["scenarioId"]), stringValue(requirement["invariantRole"]), stringValue(requirement["ownedInvariant"]), proofState, blocking, preconditioned, stringValue(requirement["mutationResistanceState"])}, append(stringArray(requirement["verifyCommands"]), append(stringArray(requirement["requiredEnvironmentClasses"]), stringArray(requirement["witnessSelectors"])...)...)...)),
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(requirement["requirementId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("requirement", stringValue(requirement["requirementId"]), true),
				browserdoc.TableCell("surface", surface, false),
				browserdoc.TableCell("invariant", stringValue(requirement["ownedInvariant"]), false),
				browserdoc.TableCell("blocking", blocking, false),
				browserdoc.TableCell("preconditioned", preconditioned, false),
				{Key: "commands", Value: browserdoc.ListOrNone(stringArray(requirement["verifyCommands"]), true)},
				{Key: "witnesses", Value: browserdoc.ListOrNone(stringArray(requirement["witnessSelectors"]), true)},
			},
			SearchText:   browserdoc.SearchText(append([]string{stringValue(requirement["requirementId"]), surface, stringValue(requirement["scenarioId"]), stringValue(requirement["ownedInvariant"]), blocking, preconditioned}, append(stringArray(requirement["verifyCommands"]), stringArray(requirement["witnessSelectors"])...)...)),
			FilterValues: filters,
		})
	}
	policy := view["localEnvironmentPolicy"].(map[string]any)
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Compact Requirement Proof View: " + stringValue(view["contractId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("Requirements", fmt.Sprint(intValue(view["requirementCount"])), false),
			browserdoc.Summary("Preconditioned requirements", fmt.Sprint(intValue(view["preconditionedRequirementCount"])), false),
			browserdoc.Summary("Commands", fmt.Sprint(intValue(view["commandCount"])), false),
			{Label: "Local environment policy", Value: browserdoc.ListOrNone(stringArray(policy["localEnvironmentClasses"]), false)},
		},
		HierarchySections: []browserdoc.HierarchySection{
			{Title: "Surface hierarchy", Items: surfaceHierarchy(requirements)},
			{Title: "Environment classes", Items: environmentHierarchy(requirements)},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("surface", "Surface", surfaces),
			browserdoc.NewFilter("blocking", "Blocking", blockingValues),
			browserdoc.NewFilter("proof-state", "Proof state", proofStates),
			browserdoc.NewFilter("preconditioned", "Preconditioned", preconditionedValues),
		},
		Cards: cards,
		Table: &browserdoc.Table{
			Columns: []browserdoc.Column{
				{Key: "requirement", Label: "Requirement"},
				{Key: "surface", Label: "Surface"},
				{Key: "invariant", Label: "Invariant"},
				{Key: "blocking", Label: "Blocking"},
				{Key: "preconditioned", Label: "Preconditioned"},
				{Key: "commands", Label: "Commands"},
				{Key: "witnesses", Label: "Witnesses"},
			},
			Rows: rows,
		},
		NonClaims: stringArray(view["nonClaims"]),
	})
}

func proofRequirementBody(requirement map[string]any) browserdoc.Fragment {
	return browserdoc.Concat(
		browserdoc.DefinitionList(
			browserdoc.Definition("Owner", browserdoc.Text(stringValue(requirement["ownerId"]))),
			browserdoc.Definition("Claim level", browserdoc.Text(stringValue(requirement["claimLevel"]))),
			browserdoc.Definition("Proof state", browserdoc.Text(stringValue(requirement["proofState"]))),
			browserdoc.Definition("Scenarios", browserdoc.Text(fmt.Sprint(intValue(requirement["scenarioCount"])))),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(requirement["commandIds"]), true)),
			browserdoc.Definition("Environments", browserdoc.ListOrNone(stringArray(requirement["environmentClasses"]), false)),
			browserdoc.Definition("Witness paths", browserdoc.ListOrNone(stringArray(requirement["witnessPaths"]), true)),
		),
		browserdoc.Details("Scenarios and test witnesses", structuredScenariosHTML(anyArray(requirement["scenarios"]))),
		browserdoc.Heading(3, "Non-claims"),
		browserdoc.ListOrNone(stringArray(requirement["nonClaims"]), false),
	)
}

func compactProofRequirementBody(requirement map[string]any) browserdoc.Fragment {
	positive := requirement["positiveWitness"].(map[string]any)
	falsification := requirement["falsificationWitness"].(map[string]any)
	return browserdoc.Concat(
		browserdoc.DefinitionList(
			browserdoc.Definition("Surface", browserdoc.Text(stringValue(requirement["surfaceId"]))),
			browserdoc.Definition("Scenario", browserdoc.Text(stringValue(requirement["scenarioId"]))),
			browserdoc.Definition("Invariant role", browserdoc.Text(stringValue(requirement["invariantRole"]))),
			browserdoc.Definition("Proof state", browserdoc.Text(stringValue(requirement["proofContractState"]))),
			browserdoc.Definition("Blocking", browserdoc.Text(stringValue(requirement["blockingStatus"]))),
			browserdoc.Definition("Preconditioned", browserdoc.Text(fmt.Sprint(requirement["preconditioned"]))),
			browserdoc.Definition("Mutation resistance", browserdoc.Text(stringValue(requirement["mutationResistanceState"]))),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(requirement["verifyCommands"]), true)),
			browserdoc.Definition("Environments", browserdoc.ListOrNone(stringArray(requirement["requiredEnvironmentClasses"]), false)),
		),
		browserdoc.Details("Scenario and test witnesses", browserdoc.DefinitionList(
			browserdoc.Definition("Scenario", browserdoc.Text(stringValue(requirement["scenarioId"]))),
			browserdoc.Definition("Positive witness", browserdoc.Code(stringValue(positive["selector"]))),
			browserdoc.Definition("Positive commands", browserdoc.ListOrNone(stringArray(positive["verifyCommands"]), true)),
			browserdoc.Definition("Falsification witness", browserdoc.Code(stringValue(falsification["selector"]))),
			browserdoc.Definition("Falsification commands", browserdoc.ListOrNone(stringArray(falsification["verifyCommands"]), true)),
			browserdoc.Definition("Witness selectors", browserdoc.ListOrNone(stringArray(requirement["witnessSelectors"]), true)),
		)),
	)
}

func structuredScenariosHTML(scenarios []any) browserdoc.Fragment {
	if len(scenarios) == 0 {
		return browserdoc.Text("none")
	}
	parts := []browserdoc.Fragment{}
	for _, item := range scenarios {
		scenario := item.(map[string]any)
		parts = append(parts, browserdoc.Section(stringValue(scenario["scenarioId"]), browserdoc.DefinitionList(
			browserdoc.Definition("Witness id", browserdoc.Text(stringValue(scenario["witnessId"]))),
			browserdoc.Definition("Witness kind", browserdoc.Text(stringValue(scenario["witnessKind"]))),
			browserdoc.Definition("Witness path", browserdoc.Code(stringValue(scenario["witnessPath"]))),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(scenario["commandIds"]), true)),
			browserdoc.Definition("Environments", browserdoc.ListOrNone(stringArray(scenario["environmentClasses"]), false)),
		)))
	}
	return browserdoc.Concat(parts...)
}

func specHierarchy(requirements []any) []browserdoc.HierarchyItem {
	return countHierarchy(requirements, "specPath", "")
}

func ownerHierarchy(requirements []any) []browserdoc.HierarchyItem {
	return countHierarchy(requirements, "ownerId", "owner:")
}

func surfaceHierarchy(requirements []any) []browserdoc.HierarchyItem {
	return countHierarchy(requirements, "surfaceId", "surface:")
}

func environmentHierarchy(requirements []any) []browserdoc.HierarchyItem {
	counts := map[string]int{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		for _, environment := range stringArray(requirement["requiredEnvironmentClasses"]) {
			counts[environment]++
		}
	}
	return hierarchyFromCounts(counts, "")
}

func countHierarchy(requirements []any, key string, anchorPrefix string) []browserdoc.HierarchyItem {
	counts := map[string]int{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		counts[stringValue(requirement[key])]++
	}
	return hierarchyFromCounts(counts, anchorPrefix)
}

func hierarchyFromCounts(counts map[string]int, anchorPrefix string) []browserdoc.HierarchyItem {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]browserdoc.HierarchyItem, 0, len(keys))
	for _, key := range keys {
		item := browserdoc.HierarchyItem{Label: key, Detail: fmt.Sprintf("%d requirement(s)", counts[key])}
		if anchorPrefix != "" {
			item.Href = "#" + browserdoc.FragmentID(anchorPrefix+key)
		}
		items = append(items, item)
	}
	return items
}

func scenarioSearch(requirement map[string]any) []string {
	values := []string{}
	for _, item := range anyArray(requirement["scenarios"]) {
		scenario := item.(map[string]any)
		values = append(values, stringValue(scenario["scenarioId"]), stringValue(scenario["witnessId"]), stringValue(scenario["witnessKind"]), stringValue(scenario["witnessPath"]))
		values = append(values, stringArray(scenario["commandIds"])...)
		values = append(values, stringArray(scenario["environmentClasses"])...)
	}
	values = append(values, stringArray(requirement["nonClaims"])...)
	return values
}

func scenarioIDs(requirement map[string]any) []string {
	values := []string{}
	for _, item := range anyArray(requirement["scenarios"]) {
		values = append(values, stringValue(item.(map[string]any)["scenarioId"]))
	}
	return values
}

func inlineCodeListOrNone(values []string) string {
	return markdownfmt.CodeListOrNone(values)
}

func plainListOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	escaped := make([]string, 0, len(values))
	for _, value := range values {
		escaped = append(escaped, markdownText(value))
	}
	return strings.Join(escaped, ", ")
}

func inlineCode(value string) string {
	return markdownfmt.CodeSpan(value)
}

func markdownText(value string) string {
	return markdownfmt.Text(value)
}

func sortedUnique(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func anyArray(raw any) []any {
	if values, ok := raw.([]any); ok {
		return values
	}
	return []any{}
}

func stringArray(raw any) []string {
	return admit.AnySliceToString(anyArray(raw))
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func intValue(raw any) int {
	value, _ := raw.(int)
	return value
}
