package requirementproofview

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

var scopeChoices = []string{"graph", "slice"}

func ScopeChoices() []string {
	return slices.Clone(scopeChoices)
}

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
	for _, key := range []string{
		"authority_state",
		"binding_columns",
		"contract_id",
		"contract_kind",
		"normalization_profile",
		"schema_version",
		"surface_columns",
		"witness_columns",
	} {
		if _, exists := record[key]; exists {
			return true
		}
	}
	return false
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

func BuildBrowserDocument(raw any, options Options) (map[string]any, string, error) {
	view, err := build(raw, options)
	if err != nil {
		return nil, "", err
	}
	if stringValue(view["viewKind"]) == "proofkit.compact-requirement-proof-view" {
		return view, compactHTML(view), nil
	}
	return view, html(view), nil
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
	if !slices.Contains(scopeChoices, scope) {
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
	bindings := anyArray(record["bindings"])
	viewBindings := make([]any, 0, len(bindings))
	requirementSet := map[string]struct{}{}
	preconditioned := 0
	for _, item := range bindings {
		binding := compactBinding(item.(map[string]any))
		viewBindings = append(viewBindings, binding)
		requirementSet[stringValue(binding["requirementId"])] = struct{}{}
		if value, _ := binding["preconditioned"].(bool); value {
			preconditioned++
		}
	}
	nonClaims := append([]string{}, defaultNonClaims...)
	nonClaims = append(nonClaims, stringArray(record["nonClaims"])...)
	nonClaims = append(nonClaims,
		"Compact requirement proof views are rendered from explicit compact contract facts only.",
		"Compact requirement proof views do not infer spec paths, owner routes, or local environment policy.",
	)
	return map[string]any{
		"authority":                  "lookup_only",
		"bindingCount":               len(viewBindings),
		"bindings":                   viewBindings,
		"commandCount":               len(anyArray(record["commands"])),
		"contractId":                 record["contractId"],
		"localEnvironmentPolicy":     record["localEnvironmentPolicy"],
		"nonClaims":                  admit.StringSliceToAny(sortedUnique(nonClaims)),
		"preconditionedBindingCount": preconditioned,
		"requirementCount":           len(requirementSet),
		"schemaVersion":              2,
		"viewKind":                   "proofkit.compact-requirement-proof-view",
	}, nil
}

func compactBinding(binding map[string]any) map[string]any {
	witnesses := binding["testWitnesses"].(map[string]any)
	routes := []any{
		compactWitnessRoute(binding["bindingRecordId"], witnesses["falsification"].(map[string]any)),
		compactWitnessRoute(binding["bindingRecordId"], witnesses["positive"].(map[string]any)),
	}
	return map[string]any{
		"bindingRecordId":                   binding["bindingRecordId"],
		"blockingStatus":                    binding["blockingStatus"],
		"declaredMutationResistanceClaimId": binding["declaredMutationResistanceClaimId"],
		"declaredWitnessRoutes":             routes,
		"invariantRole":                     binding["invariantRole"],
		"ownedInvariant":                    binding["ownedInvariant"],
		"preconditioned":                    binding["preconditioned"],
		"requiredEnvironmentClasses":        binding["requiredEnvironmentClasses"],
		"requirementId":                     binding["requirementId"],
		"scenarioId":                        binding["scenarioId"],
		"surfaceId":                         binding["surfaceId"],
		"verifyCommands":                    binding["verifyCommands"],
	}
}

func compactWitnessRoute(bindingRecordID any, witness map[string]any) map[string]any {
	return map[string]any{
		"bindingRecordId":      bindingRecordID,
		"environmentClasses":   witness["environmentClasses"],
		"resolutionOrderIndex": witness["resolutionOrderIndex"],
		"role":                 witness["role"],
		"selector":             witness["selector"],
		"verifyCommands":       witness["verifyCommandRefs"],
		"witnessRouteId":       witness["witnessRouteId"],
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
		fmt.Sprintf("Bindings: %d", intValue(view["bindingCount"])),
		fmt.Sprintf("Requirements: %d", intValue(view["requirementCount"])),
		fmt.Sprintf("Preconditioned bindings: %d", intValue(view["preconditionedBindingCount"])),
		fmt.Sprintf("Commands: %d", intValue(view["commandCount"])),
		"Local environment policy: " + plainListOrNone(stringArray(policy["localEnvironmentClasses"])),
		"",
		"## Bindings",
		"",
	}
	bindings := anyArray(view["bindings"])
	if len(bindings) == 0 {
		lines = append(lines, "No bindings declared.", "")
	} else {
		for _, item := range bindings {
			binding := item.(map[string]any)
			lines = append(lines,
				"### "+markdownText(stringValue(binding["requirementId"]))+" / "+markdownText(stringValue(binding["scenarioId"])),
				"",
				"- Binding record: "+inlineCode(stringValue(binding["bindingRecordId"])),
				"- Surface: "+markdownText(stringValue(binding["surfaceId"])),
				"- Invariant: "+markdownText(stringValue(binding["ownedInvariant"])),
				"- Invariant role: "+markdownText(stringValue(binding["invariantRole"])),
				"- Blocking: "+markdownText(stringValue(binding["blockingStatus"])),
				"- Preconditioned: "+fmt.Sprint(binding["preconditioned"]),
				"- Caller mutation-resistance claim: "+inlineCode(stringValue(binding["declaredMutationResistanceClaimId"])),
				"- Commands: "+inlineCodeListOrNone(stringArray(binding["verifyCommands"])),
				"- Environments: "+plainListOrNone(stringArray(binding["requiredEnvironmentClasses"])),
			)
			for _, routeValue := range anyArray(binding["declaredWitnessRoutes"]) {
				route := routeValue.(map[string]any)
				lines = append(lines,
					"- "+markdownText(stringValue(route["role"]))+" witness: "+inlineCode(stringValue(route["selector"])),
					"  route: "+inlineCode(stringValue(route["witnessRouteId"]))+"; order: "+fmt.Sprint(route["resolutionOrderIndex"])+"; commands: "+inlineCodeListOrNone(stringArray(route["verifyCommands"])),
				)
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
	bindings := anyArray(view["bindings"])
	cards := make([]browserdoc.Card, 0, len(bindings))
	rows := make([]browserdoc.Row, 0, len(bindings))
	surfaces := []string{}
	blockingValues := []string{}
	invariantRoles := []string{}
	preconditionedValues := []string{}
	for _, item := range bindings {
		binding := item.(map[string]any)
		surface := stringValue(binding["surfaceId"])
		blocking := stringValue(binding["blockingStatus"])
		invariantRole := stringValue(binding["invariantRole"])
		preconditioned := fmt.Sprint(binding["preconditioned"])
		surfaces = append(surfaces, surface)
		blockingValues = append(blockingValues, blocking)
		invariantRoles = append(invariantRoles, invariantRole)
		preconditionedValues = append(preconditionedValues, preconditioned)
		filters := []browserdoc.FilterValue{{Key: "surface", Value: surface}, {Key: "blocking", Value: blocking}, {Key: "invariant-role", Value: invariantRole}, {Key: "preconditioned", Value: preconditioned}}
		routeSearch := compactRouteSearchValues(binding)
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(binding["bindingRecordId"]),
			Title:        stringValue(binding["ownedInvariant"]),
			GroupID:      "surface:" + surface,
			GroupLabel:   "Surface: " + surface,
			Body:         compactProofBindingBody(binding),
			SearchText:   browserdoc.SearchText(append([]string{stringValue(binding["bindingRecordId"]), stringValue(binding["requirementId"]), surface, stringValue(binding["scenarioId"]), invariantRole, stringValue(binding["ownedInvariant"]), blocking, preconditioned, stringValue(binding["declaredMutationResistanceClaimId"])}, append(stringArray(binding["verifyCommands"]), append(stringArray(binding["requiredEnvironmentClasses"]), routeSearch...)...)...)),
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(binding["bindingRecordId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("binding", stringValue(binding["bindingRecordId"]), true),
				browserdoc.TableCell("requirement", stringValue(binding["requirementId"]), true),
				browserdoc.TableCell("surface", surface, false),
				browserdoc.TableCell("scenario", stringValue(binding["scenarioId"]), false),
				browserdoc.TableCell("invariant", stringValue(binding["ownedInvariant"]), false),
				browserdoc.TableCell("blocking", blocking, false),
				browserdoc.TableCell("preconditioned", preconditioned, false),
				{Key: "commands", Value: browserdoc.ListOrNone(stringArray(binding["verifyCommands"]), true)},
				{Key: "witnesses", Value: browserdoc.ListOrNone(compactRouteLabels(binding), true)},
			},
			SearchText:   browserdoc.SearchText(append([]string{stringValue(binding["bindingRecordId"]), stringValue(binding["requirementId"]), surface, stringValue(binding["scenarioId"]), stringValue(binding["ownedInvariant"]), blocking, preconditioned}, append(stringArray(binding["verifyCommands"]), routeSearch...)...)),
			FilterValues: filters,
		})
	}
	policy := view["localEnvironmentPolicy"].(map[string]any)
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Compact Requirement Proof View: " + stringValue(view["contractId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("Bindings", fmt.Sprint(intValue(view["bindingCount"])), false),
			browserdoc.Summary("Requirements", fmt.Sprint(intValue(view["requirementCount"])), false),
			browserdoc.Summary("Preconditioned bindings", fmt.Sprint(intValue(view["preconditionedBindingCount"])), false),
			browserdoc.Summary("Commands", fmt.Sprint(intValue(view["commandCount"])), false),
			{Label: "Local environment policy", Value: browserdoc.ListOrNone(stringArray(policy["localEnvironmentClasses"]), false)},
		},
		HierarchySections: []browserdoc.HierarchySection{
			{Title: "Surface hierarchy", Items: surfaceHierarchy(bindings)},
			{Title: "Environment classes", Items: environmentHierarchy(bindings)},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("surface", "Surface", surfaces),
			browserdoc.NewFilter("blocking", "Blocking", blockingValues),
			browserdoc.NewFilter("invariant-role", "Invariant role", invariantRoles),
			browserdoc.NewFilter("preconditioned", "Preconditioned", preconditionedValues),
		},
		Cards: cards,
		Table: &browserdoc.Table{
			Columns: []browserdoc.Column{
				{Key: "binding", Label: "Binding"},
				{Key: "requirement", Label: "Requirement"},
				{Key: "surface", Label: "Surface"},
				{Key: "scenario", Label: "Scenario"},
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

func compactProofBindingBody(binding map[string]any) browserdoc.Fragment {
	routeDefinitions := make([]browserdoc.DefinitionItem, 0, len(anyArray(binding["declaredWitnessRoutes"]))*4)
	for _, routeValue := range anyArray(binding["declaredWitnessRoutes"]) {
		route := routeValue.(map[string]any)
		prefix := stringValue(route["role"])
		routeDefinitions = append(routeDefinitions,
			browserdoc.Definition(prefix+" route", browserdoc.Code(stringValue(route["witnessRouteId"]))),
			browserdoc.Definition(prefix+" selector", browserdoc.Code(stringValue(route["selector"]))),
			browserdoc.Definition(prefix+" resolution order", browserdoc.Text(fmt.Sprint(route["resolutionOrderIndex"]))),
			browserdoc.Definition(prefix+" commands", browserdoc.ListOrNone(stringArray(route["verifyCommands"]), true)),
		)
	}
	return browserdoc.Concat(
		browserdoc.DefinitionList(
			browserdoc.Definition("Binding record", browserdoc.Code(stringValue(binding["bindingRecordId"]))),
			browserdoc.Definition("Requirement", browserdoc.Text(stringValue(binding["requirementId"]))),
			browserdoc.Definition("Surface", browserdoc.Text(stringValue(binding["surfaceId"]))),
			browserdoc.Definition("Scenario", browserdoc.Text(stringValue(binding["scenarioId"]))),
			browserdoc.Definition("Invariant role", browserdoc.Text(stringValue(binding["invariantRole"]))),
			browserdoc.Definition("Blocking", browserdoc.Text(stringValue(binding["blockingStatus"]))),
			browserdoc.Definition("Preconditioned", browserdoc.Text(fmt.Sprint(binding["preconditioned"]))),
			browserdoc.Definition("Caller mutation-resistance claim", browserdoc.Code(stringValue(binding["declaredMutationResistanceClaimId"]))),
			browserdoc.Definition("Commands", browserdoc.ListOrNone(stringArray(binding["verifyCommands"]), true)),
			browserdoc.Definition("Environments", browserdoc.ListOrNone(stringArray(binding["requiredEnvironmentClasses"]), false)),
		),
		browserdoc.Details("Declared witness routes", browserdoc.DefinitionList(routeDefinitions...)),
	)
}

func compactRouteSearchValues(binding map[string]any) []string {
	values := []string{}
	for _, routeValue := range anyArray(binding["declaredWitnessRoutes"]) {
		route := routeValue.(map[string]any)
		values = append(values, stringValue(route["role"]), stringValue(route["selector"]), stringValue(route["witnessRouteId"]))
		values = append(values, stringArray(route["environmentClasses"])...)
		values = append(values, stringArray(route["verifyCommands"])...)
	}
	return values
}

func compactRouteLabels(binding map[string]any) []string {
	labels := []string{}
	for _, routeValue := range anyArray(binding["declaredWitnessRoutes"]) {
		route := routeValue.(map[string]any)
		labels = append(labels, stringValue(route["role"])+": "+stringValue(route["selector"]))
	}
	return labels
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
