package requirementsourceview

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/browserdoc"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
)

var defaultNonClaims = []string{
	"Requirement source views are rendered presentation products only.",
	"Requirement source views do not own requirement meaning.",
	"Requirement source views do not read or lint overview Markdown.",
	"Requirement source views do not prove proof-binding adequacy.",
	"Requirement source views do not execute native witnesses.",
	"Requirement source views do not prove receipt freshness, merge approval, or rollout readiness.",
}

func BuildJSON(raw any) (any, int, error) {
	view, err := build(raw)
	if err != nil {
		return nil, 1, err
	}
	return view, 0, nil
}

func BuildMarkdown(raw any) (string, int, error) {
	view, err := build(raw)
	if err != nil {
		return "", 1, err
	}
	return markdown(view) + "\n", 0, nil
}

func BuildHTML(raw any) (string, int, error) {
	view, err := build(raw)
	if err != nil {
		return "", 1, err
	}
	return html(view), 0, nil
}

func BuildBrowserDocument(raw any) (map[string]any, string, error) {
	view, err := build(raw)
	if err != nil {
		return nil, "", err
	}
	return view, html(view), nil
}

func build(raw any) (map[string]any, error) {
	result, err := requirementsourceadmission.Evaluate(raw)
	if err != nil {
		return nil, err
	}
	if result.Report.State != "passed" {
		return nil, fmt.Errorf("cannot build requirement source view from failed requirement source admission")
	}
	requirements := make([]any, 0, len(result.Source.Requirements))
	active := 0
	blocking := 0
	deferred := 0
	for _, requirement := range result.Source.Requirements {
		if requirement.Lifecycle.State == "active" {
			active++
		}
		if requirement.ClaimLevel == "blocking" {
			blocking++
		}
		if requirement.ClaimLevel == "deferred" {
			deferred++
		}
		requirements = append(requirements, viewRequirement(requirement))
	}
	nonClaims := append([]string{}, defaultNonClaims...)
	nonClaims = append(nonClaims, result.Source.NonClaims...)
	return map[string]any{
		"activeRequirementCount":   active,
		"authority":                "presentation_only",
		"blockingRequirementCount": blocking,
		"deferredRequirementCount": deferred,
		"nonClaims":                admit.StringSliceToAny(sortedUnique(nonClaims)),
		"overviewPath":             result.Source.OverviewPath,
		"requirementCount":         len(requirements),
		"requirements":             requirements,
		"requirementsPath":         result.Source.RequirementsPath,
		"schemaVersion":            1,
		"sourceId":                 result.Source.SourceID,
		"specPackagePath":          result.Source.SpecPackagePath,
		"viewKind":                 "proofkit.requirement-source-view",
	}, nil
}

func viewRequirement(requirement requirementsourceadmission.Requirement) map[string]any {
	value := map[string]any{
		"claimLevel":                requirement.ClaimLevel,
		"deferral":                  nil,
		"invariant":                 requirement.Invariant,
		"lifecycleEvidenceRefs":     admit.StringSliceToAny(requirement.Lifecycle.EvidenceRefs),
		"lifecycleState":            requirement.Lifecycle.State,
		"nonClaimRefs":              admit.StringSliceToAny(requirement.NonClaimRefs),
		"nonClaims":                 admit.StringSliceToAny(requirement.NonClaims),
		"ownerId":                   requirement.OwnerID,
		"proofBindingRefs":          admit.StringSliceToAny(requirement.ProofBindingRefs),
		"replacementRequirementIds": admit.StringSliceToAny(requirement.Lifecycle.ReplacementRequirementIDs),
		"requirementId":             requirement.RequirementID,
		"riskClass":                 requirement.RiskClass,
		"updatePolicy": map[string]any{
			"requiresImpactDeclaration":  requirement.UpdatePolicy.RequiresImpactDeclaration,
			"requiresProofBindingReview": requirement.UpdatePolicy.RequiresProofBindingReview,
			"reviewOwnerId":              requirement.UpdatePolicy.ReviewOwnerID,
		},
	}
	if requirement.Deferral != nil {
		value["deferral"] = map[string]any{
			"evidenceRefs":    admit.StringSliceToAny(requirement.Deferral.EvidenceRefs),
			"expiryRef":       requirement.Deferral.ExpiryRef,
			"mergePolicy":     requirement.Deferral.MergePolicy,
			"ownerId":         requirement.Deferral.OwnerID,
			"reviewCondition": requirement.Deferral.ReviewCondition,
			"riskAcceptedBy":  requirement.Deferral.RiskAcceptedBy,
		}
	}
	return value
}

func markdown(view map[string]any) string {
	lines := []string{
		"# Requirement Source View: " + stringValue(view["sourceId"]),
		"",
		"Authority: " + stringValue(view["authority"]),
		"Spec package: " + markdownfmt.CodeSpan(stringValue(view["specPackagePath"])),
		"Overview: " + markdownfmt.CodeSpan(stringValue(view["overviewPath"])),
		"Requirements source: " + markdownfmt.CodeSpan(stringValue(view["requirementsPath"])),
		fmt.Sprintf("Requirements: %d", intValue(view["requirementCount"])),
		fmt.Sprintf("Active: %d", intValue(view["activeRequirementCount"])),
		fmt.Sprintf("Blocking: %d", intValue(view["blockingRequirementCount"])),
		fmt.Sprintf("Deferred: %d", intValue(view["deferredRequirementCount"])),
		"",
		"## Requirements",
		"",
	}
	for _, item := range anyArray(view["requirements"]) {
		requirement := item.(map[string]any)
		lines = append(lines,
			"### "+stringValue(requirement["requirementId"]),
			"",
			markdownText(stringValue(requirement["invariant"])),
			"",
			"- Owner: "+markdownText(stringValue(requirement["ownerId"])),
			"- Claim level: "+markdownText(stringValue(requirement["claimLevel"])),
			"- Risk class: "+markdownText(stringValue(requirement["riskClass"])),
			"- Lifecycle: "+markdownText(stringValue(requirement["lifecycleState"])),
			"- Replacement requirements: "+inlineCodeListOrNone(stringArray(requirement["replacementRequirementIds"])),
			"- Lifecycle evidence: "+inlineCodeListOrNone(stringArray(requirement["lifecycleEvidenceRefs"])),
			"- Proof bindings: "+inlineCodeListOrNone(stringArray(requirement["proofBindingRefs"])),
			"- Non-claim refs: "+inlineCodeListOrNone(stringArray(requirement["nonClaimRefs"])),
			"- Impact declaration required: "+fmt.Sprint(boolValue(requirement, "updatePolicy", "requiresImpactDeclaration")),
			"- Proof-binding review required: "+fmt.Sprint(boolValue(requirement, "updatePolicy", "requiresProofBindingReview")),
			"- Review owner: "+stringValue(requirement["updatePolicy"].(map[string]any)["reviewOwnerId"]),
			"",
			"Non-claims:",
			"",
		)
		for _, claim := range stringArray(requirement["nonClaims"]) {
			lines = append(lines, "- "+markdownText(claim))
		}
		lines = append(lines, "")
		if deferral, ok := requirement["deferral"].(map[string]any); ok {
			lines = append(lines,
				"Deferral:",
				"",
				"- Owner: "+markdownText(stringValue(deferral["ownerId"])),
				"- Risk accepted by: "+markdownText(stringValue(deferral["riskAcceptedBy"])),
				"- Review condition: "+markdownText(stringValue(deferral["reviewCondition"])),
				"- Expiry ref: "+markdownText(stringValue(deferral["expiryRef"])),
				"- Merge policy: "+markdownText(stringValue(deferral["mergePolicy"])),
				"- Evidence refs: "+inlineCodeListOrNone(stringArray(deferral["evidenceRefs"])),
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
	ownerValues := []string{}
	claimValues := []string{}
	riskValues := []string{}
	lifecycleValues := []string{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		owner := stringValue(requirement["ownerId"])
		claim := stringValue(requirement["claimLevel"])
		risk := stringValue(requirement["riskClass"])
		lifecycle := stringValue(requirement["lifecycleState"])
		ownerValues = append(ownerValues, owner)
		claimValues = append(claimValues, claim)
		riskValues = append(riskValues, risk)
		lifecycleValues = append(lifecycleValues, lifecycle)
		search := browserdoc.SearchText(append([]string{
			stringValue(requirement["requirementId"]),
			owner,
			stringValue(requirement["invariant"]),
			claim,
			risk,
			lifecycle,
		}, append(append(append(append(stringArray(requirement["replacementRequirementIds"]), stringArray(requirement["lifecycleEvidenceRefs"])...), stringArray(requirement["proofBindingRefs"])...), stringArray(requirement["nonClaimRefs"])...), stringArray(requirement["nonClaims"])...)...))
		filters := []browserdoc.FilterValue{
			{Key: "owner", Value: owner},
			{Key: "claim-level", Value: claim},
			{Key: "risk-class", Value: risk},
			{Key: "lifecycle", Value: lifecycle},
		}
		cards = append(cards, browserdoc.Card{
			ID:           stringValue(requirement["requirementId"]),
			Title:        stringValue(requirement["invariant"]),
			GroupID:      "owner:" + owner,
			GroupLabel:   "Owner: " + owner,
			Body:         sourceRequirementBody(requirement),
			SearchText:   search,
			FilterValues: filters,
		})
		rows = append(rows, browserdoc.Row{
			ID: stringValue(requirement["requirementId"]),
			Cells: []browserdoc.Cell{
				browserdoc.TableCell("requirement", stringValue(requirement["requirementId"]), true),
				browserdoc.TableCell("owner", owner, false),
				browserdoc.TableCell("invariant", stringValue(requirement["invariant"]), false),
				browserdoc.TableCell("claimLevel", claim, false),
				browserdoc.TableCell("riskClass", risk, false),
				browserdoc.TableCell("lifecycle", lifecycle, false),
				{Key: "proofBindings", Value: browserdoc.ListOrNone(stringArray(requirement["proofBindingRefs"]), true)},
			},
			SearchText:   browserdoc.SearchText(append([]string{stringValue(requirement["requirementId"]), owner, stringValue(requirement["invariant"]), claim, risk, lifecycle}, stringArray(requirement["proofBindingRefs"])...)),
			FilterValues: filters,
		})
	}
	return browserdoc.HTML(browserdoc.Document{
		Title:     "Requirement Source View: " + stringValue(view["sourceId"]),
		Authority: stringValue(view["authority"]),
		SummaryItems: []browserdoc.SummaryItem{
			browserdoc.Summary("Spec package", stringValue(view["specPackagePath"]), true),
			browserdoc.Summary("Overview", stringValue(view["overviewPath"]), true),
			browserdoc.Summary("Requirements source", stringValue(view["requirementsPath"]), true),
			browserdoc.Summary("Requirements", fmt.Sprint(intValue(view["requirementCount"])), false),
			browserdoc.Summary("Active", fmt.Sprint(intValue(view["activeRequirementCount"])), false),
			browserdoc.Summary("Blocking", fmt.Sprint(intValue(view["blockingRequirementCount"])), false),
			browserdoc.Summary("Deferred", fmt.Sprint(intValue(view["deferredRequirementCount"])), false),
		},
		HierarchySections: []browserdoc.HierarchySection{
			{
				Title: "Specification hierarchy",
				Items: []browserdoc.HierarchyItem{
					{Label: stringValue(view["specPackagePath"]), Detail: "package"},
					{Label: stringValue(view["overviewPath"]), Detail: "overview"},
					{Label: stringValue(view["requirementsPath"]), Detail: "structured records"},
				},
			},
			{Title: "Owners", Items: ownerHierarchy(requirements)},
		},
		Filters: []browserdoc.Filter{
			browserdoc.NewFilter("owner", "Owner", ownerValues),
			browserdoc.NewFilter("claim-level", "Claim level", claimValues),
			browserdoc.NewFilter("risk-class", "Risk class", riskValues),
			browserdoc.NewFilter("lifecycle", "Lifecycle", lifecycleValues),
		},
		Cards: cards,
		Table: &browserdoc.Table{
			Columns: []browserdoc.Column{
				{Key: "requirement", Label: "Requirement"},
				{Key: "owner", Label: "Owner"},
				{Key: "invariant", Label: "Invariant"},
				{Key: "claimLevel", Label: "Claim"},
				{Key: "riskClass", Label: "Risk"},
				{Key: "lifecycle", Label: "Lifecycle"},
				{Key: "proofBindings", Label: "Proof bindings"},
			},
			Rows: rows,
		},
		NonClaims: stringArray(view["nonClaims"]),
	})
}

func sourceRequirementBody(requirement map[string]any) browserdoc.Fragment {
	policy := requirement["updatePolicy"].(map[string]any)
	parts := []browserdoc.Fragment{browserdoc.DefinitionList(
		browserdoc.Definition("Owner", browserdoc.Text(stringValue(requirement["ownerId"]))),
		browserdoc.Definition("Claim level", browserdoc.Text(stringValue(requirement["claimLevel"]))),
		browserdoc.Definition("Risk class", browserdoc.Text(stringValue(requirement["riskClass"]))),
		browserdoc.Definition("Lifecycle", browserdoc.Text(stringValue(requirement["lifecycleState"]))),
		browserdoc.Definition("Replacement requirements", browserdoc.ListOrNone(stringArray(requirement["replacementRequirementIds"]), true)),
		browserdoc.Definition("Lifecycle evidence", browserdoc.ListOrNone(stringArray(requirement["lifecycleEvidenceRefs"]), true)),
		browserdoc.Definition("Proof bindings", browserdoc.ListOrNone(stringArray(requirement["proofBindingRefs"]), true)),
		browserdoc.Definition("Non-claim refs", browserdoc.ListOrNone(stringArray(requirement["nonClaimRefs"]), true)),
		browserdoc.Definition("Impact declaration required", browserdoc.Text(fmt.Sprint(policy["requiresImpactDeclaration"]))),
		browserdoc.Definition("Proof-binding review required", browserdoc.Text(fmt.Sprint(policy["requiresProofBindingReview"]))),
		browserdoc.Definition("Review owner", browserdoc.Text(stringValue(policy["reviewOwnerId"]))),
	)}
	if deferral, ok := requirement["deferral"].(map[string]any); ok {
		parts = append(parts, htmlDeferral(deferral))
	}
	parts = append(parts, browserdoc.Heading(3, "Non-claims"), browserdoc.ListOrNone(stringArray(requirement["nonClaims"]), false))
	return browserdoc.Concat(parts...)
}

func htmlDeferral(deferral map[string]any) browserdoc.Fragment {
	return browserdoc.Concat(
		browserdoc.Heading(3, "Deferral"),
		browserdoc.DefinitionList(
			browserdoc.Definition("Owner", browserdoc.Text(stringValue(deferral["ownerId"]))),
			browserdoc.Definition("Risk accepted by", browserdoc.Text(stringValue(deferral["riskAcceptedBy"]))),
			browserdoc.Definition("Review condition", browserdoc.Text(stringValue(deferral["reviewCondition"]))),
			browserdoc.Definition("Expiry ref", browserdoc.Text(stringValue(deferral["expiryRef"]))),
			browserdoc.Definition("Merge policy", browserdoc.Text(stringValue(deferral["mergePolicy"]))),
			browserdoc.Definition("Evidence refs", browserdoc.ListOrNone(stringArray(deferral["evidenceRefs"]), true)),
		),
	)
}

func ownerHierarchy(requirements []any) []browserdoc.HierarchyItem {
	counts := map[string]int{}
	for _, item := range requirements {
		requirement := item.(map[string]any)
		counts[stringValue(requirement["ownerId"])]++
	}
	owners := make([]string, 0, len(counts))
	for owner := range counts {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	items := make([]browserdoc.HierarchyItem, 0, len(owners))
	for _, owner := range owners {
		items = append(items, browserdoc.HierarchyItem{
			Label:  owner,
			Detail: fmt.Sprintf("%d requirement(s)", counts[owner]),
			Href:   "#" + browserdoc.FragmentID("owner:"+owner),
		})
	}
	return items
}

func inlineCodeListOrNone(values []string) string {
	return markdownfmt.CodeListOrNone(values)
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

func boolValue(record map[string]any, key string, nested string) bool {
	child, _ := record[key].(map[string]any)
	value, _ := child[nested].(bool)
	return value
}
