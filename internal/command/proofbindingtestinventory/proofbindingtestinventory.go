package proofbindingtestinventory

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const ProjectionKind = "proofkit.proof-binding-test-inventory"

var projectionNonClaims = []string{
	"Proof-binding-derived test inventories do not execute native tests or authenticate receipts.",
	"Proof-binding-derived test inventories do not prove repository inventory completeness, proof freshness, merge approval, release approval, rollout approval, or production readiness.",
	"Proof-binding-derived test inventories project caller-owned proof binding falsification witnesses and remain subject to caller-owned coverage universes.",
}

type Input struct {
	CommandRefPrefix string
	CompactProof     any
	InventoryID      string
	NonClaims        []string
	RequirementOwner map[string]string
}

type Projection struct {
	CommandRefs []string
	Entries     []map[string]any
	Inventory   map[string]any
	NonClaims   []string
}

func Build(raw any) (any, int, error) {
	projection, err := Project(raw)
	if err != nil {
		return nil, 1, err
	}
	return projectionValue(projection), 0, nil
}

func BuildReport(raw any) (report.Record, int, error) {
	projection, err := Project(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	return testevidenceinventory.Build(projection.Inventory)
}

func BuildNormalized(raw any) (map[string]any, int, error) {
	projection, err := Project(raw)
	if err != nil {
		return nil, 1, err
	}
	normalized, exitCode, err := testevidenceinventory.BuildNormalized(projection.Inventory)
	if err != nil || exitCode != 0 {
		return normalized, exitCode, err
	}
	normalized["projectionKind"] = ProjectionKind
	normalized["projectionSummary"] = map[string]any{
		"commandRefCount": len(projection.CommandRefs),
		"entryCount":      len(projection.Entries),
	}
	return normalized, 0, nil
}

func Project(raw any) (Projection, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Projection{}, err
	}
	projection, err := project(input)
	if err != nil {
		return Projection{}, err
	}
	if result, err := testevidenceinventory.Evaluate(projection.Inventory); err != nil {
		return Projection{}, err
	} else if result.ExitCode != 0 {
		return Projection{}, fmt.Errorf("derived test evidence inventory failed downstream admission: %s", strings.Join(result.Failures, "; "))
	}
	return projection, nil
}

func projectionValue(projection Projection) map[string]any {
	return map[string]any{
		"commandRefs":    admit.StringSliceToAny(projection.CommandRefs),
		"entryCount":     len(projection.Entries),
		"inventory":      projection.Inventory,
		"inventoryId":    projection.Inventory["inventoryId"],
		"nonClaims":      admit.StringSliceToAny(projection.NonClaims),
		"projectionKind": ProjectionKind,
		"schemaVersion":  json.Number("1"),
	}
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("proof-binding test inventory input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commandRefPolicy", "compactProofContract", "inventoryId", "nonClaims", "requirementSource", "schemaVersion"}, "proof-binding test inventory input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("proof-binding test inventory schemaVersion must be 1")
	}
	inventoryID, err := admit.RuleID(record["inventoryId"], "proof-binding test inventory inventoryId")
	if err != nil {
		return Input{}, err
	}
	prefix, err := commandRefPrefix(record["commandRefPolicy"])
	if err != nil {
		return Input{}, err
	}
	owners, err := requirementOwners(record["requirementSource"])
	if err != nil {
		return Input{}, err
	}
	nonClaims, err := optionalSortedText(record["nonClaims"], "proof-binding test inventory nonClaims")
	if err != nil {
		return Input{}, err
	}
	return Input{
		CommandRefPrefix: prefix,
		CompactProof:     record["compactProofContract"],
		InventoryID:      inventoryID,
		NonClaims:        nonClaims,
		RequirementOwner: owners,
	}, nil
}

func commandRefPrefix(raw any) (string, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return "", fmt.Errorf("proof-binding test inventory commandRefPolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"prefix"}, "proof-binding test inventory commandRefPolicy"); err != nil {
		return "", err
	}
	return admit.RuleID(record["prefix"], "proof-binding test inventory commandRefPolicy.prefix")
}

func requirementOwners(raw any) (map[string]string, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("proof-binding test inventory requirementSource must be an object")
	}
	requirements, ok := record["requirements"].([]any)
	if !ok {
		return nil, fmt.Errorf("proof-binding test inventory requirementSource.requirements must be an array")
	}
	owners := map[string]string{}
	for index, value := range requirements {
		requirement, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("proof-binding test inventory requirementSource.requirements[%d] must be an object", index)
		}
		requirementID, err := admit.RuleID(requirement["requirementId"], fmt.Sprintf("proof-binding test inventory requirement #%d requirementId", index+1))
		if err != nil {
			return nil, err
		}
		ownerID, err := admit.RuleID(requirement["ownerId"], fmt.Sprintf("proof-binding test inventory requirement %s ownerId", requirementID))
		if err != nil {
			return nil, err
		}
		if previous, ok := owners[requirementID]; ok {
			return nil, fmt.Errorf("proof-binding test inventory duplicate requirement owner for %s: %s and %s", requirementID, previous, ownerID)
		}
		owners[requirementID] = ownerID
	}
	return owners, nil
}

func optionalSortedText(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	values, err := admit.TextArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	return admit.PreserveSortedText(values, context, true)
}

func project(input Input) (Projection, error) {
	contract, err := compactproofcontract.Admit(input.CompactProof)
	if err != nil {
		return Projection{}, err
	}
	routes := contract.FalsificationRoutes()
	commandByRef := map[string]string{}
	commandRefs := map[string]struct{}{}
	entries := make([]map[string]any, 0, len(routes))
	for _, route := range routes {
		ownerID, ok := input.RequirementOwner[route.RequirementID]
		if !ok {
			return Projection{}, fmt.Errorf("proof-binding test inventory requirement %s has no owner in requirementSource", route.RequirementID)
		}
		sourcePath, err := structuredSelectorPath(route.FalsificationSelector, "proof-binding test inventory "+route.RequirementID+" falsification selector")
		if err != nil {
			return Projection{}, err
		}
		entryCommandRefs, err := commandRefsFor(input.CommandRefPrefix, route.SurfaceID, route.VerifyCommands, commandByRef)
		if err != nil {
			return Projection{}, err
		}
		if len(entryCommandRefs) == 0 {
			return Projection{}, fmt.Errorf("proof-binding test inventory %s semantic falsifier requires at least one verify command", route.RequirementID)
		}
		for _, ref := range entryCommandRefs {
			commandRefs[ref] = struct{}{}
		}
		requirementSlug := ruleFragment(route.RequirementID)
		invariantSlug := truncateRuleFragment(ruleFragment(route.OwnedInvariant), 64)
		entries = append(entries, map[string]any{
			"commandRefs":        admit.StringSliceToAny(entryCommandRefs),
			"evidenceClass":      "semantic_falsifier",
			"falsifier":          falsifierValue(route.SurfaceID, requirementSlug, invariantSlug),
			"nonClaims":          admit.StringSliceToAny(entryNonClaims()),
			"oracle":             oracleValue(route.RequirementID, route.SurfaceID, requirementSlug),
			"ownerId":            ownerID,
			"ownerInvariantRefs": []any{},
			"requirementRefs":    []any{route.RequirementID},
			"selector":           route.FalsificationSelector,
			"sourcePath":         sourcePath,
			"testId":             "test." + route.SurfaceID + "." + requirementSlug,
			"witnessRefs":        []any{},
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left]["testId"].(string) < entries[right]["testId"].(string)
	})
	allCommandRefs := keys(commandRefs)
	nonClaims := sortedUnique(append(append([]string{}, projectionNonClaims...), input.NonClaims...))
	inventory := map[string]any{
		"authority":     "caller_owned_inventory",
		"entries":       entriesToAny(entries),
		"inventoryId":   input.InventoryID,
		"nonClaims":     admit.StringSliceToAny(nonClaims),
		"schemaVersion": json.Number("1"),
	}
	return Projection{CommandRefs: allCommandRefs, Entries: entries, Inventory: inventory, NonClaims: nonClaims}, nil
}

func structuredSelectorPath(selector string, context string) (string, error) {
	parts := strings.Split(selector, "::")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("%s must use repo/path::stable_anchor selector identity", context)
	}
	sourcePath, err := admit.SafeRepoRelativePath(parts[0], context+" source path")
	if err != nil {
		return "", err
	}
	if _, err := admit.RuleID(parts[1], context+" anchor"); err != nil {
		return "", err
	}
	return sourcePath, nil
}

func commandRefsFor(prefix string, surfaceID string, commands []string, commandByRef map[string]string) ([]string, error) {
	refs := map[string]struct{}{}
	for _, command := range commands {
		ref := prefix + "." + surfaceID + ".verify." + truncateRuleFragment(ruleFragment(command), 96)
		ref, err := admit.RuleID(ref, "proof-binding test inventory derived commandRef")
		if err != nil {
			return nil, err
		}
		if previous, ok := commandByRef[ref]; ok && previous != command {
			return nil, fmt.Errorf("proof-binding test inventory commandRef collision for %s", ref)
		}
		commandByRef[ref] = command
		refs[ref] = struct{}{}
	}
	return keys(refs), nil
}

func ruleFragment(value string) string {
	var builder strings.Builder
	lastSeparator := false
	for _, character := range strings.ToLower(value) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			builder.WriteRune(character)
			lastSeparator = false
			continue
		}
		if !lastSeparator {
			builder.WriteByte('_')
			lastSeparator = true
		}
	}
	fragment := strings.Trim(builder.String(), "_")
	if fragment == "" || !unicode.IsLetter([]rune(fragment)[0]) {
		return "ref_" + fragment
	}
	return fragment
}

func truncateRuleFragment(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func falsifierValue(surfaceID string, requirementSlug string, invariantSlug string) map[string]any {
	return map[string]any{
		"dominanceGroup":             surfaceID + "." + invariantSlug,
		"falsifierId":                "falsifier." + surfaceID + "." + requirementSlug,
		"negativeCaseId":             "case." + surfaceID + "." + requirementSlug + ".falsification_witness",
		"supersedes":                 []any{},
		"wrongImplementationClassId": "wrong." + surfaceID + "." + invariantSlug,
	}
}

func oracleValue(requirementID string, surfaceID string, requirementSlug string) map[string]any {
	return map[string]any{
		"assertionSummary":      "The selected canonical proof binding supplies a falsification witness for " + requirementID + ".",
		"expectedPublicOutcome": "coverage remains failed unless the selected requirement has an admitted falsification witness and executable command ref",
		"oracleId":              "oracle." + surfaceID + "." + requirementSlug,
		"oracleKind":            "canonical_binding_falsification_witness",
	}
}

func entryNonClaims() []string {
	return []string{
		"This inventory entry declares selected-owner semantic falsifier coverage and must remain consistent with canonical proof-binding falsification witnesses.",
		"This inventory entry does not execute native tests or authenticate receipts.",
	}
}

func entriesToAny(entries []map[string]any) []any {
	values := make([]any, len(entries))
	for index, entry := range entries {
		values[index] = entry
	}
	return values
}

func keys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			out = append(out, value)
		}
		previous = value
	}
	return out
}
