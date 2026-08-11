package requirementcoverageview

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

type admittedCoverageScenario struct {
	bindingRecordID            string
	bindingVerifyCommands      []string
	commandIDs                 []string
	declaredWitnessRoutes      []admittedDeclaredWitnessRoute
	environmentClasses         []string
	requiredEnvironmentClasses []string
	requirementID              string
	scenarioID                 string
	surfaceID                  string
	verifyCommands             []string
	witnessID                  string
}

type admittedDeclaredWitnessRoute struct {
	BindingRecordID    string
	EnvironmentClasses []string
	RequirementID      string
	ResolutionOrder    int
	Role               string
	ScenarioID         string
	Selector           string
	SurfaceID          string
	VerifyCommands     []string
	WitnessRouteID     string
}

func admitRequirementProofProjection(row map[string]any, proofMode string, entries []testevidenceinventory.Entry, context string) error {
	if proofMode == "compact" {
		return admitCompactRequirementProofProjection(row, entries, stringValue(row["requirementId"]), context)
	}
	proofState, ok := row["proofState"].(string)
	if !ok {
		return fmt.Errorf("%s structured proofState must be a string", context)
	}
	if proofState != "" {
		if _, err := admit.Enum(proofState, proofvocab.RequirementProofStateSet(), context+" proofState"); err != nil {
			return err
		}
	}
	scenarios, err := admitCoverageScenarios(row["scenarios"], proofMode, "", context+" scenarios")
	if err != nil {
		return err
	}
	if !wireCountEquals(row["scenarioCount"], len(scenarios)) {
		return fmt.Errorf("%s scenarioCount does not match scenarios", context)
	}
	if (proofState == "witness_backed") != (len(scenarios) > 0) {
		return fmt.Errorf("%s proofState and scenarios are inconsistent", context)
	}
	commandIDs, err := admitProjectedRuleIDs(row["commandIds"], context+" commandIds")
	if err != nil {
		return err
	}
	environmentClasses, err := admitProjectedRuleIDs(row["environmentClasses"], context+" environmentClasses")
	if err != nil {
		return err
	}
	verifyCommands, err := admitProjectedCommands(row["verifyCommands"], context+" verifyCommands")
	if err != nil {
		return err
	}
	witnessRefs, err := admitProjectedRuleIDs(row["witnessRefs"], context+" witnessRefs")
	if err != nil {
		return err
	}
	expectedEnvironments := []string{}
	for _, scenario := range scenarios {
		expectedEnvironments = append(expectedEnvironments, scenario.environmentClasses...)
	}
	if !slices.Equal(environmentClasses, sortedUnique(expectedEnvironments)) {
		return fmt.Errorf("%s environmentClasses are not derived from scenarios", context)
	}
	expectedCommands := []string{}
	expectedWitnesses := []string{}
	for _, scenario := range scenarios {
		expectedCommands = append(expectedCommands, scenario.commandIDs...)
		expectedWitnesses = append(expectedWitnesses, scenario.witnessID)
	}
	if !slices.Equal(commandIDs, sortedUnique(expectedCommands)) {
		return fmt.Errorf("%s commandIds are not derived from scenarios", context)
	}
	if !slices.Equal(witnessRefs, sortedUnique(expectedWitnesses)) {
		return fmt.Errorf("%s witnessRefs are not derived from scenarios", context)
	}
	if len(verifyCommands) != 0 {
		return fmt.Errorf("%s structured proof must not project compact verifyCommands", context)
	}
	return nil
}

func admitCompactRequirementProofProjection(row map[string]any, entries []testevidenceinventory.Entry, parentRequirementID string, context string) error {
	scenarios, err := admitCoverageScenarios(row["scenarios"], "compact", parentRequirementID, context+" scenarios")
	if err != nil {
		return err
	}
	if !wireCountEquals(row["scenarioCount"], len(scenarios)) {
		return fmt.Errorf("%s scenarioCount does not match scenarios", context)
	}
	commandIDs, err := admitProjectedRuleIDs(row["commandIds"], context+" commandIds")
	if err != nil {
		return err
	}
	environmentClasses, err := admitProjectedRuleIDs(row["environmentClasses"], context+" environmentClasses")
	if err != nil {
		return err
	}
	verifyCommands, err := admitProjectedCommands(row["verifyCommands"], context+" verifyCommands")
	if err != nil {
		return err
	}
	routes, err := admitDeclaredWitnessRoutes(row["declaredWitnessRoutes"], context+" declaredWitnessRoutes")
	if err != nil {
		return err
	}
	expectedEnvironments := []string{}
	expectedCommands := []string{}
	expectedRoutes := []admittedDeclaredWitnessRoute{}
	for _, scenario := range scenarios {
		expectedEnvironments = append(expectedEnvironments, scenario.environmentClasses...)
		expectedCommands = append(expectedCommands, scenario.verifyCommands...)
		expectedRoutes = append(expectedRoutes, scenario.declaredWitnessRoutes...)
	}
	if !slices.Equal(environmentClasses, sortedUnique(expectedEnvironments)) {
		return fmt.Errorf("%s environmentClasses are not derived from scenarios", context)
	}
	if !slices.Equal(verifyCommands, sortedUnique(expectedCommands)) {
		return fmt.Errorf("%s verifyCommands are not derived from scenarios", context)
	}
	if !equalCanonicalRouteFacts(routes, expectedRoutes) {
		return fmt.Errorf("%s declaredWitnessRoutes are not the exact scenario route union", context)
	}
	expectedCommandIDs := []string{}
	if len(scenarios) > 0 {
		expectedCommandIDs = entryCommandRefs(entries)
	}
	if !slices.Equal(commandIDs, expectedCommandIDs) {
		return fmt.Errorf("%s commandIds are not derived from projected tests", context)
	}
	return nil
}

func admitCoverageScenarios(raw any, proofMode string, parentRequirementID string, context string) ([]admittedCoverageScenario, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]admittedCoverageScenario, 0, len(values))
	previousID := ""
	for index, rawScenario := range values {
		record, ok := rawScenario.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		scenarioContext := fmt.Sprintf("%s[%d]", context, index)
		environmentClasses, err := admitProjectedRuleIDs(record["environmentClasses"], scenarioContext+" environmentClasses")
		if err != nil {
			return nil, err
		}
		verifyCommands, err := admitProjectedCommands(record["verifyCommands"], scenarioContext+" verifyCommands")
		if err != nil {
			return nil, err
		}
		scenarioID, scenarioSurfaceID, err := admitCoverageScenarioID(record["scenarioId"], proofMode, scenarioContext+" scenarioId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= scenarioID {
			return nil, fmt.Errorf("%s must be sorted and unique by scenarioId", context)
		}
		previousID = scenarioID

		if proofMode == "compact" {
			bindingVerifyCommands, err := admitProjectedCommands(record["bindingVerifyCommands"], scenarioContext+" bindingVerifyCommands")
			if err != nil {
				return nil, err
			}
			requiredEnvironmentClasses, err := admitProjectedRuleIDs(record["requiredEnvironmentClasses"], scenarioContext+" requiredEnvironmentClasses")
			if err != nil {
				return nil, err
			}
			requirementID, err := admit.RuleID(record["requirementId"], scenarioContext+" requirementId")
			if err != nil {
				return nil, err
			}
			if requirementID != parentRequirementID {
				return nil, fmt.Errorf("%s requirementId must match its parent requirement row", scenarioContext)
			}
			surfaceID, err := admit.RuleID(record["surfaceId"], scenarioContext+" surfaceId")
			if err != nil {
				return nil, err
			}
			if scenarioSurfaceID != surfaceID {
				return nil, fmt.Errorf("%s scenarioId must be scoped to surfaceId", scenarioContext)
			}
			bindingRecordID, err := admit.SHA256Ref(record["bindingRecordId"], scenarioContext+" bindingRecordId")
			if err != nil {
				return nil, err
			}
			expectedBindingRecordID, err := compactproofcontract.BindingRecordID(compactproofcontract.BindingIdentity{RequirementID: requirementID, ScenarioID: scenarioID, SurfaceID: surfaceID})
			if err != nil {
				return nil, err
			}
			if bindingRecordID != expectedBindingRecordID {
				return nil, fmt.Errorf("%s bindingRecordId does not match its requirement, surface, and scenario identity", scenarioContext)
			}
			routes, err := admitDeclaredWitnessRoutes(record["declaredWitnessRoutes"], scenarioContext+" declaredWitnessRoutes")
			if err != nil {
				return nil, err
			}
			if err := admitScenarioRouteClosure(routes, bindingRecordID, requirementID, surfaceID, scenarioID, scenarioContext); err != nil {
				return nil, err
			}
			expectedEnvironments := append([]string{}, requiredEnvironmentClasses...)
			routeVerifyCommands := [][]string{}
			for _, route := range routes {
				expectedEnvironments = append(expectedEnvironments, route.EnvironmentClasses...)
				routeVerifyCommands = append(routeVerifyCommands, route.VerifyCommands)
			}
			if !slices.Equal(environmentClasses, sortedUnique(expectedEnvironments)) {
				return nil, fmt.Errorf("%s environmentClasses are not derived from requiredEnvironmentClasses and declaredWitnessRoutes", scenarioContext)
			}
			if !slices.Equal(verifyCommands, compactScenarioCommandClosure(bindingVerifyCommands, routeVerifyCommands...)) {
				return nil, fmt.Errorf("%s verifyCommands are not derived from bindingVerifyCommands and declaredWitnessRoutes", scenarioContext)
			}
			result = append(result, admittedCoverageScenario{
				bindingRecordID: bindingRecordID, bindingVerifyCommands: bindingVerifyCommands, declaredWitnessRoutes: routes,
				environmentClasses: environmentClasses, requiredEnvironmentClasses: requiredEnvironmentClasses, requirementID: requirementID,
				scenarioID: scenarioID, surfaceID: surfaceID, verifyCommands: verifyCommands,
			})
			continue
		}

		commandIDs, err := admitProjectedRuleIDs(record["commandIds"], scenarioContext+" commandIds")
		if err != nil {
			return nil, err
		}
		witnessID := stringValue(record["witnessId"])
		witnessKind := stringValue(record["witnessKind"])
		witnessPath := stringValue(record["witnessPath"])
		if len(verifyCommands) != 0 {
			return nil, fmt.Errorf("%s structured scenario must not project compact verify commands", scenarioContext)
		}
		if _, err := admit.RuleID(witnessID, scenarioContext+" witnessId"); err != nil {
			return nil, err
		}
		if _, err := admit.RuleID(witnessKind, scenarioContext+" witnessKind"); err != nil {
			return nil, err
		}
		if _, err := admit.SafeRepoRelativePath(witnessPath, scenarioContext+" witnessPath"); err != nil {
			return nil, err
		}
		result = append(result, admittedCoverageScenario{
			commandIDs: commandIDs, environmentClasses: environmentClasses,
			scenarioID: scenarioID, verifyCommands: verifyCommands, witnessID: witnessID,
		})
	}
	return result, nil
}

func admitCoverageScenarioID(raw any, proofMode string, context string) (string, string, error) {
	if proofMode == "structured" {
		value, err := admit.RuleID(raw, context)
		return value, "", err
	}
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", "", err
	}
	if raw != value {
		return "", "", fmt.Errorf("%s must be canonical non-empty text", context)
	}
	return compactproofcontract.AdmitScenarioID(value, context)
}

func compactScenarioCommandClosure(bindingCommands []string, routeCommands ...[]string) []string {
	values := append([]string{}, bindingCommands...)
	for _, commands := range routeCommands {
		values = append(values, commands...)
	}
	return sortedUnique(values)
}

func admitProjectedCommands(raw any, context string) ([]string, error) {
	values, err := admit.PreserveSortedTextArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		if _, err := admit.DisplayOnlyCommandText(value, fmt.Sprintf("%s[%d]", context, index)); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func admitDeclaredWitnessRoutes(raw any, context string) ([]admittedDeclaredWitnessRoute, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	routes := make([]admittedDeclaredWitnessRoute, 0, len(values))
	previousRouteID := ""
	for index, rawRoute := range values {
		record, ok := rawRoute.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		routeContext := fmt.Sprintf("%s[%d]", context, index)
		if err := admit.KnownKeys(record, compactWitnessRouteKeys(), routeContext); err != nil {
			return nil, err
		}
		bindingRecordID, err := admit.SHA256Ref(record["bindingRecordId"], routeContext+" bindingRecordId")
		if err != nil {
			return nil, err
		}
		requirementID, err := admit.RuleID(record["requirementId"], routeContext+" requirementId")
		if err != nil {
			return nil, err
		}
		surfaceID, err := admit.RuleID(record["surfaceId"], routeContext+" surfaceId")
		if err != nil {
			return nil, err
		}
		scenarioID, scenarioSurfaceID, err := admitCoverageScenarioID(record["scenarioId"], "compact", routeContext+" scenarioId")
		if err != nil {
			return nil, err
		}
		if scenarioSurfaceID != surfaceID {
			return nil, fmt.Errorf("%s scenarioId must be scoped to surfaceId", routeContext)
		}
		expectedBindingRecordID, err := compactproofcontract.BindingRecordID(compactproofcontract.BindingIdentity{RequirementID: requirementID, ScenarioID: scenarioID, SurfaceID: surfaceID})
		if err != nil {
			return nil, err
		}
		if bindingRecordID != expectedBindingRecordID {
			return nil, fmt.Errorf("%s bindingRecordId does not match its requirement, surface, and scenario identity", routeContext)
		}
		role, err := admit.Enum(record["role"], map[string]struct{}{compactproofcontract.FalsificationWitnessRole: {}, compactproofcontract.PositiveWitnessRole: {}}, routeContext+" role")
		if err != nil {
			return nil, err
		}
		selector, err := compactproofcontract.AdmitWitnessSelector(stringValue(record["selector"]), routeContext+" selector")
		if err != nil {
			return nil, err
		}
		witnessRouteID, err := admit.SHA256Ref(record["witnessRouteId"], routeContext+" witnessRouteId")
		if err != nil {
			return nil, err
		}
		expectedRouteID, err := compactproofcontract.WitnessRouteID(bindingRecordID, role, selector)
		if err != nil {
			return nil, err
		}
		if witnessRouteID != expectedRouteID {
			return nil, fmt.Errorf("%s witnessRouteId does not match its binding, role, and selector identity", routeContext)
		}
		if previousRouteID != "" && previousRouteID >= witnessRouteID {
			return nil, fmt.Errorf("%s must be sorted and unique by witnessRouteId", context)
		}
		previousRouteID = witnessRouteID
		environments, err := admitProjectedRuleIDs(record["environmentClasses"], routeContext+" environmentClasses")
		if err != nil {
			return nil, err
		}
		commands, err := admitProjectedCommands(record["verifyCommands"], routeContext+" verifyCommands")
		if err != nil {
			return nil, err
		}
		resolutionOrder, err := admitProjectedNonNegativeInteger(record["resolutionOrderIndex"], routeContext+" resolutionOrderIndex")
		if err != nil {
			return nil, err
		}
		routes = append(routes, admittedDeclaredWitnessRoute{
			BindingRecordID: bindingRecordID, EnvironmentClasses: environments,
			RequirementID: requirementID, ResolutionOrder: resolutionOrder, Role: role,
			ScenarioID: scenarioID, Selector: selector, SurfaceID: surfaceID,
			VerifyCommands: commands, WitnessRouteID: witnessRouteID,
		})
	}
	return routes, nil
}

func admitScenarioRouteClosure(routes []admittedDeclaredWitnessRoute, bindingRecordID, requirementID, surfaceID, scenarioID, context string) error {
	if len(routes) != 2 {
		return fmt.Errorf("%s must retain exactly positive and falsification witness routes", context)
	}
	roles := map[string]struct{}{}
	for _, route := range routes {
		if route.BindingRecordID != bindingRecordID || route.RequirementID != requirementID || route.SurfaceID != surfaceID || route.ScenarioID != scenarioID {
			return fmt.Errorf("%s declared witness route identity does not match its scenario", context)
		}
		roles[route.Role] = struct{}{}
	}
	if len(roles) != 2 {
		return fmt.Errorf("%s must retain one positive and one falsification witness route", context)
	}
	return nil
}

func admitProjectedNonNegativeInteger(raw any, context string) (int, error) {
	return compactproofcontract.AdmitProjectedResolutionOrderIndex(raw, context)
}

func equalCanonicalRouteFacts(left, right []admittedDeclaredWitnessRoute) bool {
	return slices.EqualFunc(canonicalRouteFacts(left), canonicalRouteFacts(right), func(left, right admittedDeclaredWitnessRoute) bool {
		return compareRouteFacts(left, right) == 0
	})
}

func canonicalRouteFacts(routes []admittedDeclaredWitnessRoute) []admittedDeclaredWitnessRoute {
	facts := slices.Clone(routes)
	slices.SortFunc(facts, compareRouteFacts)
	return facts
}

func compareRouteFacts(left, right admittedDeclaredWitnessRoute) int {
	return cmp.Or(
		cmp.Compare(left.WitnessRouteID, right.WitnessRouteID),
		cmp.Compare(left.BindingRecordID, right.BindingRecordID),
		cmp.Compare(left.RequirementID, right.RequirementID),
		cmp.Compare(left.SurfaceID, right.SurfaceID),
		cmp.Compare(left.ScenarioID, right.ScenarioID),
		cmp.Compare(left.Role, right.Role),
		cmp.Compare(left.Selector, right.Selector),
		cmp.Compare(left.ResolutionOrder, right.ResolutionOrder),
		slices.Compare(left.EnvironmentClasses, right.EnvironmentClasses),
		slices.Compare(left.VerifyCommands, right.VerifyCommands),
	)
}
