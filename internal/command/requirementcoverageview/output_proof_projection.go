package requirementcoverageview

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/proofvocab"
)

type admittedCoverageScenario struct {
	commandIDs         []string
	environmentClasses []string
	scenarioID         string
	verifyCommands     []string
	witnessID          string
	witnessSelectors   []string
}

func admitRequirementProofProjection(row map[string]any, proofMode string, entries []testevidenceinventory.Entry, context string) error {
	proofState, ok := row["proofState"].(string)
	if !ok {
		return fmt.Errorf("%s proofState must be a string", context)
	}
	if proofState != "" {
		if _, err := admit.Enum(proofState, proofvocab.RequirementProofStateSet(), context+" proofState"); err != nil {
			return err
		}
	}
	scenarios, err := admitCoverageScenarios(row["scenarios"], proofMode, context+" scenarios")
	if err != nil {
		return err
	}
	if !wireCountEquals(row["scenarioCount"], len(scenarios)) {
		return fmt.Errorf("%s scenarioCount does not match scenarios", context)
	}
	if (proofState == "witness_backed") != (len(scenarios) > 0) {
		return fmt.Errorf("%s proofState and scenarios are inconsistent", context)
	}
	if proofMode == "compact" && proofState != "" && proofState != "witness_backed" {
		return fmt.Errorf("%s compact proofState must be witness_backed", context)
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
	witnessSelectors, err := admitProjectedWitnessSelectors(row["witnessSelectors"], context+" witnessSelectors")
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
	if proofMode == "compact" {
		if len(witnessRefs) != 0 {
			return fmt.Errorf("%s compact witnessRefs must be empty", context)
		}
		expectedCommands := []string{}
		if proofState == "witness_backed" {
			expectedCommands = entryCommandRefs(entries)
		}
		if !slices.Equal(commandIDs, expectedCommands) {
			return fmt.Errorf("%s compact commandIds are not derived from projected tests", context)
		}
		expectedVerifyCommands := []string{}
		expectedWitnessSelectors := []string{}
		for _, scenario := range scenarios {
			expectedVerifyCommands = append(expectedVerifyCommands, scenario.verifyCommands...)
			expectedWitnessSelectors = append(expectedWitnessSelectors, scenario.witnessSelectors...)
		}
		if !slices.Equal(verifyCommands, sortedUnique(expectedVerifyCommands)) {
			return fmt.Errorf("%s compact verifyCommands are not derived from scenarios", context)
		}
		if !slices.Equal(witnessSelectors, sortedUnique(expectedWitnessSelectors)) {
			return fmt.Errorf("%s compact witnessSelectors are not derived from scenarios", context)
		}
		return nil
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
	if len(verifyCommands) != 0 || len(witnessSelectors) != 0 {
		return fmt.Errorf("%s structured proof must not project compact verifyCommands or witnessSelectors", context)
	}
	return nil
}

func admitCoverageScenarios(raw any, proofMode string, context string) ([]admittedCoverageScenario, error) {
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
		commandIDs, err := admitProjectedRuleIDs(record["commandIds"], scenarioContext+" commandIds")
		if err != nil {
			return nil, err
		}
		environmentClasses, err := admitProjectedRuleIDs(record["environmentClasses"], scenarioContext+" environmentClasses")
		if err != nil {
			return nil, err
		}
		verifyCommands, err := admitProjectedCommands(record["verifyCommands"], scenarioContext+" verifyCommands")
		if err != nil {
			return nil, err
		}
		witnessSelectors, err := admitProjectedWitnessSelectors(record["witnessSelectors"], scenarioContext+" witnessSelectors")
		if err != nil {
			return nil, err
		}
		scenarioID, err := admitCoverageScenarioID(record["scenarioId"], proofMode, scenarioContext+" scenarioId")
		if err != nil {
			return nil, err
		}
		if previousID != "" && previousID >= scenarioID {
			return nil, fmt.Errorf("%s must be sorted and unique by scenarioId", context)
		}
		previousID = scenarioID

		witnessID := stringValue(record["witnessId"])
		witnessKind := stringValue(record["witnessKind"])
		witnessPath := stringValue(record["witnessPath"])
		if proofMode == "compact" {
			if len(commandIDs) != 0 || witnessID != "" || witnessKind != "" || witnessPath != "" {
				return nil, fmt.Errorf("%s compact scenario must not synthesize command or witness identity", scenarioContext)
			}
			if len(verifyCommands) == 0 || len(witnessSelectors) == 0 {
				return nil, fmt.Errorf("%s compact scenario must retain verify commands and witness selectors", scenarioContext)
			}
		} else {
			if len(verifyCommands) != 0 || len(witnessSelectors) != 0 {
				return nil, fmt.Errorf("%s structured scenario must not project compact routes", scenarioContext)
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
		}
		result = append(result, admittedCoverageScenario{
			commandIDs: commandIDs, environmentClasses: environmentClasses,
			scenarioID: scenarioID, verifyCommands: verifyCommands, witnessID: witnessID,
			witnessSelectors: witnessSelectors,
		})
	}
	return result, nil
}

func admitCoverageScenarioID(raw any, proofMode string, context string) (string, error) {
	if proofMode == "structured" {
		return admit.RuleID(raw, context)
	}
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if raw != value {
		return "", fmt.Errorf("%s must be canonical non-empty text", context)
	}
	scenarioID, _, err := compactproofcontract.AdmitScenarioID(value, context)
	return scenarioID, err
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

func admitProjectedWitnessSelectors(raw any, context string) ([]string, error) {
	values, err := admit.PreserveSortedTextArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		if _, err := compactproofcontract.AdmitWitnessSelector(value, fmt.Sprintf("%s[%d]", context, index)); err != nil {
			return nil, err
		}
	}
	return values, nil
}
