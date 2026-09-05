package app

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
)

func TestProjectNavigationVersionEdgeRejectsUndeclaredPublicABIDrift(t *testing.T) {
	frozen := readFrozenProjectNavigationPublicABI(t)
	firstDefinition := sortedFirstKey(t, frozen.ContractDefinitions)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "header", mutate: func(current map[string]any) { current["packageName"] = "unexpected" }},
		{name: "predecessor command removed", mutate: func(current map[string]any) {
			removePublicABIRecord(t, current, "commands", "command", "impact")
		}},
		{name: "predecessor command changed", mutate: func(current map[string]any) {
			mutatePublicABIRecord(t, current, "commands", "command", "impact", func(record map[string]any) { record["route"] = []any{"impact-drift"} })
		}},
		{name: "command order", mutate: func(current map[string]any) { swapFirstPublicABIRecords(t, current, "commands") }},
		{name: "unexpected command", mutate: func(current map[string]any) {
			appendRenamedPublicABIRecord(t, current, "commands", "command", "impact", "zz-unexpected-command")
		}},
		{name: "predecessor definition removed", mutate: func(current map[string]any) {
			removePublicABIRecord(t, current, "contractDefinitions", "definitionId", firstDefinition)
		}},
		{name: "predecessor definition changed", mutate: func(current map[string]any) {
			mutatePublicABIRecord(t, current, "contractDefinitions", "definitionId", firstDefinition, func(record map[string]any) { record["unexpectedField"] = true })
		}},
		{name: "definition order", mutate: func(current map[string]any) { swapFirstPublicABIRecords(t, current, "contractDefinitions") }},
		{name: "unexpected definition", mutate: func(current map[string]any) {
			appendRenamedPublicABIRecord(t, current, "contractDefinitions", "definitionId", firstDefinition, "proofkit.zz-unexpected.definition")
		}},
		{name: "process contract", mutate: func(current map[string]any) {
			process := clonePublicABIRecord(current["processContract"].(map[string]any))
			process["successExitCode"] = json.Number("9")
			current["processContract"] = process
		}},
		{name: "omitted route policy missing", mutate: func(current map[string]any) { mutateOmittedRoutePolicy(t, current, nil) }},
		{name: "omitted route policy changed", mutate: func(current map[string]any) { mutateOmittedRoutePolicy(t, current, "unexpected") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := readProjectNavigationCLIContractRaw(t)
			test.mutate(current)
			if err := verifyCompleteProjectNavigationABIDiff(frozen, current); err == nil {
				t.Fatal("undeclared public ABI drift was admitted")
			}
		})
	}

	t.Run("native source digest drift is intentionally normalized", func(t *testing.T) {
		current := readProjectNavigationCLIContractRaw(t)
		mutatePublicABIRecord(t, current, "commands", "command", "impact", func(record map[string]any) {
			for _, field := range []string{"inputContract", "outputContract"} {
				contract := clonePublicABIRecord(record[field].(map[string]any))
				source := clonePublicABIRecord(contract["nativeSource"].(map[string]any))
				source["canonicalDigest"] = digest.SHA256TextRef("updated native source bytes")
				contract["nativeSource"] = source
				record[field] = contract
			}
		})
		if err := verifyCompleteProjectNavigationABIDiff(frozen, current); err != nil {
			t.Fatalf("native source digest drift should be normalized: %v", err)
		}
	})
}

func sortedFirstKey(t *testing.T, values map[string]string) string {
	t.Helper()
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		t.Fatal("frozen public ABI inventory is empty")
	}
	return keys[0]
}

func mutatePublicABIRecord(t *testing.T, current map[string]any, inventory string, identityField string, identity string, mutate func(map[string]any)) {
	t.Helper()
	values := current[inventory].([]any)
	for index, raw := range values {
		record := raw.(map[string]any)
		if record[identityField] != identity {
			continue
		}
		mutant := clonePublicABIRecord(record)
		mutate(mutant)
		values[index] = mutant
		return
	}
	t.Fatalf("%s is missing %s %s", inventory, identityField, identity)
}

func removePublicABIRecord(t *testing.T, current map[string]any, inventory string, identityField string, identity string) {
	t.Helper()
	values := current[inventory].([]any)
	for index, raw := range values {
		if raw.(map[string]any)[identityField] == identity {
			current[inventory] = append(append([]any{}, values[:index]...), values[index+1:]...)
			return
		}
	}
	t.Fatalf("%s is missing %s %s", inventory, identityField, identity)
}

func swapFirstPublicABIRecords(t *testing.T, current map[string]any, inventory string) {
	t.Helper()
	values := current[inventory].([]any)
	if len(values) < 2 {
		t.Fatalf("%s has fewer than two records", inventory)
	}
	values[0], values[1] = values[1], values[0]
}

func appendRenamedPublicABIRecord(t *testing.T, current map[string]any, inventory string, identityField string, sourceIdentity string, newIdentity string) {
	t.Helper()
	values := current[inventory].([]any)
	for _, raw := range values {
		record := raw.(map[string]any)
		if record[identityField] != sourceIdentity {
			continue
		}
		mutant := clonePublicABIRecord(record)
		mutant[identityField] = newIdentity
		current[inventory] = append(values, mutant)
		return
	}
	t.Fatalf("%s is missing %s %s", inventory, identityField, sourceIdentity)
}

func mutateOmittedRoutePolicy(t *testing.T, current map[string]any, replacement any) {
	t.Helper()
	process := clonePublicABIRecord(current["processContract"].(map[string]any))
	grammar := clonePublicABIRecord(process["commandRouteGrammar"].(map[string]any))
	if replacement == nil {
		delete(grammar, "omittedRoutePolicy")
	} else {
		grammar["omittedRoutePolicy"] = replacement
	}
	process["commandRouteGrammar"] = grammar
	current["processContract"] = process
}
