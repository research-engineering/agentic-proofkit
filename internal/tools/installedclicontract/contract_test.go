package installedclicontract

import (
	"slices"
	"testing"
)

func TestAdmitPreservesExactRoutesAndPresetChoices(t *testing.T) {
	content := []byte(`{"commands":[{"command":"adopt-plan","route":["adopt","plan"]},{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["go_cli_repo","python_service"]}}}]}`)
	contract, err := Admit(content)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	routes := contract.CommandIDsByRoute()
	if len(routes) != 2 || routes["adopt plan"] != "adopt-plan" || routes["stack-preset"] != "stack-preset" {
		t.Fatalf("routes = %v", routes)
	}
	presetIDs, err := contract.PresetIDs()
	if err != nil || !slices.Equal(presetIDs, []string{"go_cli_repo", "python_service"}) {
		t.Fatalf("preset IDs = %v, error = %v", presetIDs, err)
	}

	routes["mutated"] = "mutated"
	presets, _ := contract.PresetIDs()
	presets[0] = "mutated"
	ownerPresets, _ := contract.PresetIDs()
	if len(contract.CommandIDsByRoute()) != 2 || ownerPresets[0] != "go_cli_repo" {
		t.Fatal("contract accessors exposed mutable owner state")
	}
}

func TestAdmitRejectsAmbiguousOrIncompleteContracts(t *testing.T) {
	mutants := map[string]string{
		"duplicate key":    `{"commands":[{"command":"one","command":"two"},{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["go_cli_repo"]}}}]}`,
		"duplicate id":     `{"commands":[{"command":"same"},{"command":"same","route":["other"]},{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["go_cli_repo"]}}}]}`,
		"duplicate route":  `{"commands":[{"command":"one","route":["same"]},{"command":"two","route":["same"]},{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["go_cli_repo"]}}}]}`,
		"route prefix":     `{"commands":[{"command":"one","route":["adopt"]},{"command":"two","route":["adopt","plan"]},{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["go_cli_repo"]}}}]}`,
		"duplicate preset": `{"commands":[{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["same","same"]}}}]}`,
		"unsorted presets": `{"commands":[{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":["z","a"]}}}]}`,
	}
	for name, content := range mutants {
		t.Run(name, func(t *testing.T) {
			if _, err := Admit([]byte(content)); err == nil {
				t.Fatalf("Admit() accepted mutant: %s", content)
			}
		})
	}
	contract, err := Admit([]byte(`{"commands":[{"command":"one"}]}`))
	if err != nil {
		t.Fatalf("route-only contract rejected: %v", err)
	}
	if _, err := contract.PresetIDs(); err == nil {
		t.Fatal("PresetIDs() accepted a contract without stack-preset")
	}
}

func TestAdmitCommandRouteTokenBoundariesAreExact(t *testing.T) {
	for _, test := range []struct {
		name    string
		route   string
		wantErr bool
	}{
		{name: "max-1", route: `["three","route","tokens"]`},
		{name: "max", route: `["four","route","tokens","exactly"]`},
		{name: "max+1", route: `["five","route","tokens","are","invalid"]`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			content := []byte(`{"commands":[{"command":"sample","route":` + test.route + `}]}`)
			_, err := Admit(content)
			if test.wantErr && err == nil {
				t.Fatal("Admit() accepted route above token limit")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Admit() error = %v", err)
			}
		})
	}
}
