package installedclicontract

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
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

func TestAdmitContractResourceBoundsAreExact(t *testing.T) {
	base := []byte(`{"commands":[{"command":"one"}]}`)
	exactBytes := append(append([]byte(nil), base...), bytes.Repeat([]byte(" "), MaximumContractBytes-len(base))...)
	if _, err := Admit(exactBytes); err != nil {
		t.Fatalf("exact byte limit rejected: %v", err)
	}
	if _, err := Admit(append(exactBytes, ' ')); err == nil {
		t.Fatal("one-over contract byte limit was accepted")
	}

	commands := make([]string, MaximumCommands+1)
	for index := range commands {
		commands[index] = fmt.Sprintf(`{"command":"command-%d"}`, index)
	}
	contract := func(count int) []byte {
		return []byte(`{"commands":[` + strings.Join(commands[:count], ",") + `]}`)
	}
	if _, err := Admit(contract(MaximumCommands)); err != nil {
		t.Fatalf("exact command cardinality rejected: %v", err)
	}
	if _, err := Admit(contract(MaximumCommands + 1)); err == nil {
		t.Fatal("one-over command cardinality was accepted")
	}

	presets := make([]string, MaximumPresetIDs+1)
	for index := range presets {
		presets[index] = fmt.Sprintf(`"preset-%03d"`, index)
	}
	presetContract := func(count int) []byte {
		return []byte(`{"commands":[{"command":"stack-preset","outputContract":{"flagChoices":{"--preset":[` + strings.Join(presets[:count], ",") + `]}}}]}`)
	}
	if _, err := Admit(presetContract(MaximumPresetIDs)); err != nil {
		t.Fatalf("exact preset cardinality rejected: %v", err)
	}
	if _, err := Admit(presetContract(MaximumPresetIDs + 1)); err == nil {
		t.Fatal("one-over preset cardinality was accepted")
	}
}

func TestAdmitHelpIdentityRequiresExactCommandAndRoute(t *testing.T) {
	help := []byte("Usage:\n  agentic-proofkit adopt plan\n\nCommand ID:\n  adopt-plan\n\nRoute:\n  adopt plan\n")
	identity, err := AdmitHelpIdentity(help)
	if err != nil {
		t.Fatalf("AdmitHelpIdentity() error = %v", err)
	}
	if identity.CommandID != "adopt-plan" || identity.Route != "adopt plan" {
		t.Fatalf("help identity = %#v", identity)
	}
	mutants := [][]byte{
		bytes.Replace(help, []byte("adopt-plan"), []byte("Wrong_ID"), 1),
		append(append([]byte(nil), help...), []byte("Command ID:\n  adopt-plan\n")...),
		bytes.Replace(help, []byte("  adopt plan\n"), []byte("  adopt  plan\n"), 1),
		append([]byte(nil), bytes.Repeat([]byte("x"), maximumHelpBytes+1)...),
	}
	for index, mutant := range mutants {
		if _, err := AdmitHelpIdentity(mutant); err == nil {
			t.Fatalf("help identity mutant %d was accepted", index)
		}
	}
}
