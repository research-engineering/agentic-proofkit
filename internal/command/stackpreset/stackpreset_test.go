package stackpreset

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

func TestPresetInventoryIsCompleteDeterministicAndDefensivelyCopied(t *testing.T) {
	if len(presetIDs) != len(presets) {
		t.Fatalf("presetIDs=%d presets=%d, want one id per preset", len(presetIDs), len(presets))
	}
	seen := map[string]struct{}{}
	for _, presetID := range presetIDs {
		if _, ok := seen[presetID]; ok {
			t.Fatalf("duplicate preset id %s", presetID)
		}
		seen[presetID] = struct{}{}
		if !IsPresetID(presetID) {
			t.Fatalf("IsPresetID(%q)=false, want true", presetID)
		}
		profile, ok := ProfileFor(presetID)
		if !ok {
			t.Fatalf("ProfileFor(%q) missing", presetID)
		}
		assertNonEmptyPresetProfile(t, presetID, profile)

		record, err := Build(presetID)
		if err != nil {
			t.Fatalf("Build(%q) error=%v", presetID, err)
		}
		if record.ReportKind != "proofkit.stack-preset" || record.ReportID != "proofkit.stack-preset."+presetID || record.State != "passed" {
			t.Fatalf("Build(%q) record=%#v, want deterministic passed preset report", presetID, record)
		}
		if record.Summary["expectedFileCount"] != len(profile.ExpectedFiles) {
			t.Fatalf("Build(%q) summary=%#v, want expected file count", presetID, record.Summary)
		}
		for _, command := range profile.SuggestedCommands {
			assertPackageExecutableCommand(t, command)
			if command == cliexec.DisplayCommand("witness-plan", "--input", "proofkit/witness-plan.json") {
				t.Fatalf("preset %s emits catalog command for scheduler-plan fixture: %s", presetID, command)
			}
		}
	}
	for presetID := range presets {
		if _, ok := seen[presetID]; !ok {
			t.Fatalf("preset %s missing from presetIDs", presetID)
		}
	}

	original, ok := ProfileFor("typescript_workspace")
	if !ok {
		t.Fatal("typescript_workspace profile missing")
	}
	mutated := original
	mutated.ExpectedFiles[0] = "mutated"
	mutated.PrimaryLanguages[0] = "mutated"
	mutated.StarterEnvironmentClasses[0] = "mutated"
	mutated.StarterProofLikePaths[0] = "mutated"
	mutated.StarterWitnessKinds[0] = "mutated"
	mutated.SuggestedCommands[0] = "mutated"

	fresh, ok := ProfileFor("typescript_workspace")
	if !ok {
		t.Fatal("typescript_workspace profile missing after mutation")
	}
	if fresh.ExpectedFiles[0] == "mutated" ||
		fresh.PrimaryLanguages[0] == "mutated" ||
		fresh.StarterEnvironmentClasses[0] == "mutated" ||
		fresh.StarterProofLikePaths[0] == "mutated" ||
		fresh.StarterWitnessKinds[0] == "mutated" ||
		fresh.SuggestedCommands[0] == "mutated" {
		t.Fatalf("ProfileFor leaked mutable preset slices: %#v", fresh)
	}
}

func TestUnknownPresetIsRejected(t *testing.T) {
	if IsPresetID("unknown") {
		t.Fatal("IsPresetID accepted unknown preset")
	}
	if _, ok := ProfileFor("unknown"); ok {
		t.Fatal("ProfileFor accepted unknown preset")
	}
	if _, err := Build("unknown"); err == nil {
		t.Fatal("Build accepted unknown preset")
	}
}

func assertNonEmptyPresetProfile(t *testing.T, presetID string, profile Profile) {
	t.Helper()
	if profile.Purpose == "" ||
		len(profile.ExpectedFiles) == 0 ||
		len(profile.PrimaryLanguages) == 0 ||
		len(profile.StarterEnvironmentClasses) == 0 ||
		len(profile.StarterProofLikePaths) == 0 ||
		len(profile.StarterWitnessKinds) == 0 ||
		len(profile.SuggestedCommands) == 0 {
		t.Fatalf("preset %s has incomplete profile: %#v", presetID, profile)
	}
}

func assertPackageExecutableCommand(t *testing.T, command string) {
	t.Helper()
	fields := strings.Fields(command)
	if len(fields) < 2 {
		t.Fatalf("generated command %q has no command name", command)
	}
	if fields[0] != cliexec.BinaryName {
		t.Fatalf("generated command %q uses binary %q, want %q", command, fields[0], cliexec.BinaryName)
	}
}
