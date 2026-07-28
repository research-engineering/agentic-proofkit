package app

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/stackpreset"
)

func TestCommandFamilyCatalogMatchesDescriptors(t *testing.T) {
	seen := map[string]string{}
	for _, family := range generatedCommandFamilyCatalog().Families {
		if len(family.Commands) == 0 || len(family.Commands) > 8 {
			t.Fatalf("family %s command count = %d", family.ID, len(family.Commands))
		}
		for _, command := range family.Commands {
			if prior, duplicate := seen[command]; duplicate {
				t.Fatalf("command %s belongs to %s and %s", command, prior, family.ID)
			}
			seen[command] = family.ID
		}
	}
	if len(seen) != len(commandDescriptors) {
		t.Fatalf("catalog command count = %d, descriptor count = %d", len(seen), len(commandDescriptors))
	}
	for _, descriptor := range commandDescriptors {
		if seen[descriptor.name] == "" {
			t.Fatalf("descriptor %s is missing from the command family catalog", descriptor.name)
		}
	}
}

func TestGeneratedCommandFamilyCatalogDoesNotShareMutableSlices(t *testing.T) {
	first := generatedCommandFamilyCatalog()
	first.Families[0].Commands[0] = "mutated"
	first.Families[0].Purpose = "mutated"
	second := generatedCommandFamilyCatalog()
	if second.Families[0].Commands[0] == "mutated" || second.Families[0].Purpose == "mutated" {
		t.Fatal("generated command family projection shares mutable state")
	}
}

func TestCommandFamilyHelpFormsAreOptInAndLeafDispatchIsUnchanged(t *testing.T) {
	rootHelp := runTextCommand(t, []string{"help"})
	if strings.Contains(rootHelp, "Command families:") {
		t.Fatal("default help unexpectedly includes the opt-in family catalog")
	}
	if !strings.Contains(rootHelp, "agentic-proofkit help families") {
		t.Fatal("root help does not expose the opt-in command-family discovery route")
	}
	familiesHelp := runTextCommand(t, []string{"help", "families"})
	for _, family := range generatedCommandFamilyCatalog().Families {
		if !strings.Contains(familiesHelp, "  "+family.ID+"\t"+family.Label) {
			t.Fatalf("family list does not route %s", family.ID)
		}
		familyHelp := runTextCommand(t, []string{"help", "family", family.ID})
		for _, command := range family.Commands {
			if !strings.Contains(familyHelp, "  "+command+"\n") {
				t.Fatalf("family %s help does not route command %s", family.ID, command)
			}
			copyableRoute := "agentic-proofkit help " + command
			copyableLine := "    " + copyableRoute + "\n"
			if strings.Count(familyHelp, copyableLine) != 1 {
				t.Fatalf("family %s copyable route %q count=%d, want 1", family.ID, copyableRoute, strings.Count(familyHelp, copyableLine))
			}
			direct := runTextCommand(t, []string{"help", command})
			descriptor, _ := commandDescriptorFor(command)
			if direct != commandUsage(descriptor) {
				t.Fatalf("direct help for %s changed through family navigation", command)
			}
		}
		copyableFamilyRoute := "agentic-proofkit help family " + family.ID
		if strings.Count(familiesHelp, copyableFamilyRoute) != 1 {
			t.Fatalf("family list copyable route %q count=%d, want 1", copyableFamilyRoute, strings.Count(familiesHelp, copyableFamilyRoute))
		}
	}
}

func TestRootHelpDiscoversFamiliesWithoutExpandingThem(t *testing.T) {
	rootHelp := runTextCommand(t, []string{"help"})
	const route = "agentic-proofkit help families"
	if strings.Count(rootHelp, route) != 1 {
		t.Fatalf("root help family route count=%d, want 1", strings.Count(rootHelp, route))
	}
	for _, family := range generatedCommandFamilyCatalog().Families {
		if strings.Contains(rootHelp, family.Label) || strings.Contains(rootHelp, family.Purpose) {
			t.Fatalf("root help eagerly expanded family %s", family.ID)
		}
	}
}

func TestStackPresetVocabularyProjectsFromOneOwner(t *testing.T) {
	choices := generatedCommandContractMetadataByName["stack-preset"].FlagChoices["--preset"]
	if !slices.Equal(choices, stackpreset.IDs()) {
		t.Fatalf("CLI contract preset choices=%v runtime preset ids=%v", choices, stackpreset.IDs())
	}
	descriptor, ok := commandDescriptorFor("stack-preset")
	if !ok {
		t.Fatal("stack-preset descriptor missing")
	}
	if !slices.Equal(descriptor.flagValueChoices["--preset"], choices) {
		t.Fatalf("descriptor preset choices=%v contract choices=%v", descriptor.flagValueChoices["--preset"], choices)
	}
	help := commandUsage(descriptor)
	const prefix = "agentic-proofkit stack-preset --preset <"
	start := strings.Index(help, prefix)
	if start < 0 {
		t.Fatalf("stack-preset help omits generated usage: %s", help)
	}
	start += len(prefix)
	end := strings.Index(help[start:], ">")
	if end < 0 {
		t.Fatalf("stack-preset help has no closed preset vocabulary: %s", help)
	}
	helpIDs := strings.Split(help[start:start+end], "|")
	if !slices.Equal(helpIDs, choices) {
		t.Fatalf("help preset ids=%v contract choices=%v", helpIDs, choices)
	}
	for _, presetID := range choices {
		route := "agentic-proofkit stack-preset --preset " + presetID
		if strings.Count(help, route) != 1 {
			t.Fatalf("stack-preset copyable route %q count=%d, want 1", route, strings.Count(help, route))
		}
	}
	if strings.Count(help, "Path: node_modules/@research-engineering/agentic-proofkit/README.md") != 1 {
		t.Fatal("stack-preset help does not expose exactly one installed README continuation")
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), []string{"stack-preset", "--preset", "unknown"}, panicReader{}, &stdout, &stderr)
	wantDiagnostic := "--preset requires one of: " + strings.Join(choices, ", ") + "\n"
	if status != 1 || stdout.Len() != 0 || stderr.String() != wantDiagnostic {
		t.Fatalf("invalid preset status=%d stdout=%q stderr=%q, want %q", status, stdout.String(), stderr.String(), wantDiagnostic)
	}
}

func TestExistingHelpEntrypointsRemainCompatible(t *testing.T) {
	rootHelp := usage()
	if !strings.Contains(rootHelp, "agentic-proofkit help [<command>|-h|--help]") {
		t.Fatal("root help omits the admitted positional command target")
	}
	rootForms := [][]string{nil, {"help"}, {"--help"}, {"-h"}, {"help", "--help"}, {"help", "-h"}}
	for _, args := range rootForms {
		if got := runTextCommand(t, args); got != rootHelp {
			t.Fatalf("root help entrypoint %v diverged from the root projection", args)
		}
	}
	for _, descriptor := range commandDescriptors {
		expected := commandUsage(descriptor)
		installedLine := "Installed invocation:\n  " + installedCommandUsageLine(descriptor) + "\n"
		if strings.Count(expected, installedLine) != 1 {
			t.Fatalf("command %s installed invocation %q count=%d, want 1", descriptor.name, installedCommandUsageLine(descriptor), strings.Count(expected, installedLine))
		}
		aliases := [][]string{{"help", descriptor.name}}
		if descriptor.name != "help" {
			aliases = append(aliases, []string{descriptor.name, "--help"}, []string{descriptor.name, "-h"})
		}
		for _, args := range aliases {
			if got := runTextCommand(t, args); got != expected {
				t.Fatalf("per-command help %v changed across an existing alias", args)
			}
		}
	}
	requirementSource, ok := commandDescriptorFor("requirement-source-admission")
	if !ok {
		t.Fatal("requirement-source-admission descriptor missing")
	}
	if strings.Count(commandUsage(requirementSource), "Path: node_modules/@research-engineering/agentic-proofkit/README.md") != 1 {
		t.Fatal("requirement-source-admission help does not expose exactly one installed README continuation")
	}
}

func TestHelpCommandUsageIncludesGeneratedFamilyGrammar(t *testing.T) {
	output := runTextCommand(t, []string{"help", "help"})
	for _, form := range generatedCommandFamilyCatalog().HelpForms {
		if !strings.Contains(output, "agentic-proofkit "+form) {
			t.Fatalf("help help output is missing generated family form %q:\n%s", form, output)
		}
	}
}

func TestCommandFamilyHelpRejectsInvalidFormsBeforeReadingInput(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{args: []string{"help", "family"}, want: "help family requires a family id"},
		{args: []string{"help", "family", "unknown"}, want: "unsupported command family"},
		{args: []string{"help", "family", "adoption-lifecycle", "extra"}, want: "help family accepts exactly one family id"},
		{args: []string{"help", "families", "extra"}, want: "help families accepts no additional operands"},
	}
	for _, test := range cases {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		status := Run(t.Context(), test.args, panicReader{}, &stdout, &stderr)
		if status != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
			t.Fatalf("Run(%v) status=%d stdout=%q stderr=%q", test.args, status, stdout.String(), stderr.String())
		}
	}
}

func runTextCommand(t *testing.T, args []string) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := Run(t.Context(), args, panicReader{}, &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(%v) status=%d stdout=%q stderr=%q", args, status, stdout.String(), stderr.String())
	}
	return stdout.String()
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("help command read stdin")
}
