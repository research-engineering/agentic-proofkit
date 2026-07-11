package app

import (
	"bytes"
	"strings"
	"testing"
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
			direct := runTextCommand(t, []string{"help", command})
			descriptor, _ := commandDescriptorFor(command)
			if direct != commandUsage(descriptor) {
				t.Fatalf("direct help for %s changed through family navigation", command)
			}
		}
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
