package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	rootHelpSHA256          = "d8f71779e3feab2faf4ac19d81881583d857155f2d75e923dc5bcfa61de8b6bb"
	perCommandHelpSetSHA256 = "9bd92c609b1f96ee4964c1c7ae3bf2a5150a2e4a9145b179f19ace11a6b15b8d"
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

func TestExistingHelpBytesRemainOwnerApproved(t *testing.T) {
	rootDigest := sha256.Sum256([]byte(usage()))
	if got := hex.EncodeToString(rootDigest[:]); got != rootHelpSHA256 {
		t.Fatalf("root help hash = %s, want %s", got, rootHelpSHA256)
	}
	hash := sha256.New()
	for _, descriptor := range commandDescriptors {
		_, _ = hash.Write([]byte(descriptor.name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(commandUsage(descriptor)))
		_, _ = hash.Write([]byte{0})
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != perCommandHelpSetSHA256 {
		t.Fatalf("per-command help set hash = %s, want %s", got, perCommandHelpSetSHA256)
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
	status := Run(t.Context(), args, strings.NewReader(""), &stdout, &stderr)
	if status != 0 || stderr.Len() != 0 {
		t.Fatalf("Run(%v) status=%d stdout=%q stderr=%q", args, status, stdout.String(), stderr.String())
	}
	return stdout.String()
}

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("help command read stdin")
}
