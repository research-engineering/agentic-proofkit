package app

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

type commandFamily struct {
	ID       string
	Label    string
	Purpose  string
	Commands []string
}

type commandFamilyCatalog struct {
	CatalogID            string
	Families             []commandFamily
	HelpForms            []string
	NonClaims            []string
	ReservedHelpOperands []string
	SchemaVersion        int
}

func commandFamiliesUsageWithRenderer(renderer cliexec.Renderer) string {
	lines := []string{"Command families:"}
	for _, family := range generatedCommandFamilyCatalog().Families {
		lines = append(lines, fmt.Sprintf("  %s\t%s", family.ID, family.Label))
		lines = append(lines, "    "+family.Purpose)
		lines = append(lines, "    "+renderer.DisplayCommand("help", "family", family.ID))
	}
	return strings.Join(lines, "\n") + "\n"
}

func commandFamilyUsageWithRenderer(familyID string, renderer cliexec.Renderer) (string, error) {
	for _, family := range generatedCommandFamilyCatalog().Families {
		if family.ID != familyID {
			continue
		}
		lines := []string{
			"Command family:",
			"  ID: " + family.ID,
			"  Label: " + family.Label,
			"  Purpose: " + family.Purpose,
			"",
			"Commands:",
		}
		for _, command := range family.Commands {
			lines = append(lines, "  "+command)
			lines = append(lines, "    "+renderer.DisplayCommand("help", command))
		}
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("unsupported command family")
}
