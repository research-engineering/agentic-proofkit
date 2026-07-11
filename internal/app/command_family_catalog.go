package app

import (
	"fmt"
	"strings"
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

func commandFamiliesUsage() string {
	lines := []string{"Command families:"}
	for _, family := range generatedCommandFamilyCatalog().Families {
		lines = append(lines, fmt.Sprintf("  %s\t%s", family.ID, family.Label))
		lines = append(lines, "    "+family.Purpose)
	}
	lines = append(lines, "", "Use `agentic-proofkit help family <family-id>` for leaf commands.")
	return strings.Join(lines, "\n") + "\n"
}

func commandFamilyUsage(familyID string) (string, error) {
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
		}
		return strings.Join(lines, "\n") + "\n", nil
	}
	return "", fmt.Errorf("unsupported command family")
}
