package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIContractAndFamilyCatalogHaveDistinctResourceBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resource.json")
	const prefix = `{"commands":[{"command":"sample"}]}`
	for _, size := range []int{4 << 20, (4 << 20) + 1} {
		content := prefix + strings.Repeat(" ", size-len(prefix))
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		commands, err := readCLICommands(path)
		if size == 4<<20 {
			if err != nil || len(commands) != 1 || commands[0] != "sample" {
				t.Fatalf("exact-bound contract rejected: %v", err)
			}
		} else if err == nil || commands != nil || !strings.Contains(err.Error(), "exceeds resource limit") {
			t.Fatalf("one-over contract did not fail closed: %v", err)
		}
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte(" "), (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCatalog(path); err == nil || !strings.Contains(err.Error(), "catalog exceeds size limit") {
		t.Fatalf("unrelated family-catalog bound was raised: %v", err)
	}
}

func TestGeneratedCommandFamilyProjectionIsFresh(t *testing.T) {
	root := repositoryRoot(t)
	expected, err := render(root)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(generatedPath)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("generated command family projection is stale")
	}
}

func TestCommandFamilyCatalogRejectsParityAndCardinalityMutations(t *testing.T) {
	root := repositoryRoot(t)
	_, admitted, err := readCatalog(filepath.Join(root, filepath.FromSlash(catalogPath)))
	if err != nil {
		t.Fatal(err)
	}
	commands, err := readCLICommands(filepath.Join(root, filepath.FromSlash(cliContractPath)))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*catalog, *[]string)
		want   string
	}{
		{
			name: "missing command",
			mutate: func(value *catalog, _ *[]string) {
				value.Families[0].Commands = value.Families[0].Commands[1:]
			},
			want: "coverage count",
		},
		{
			name: "duplicate command",
			mutate: func(value *catalog, _ *[]string) {
				commands := value.Families[1].Commands
				value.Families[1].Commands = append(commands, commands[len(commands)-1])
			},
			want: "sorted unique",
		},
		{
			name: "ninth family member",
			mutate: func(value *catalog, _ *[]string) {
				value.Families[0].Commands = append(value.Families[0].Commands, "synthetic-command")
			},
			want: "1..8",
		},
		{
			name: "reserved operand collision",
			mutate: func(_ *catalog, commands *[]string) {
				*commands = append(*commands, "family")
			},
			want: "collides",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := cloneCatalog(admitted)
			commandCopy := append([]string(nil), commands...)
			test.mutate(&value, &commandCopy)
			err := validateCatalog(value, commandCopy)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateCatalog() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestCommandFamilyCatalogRejectsUnknownFields(t *testing.T) {
	var value catalog
	err := decodeStrict([]byte(`{"schemaVersion":1,"catalogId":"proofkit.command-families.v1","families":[],"helpForms":[],"reservedHelpOperands":[],"nonClaims":[],"unknown":true}`), &value)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decodeStrict() error = %v", err)
	}
}

func cloneCatalog(source catalog) catalog {
	result := source
	result.Families = make([]family, len(source.Families))
	for index, item := range source.Families {
		result.Families[index] = item
		result.Families[index].Commands = append([]string(nil), item.Commands...)
	}
	result.HelpForms = append([]string(nil), source.HelpForms...)
	result.NonClaims = append([]string(nil), source.NonClaims...)
	result.ReservedHelpOperands = append([]string(nil), source.ReservedHelpOperands...)
	return result
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}
