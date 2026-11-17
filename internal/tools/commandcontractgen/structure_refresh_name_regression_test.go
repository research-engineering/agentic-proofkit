package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestStructureRefreshCommandNameAdmission(t *testing.T) {
	original, _, err := readContract(filepath.Join("..", "..", "..", cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name  string
		value any
	}{
		{"missing", nil},
		{"null", nil},
		{"number", 9},
		{"boolean", false},
		{"array", []any{"private-caller-text"}},
		{"object", map[string]any{"private-caller-text": true}},
		{"empty", ""},
		{"valid", "receipt-producer-admission"},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "proofkit"), 0o755); err != nil {
				t.Fatal(err)
			}
			_, contract, err := readContractInput(bytes.NewReader(original))
			if err != nil {
				t.Fatal(err)
			}
			index := -1
			for i, raw := range contract["commands"].([]any) {
				command := raw.(map[string]any)
				if command["command"] == "receipt-producer-admission" {
					index = i
					if row.name == "missing" {
						delete(command, "command")
					} else {
						command["command"] = row.value
					}
					break
				}
			}
			if index < 0 {
				t.Fatal("production receipt command missing")
			}
			encoded, err := json.Marshal(contract)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, cliContractPath), encoded, 0o644); err != nil {
				t.Fatal(err)
			}
			source, admitted, err := readContract(filepath.Join(root, cliContractPath))
			if err != nil {
				t.Fatal(err)
			}
			before := refreshNameSnapshot(t, root)
			var updated []byte
			func() {
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("refresh panicked rather than rejecting row: %v", value)
					}
				}()
				updated, err = refreshStructureSource(source, admitted)
			}()
			if row.name == "valid" {
				if err != nil || len(updated) == 0 {
					t.Fatalf("valid row failed refresh: %v", err)
				}
				_, refreshed, err := readContractInput(bytes.NewReader(updated))
				if err != nil {
					t.Fatal(err)
				}
				if again, err := refreshStructureSource(updated, refreshed); err != nil || !bytes.Equal(updated, again) {
					t.Fatalf("valid refresh is not idempotent: %v", err)
				}
				if after := refreshNameSnapshot(t, root); !reflect.DeepEqual(before, after) {
					t.Fatal("pure refresh wrote files")
				}
				return
			}
			want := fmt.Sprintf("CLI command row %d must have a nonempty string command name", index)
			if err == nil || err.Error() != want || strings.Contains(err.Error(), "private-caller-text") || updated != nil {
				t.Errorf("invalid name did not produce a safe row admission error: %v", err)
			}
			func() {
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("refresh entrypoint panicked: %v", value)
					}
				}()
				if err := refreshStructures(root); err == nil || err.Error() != want {
					t.Errorf("entrypoint returned wrong admission error: %v", err)
				}
			}()
			if after := refreshNameSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("rejected refresh changed files or inventory")
			}
		})
	}
}

func refreshNameSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err == nil {
			files[path] = string(content)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return files
}
