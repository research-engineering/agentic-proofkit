package repositoryinventory

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestInventoryStructurePreservesNativeCatalogAndEndpoints(t *testing.T) {
	shape := OutputShape()
	for _, state := range []string{"empty", "populated", "omitted", "oversize"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			if state != "empty" {
				for _, item := range rootCatalog {
					content := []byte("synthetic\n")
					if state == "omitted" {
						content = []byte{0}
					}
					if state == "oversize" {
						content = bytes.Repeat([]byte{'a'}, 1048577)
					}
					writeInventoryFixture(t, root, item.Path, content)
					if state == "oversize" {
						break
					}
				}
			}
			snapshot, err := Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := stablejson.Marshal(snapshot.JSONValue())
			if err != nil {
				t.Fatal(err)
			}
			wire, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := shape.Admit(wire, "inventory"); err != nil {
				t.Fatal(err)
			}
			if _, err := AdmitOutput(wire); err != nil {
				t.Fatal(err)
			}
			value := wire.(map[string]any)
			for _, field := range []string{"entries", "inventoryId", "inventoryKind", "nonClaims", "omissions", "policyId", "schemaVersion", "scope"} {
				missing := maps.Clone(value)
				delete(missing, field)
				if _, err := shape.Admit(missing, "inventory"); err == nil {
					t.Fatalf("accepted missing %s", field)
				}
				null := maps.Clone(value)
				null[field] = nil
				if _, err := shape.Admit(null, "inventory"); err == nil {
					t.Fatalf("accepted null %s", field)
				}
			}
			extra := maps.Clone(value)
			extra["unexpected"] = true
			if _, err := shape.Admit(extra, "inventory"); err == nil {
				t.Fatal("accepted an extra root member")
			}
			for _, field := range []string{"inventoryKind", "policyId", "schemaVersion"} {
				changed := maps.Clone(value)
				changed[field] = "foreign"
				if _, err := shape.Admit(changed, "inventory"); err == nil {
					t.Fatalf("accepted a foreign %s", field)
				}
			}
			if state == "populated" {
				entries := value["entries"].([]any)
				if len(entries) != 25 {
					t.Fatalf("catalog entry count=%d, want25", len(entries))
				}
				entryShape, _ := shape.Property("entries")
				itemShape, _ := entryShape.Element()
				for _, raw := range entries {
					entry := raw.(map[string]any)
					for _, length := range []json.Number{"0", "1048576"} {
						boundary := maps.Clone(entry)
						boundary["byteLength"] = length
						if _, err := itemShape.Admit(boundary, "entry"); err != nil {
							t.Fatal(err)
						}
					}
					for field, neighbors := range map[string][]any{
						"byteLength":    {json.Number("-1"), json.Number("1048577"), json.Number("0.5"), "0"},
						"contentSha256": {"sha256:" + strings.Repeat("g", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), strings.Repeat("a", 64)},
						"path":          {"unknown", entry["path"].(string) + " "},
						"role":          {"unknown", entry["role"].(string) + " "},
						"syntaxState":   {"evaluated", "not_evaluated "},
					} {
						for _, neighbor := range append(neighbors, nil, false) {
							changed := maps.Clone(entry)
							changed[field] = neighbor
							if _, err := itemShape.Admit(changed, "entry"); err == nil {
								t.Fatalf("accepted %s neighbor for %s", field, entry["path"])
							}
						}
					}
					wrongRole := maps.Clone(entry)
					wrongRole["role"] = "human_overview"
					if entry["role"] == "human_overview" {
						wrongRole["role"] = "ecosystem_manifest"
					}
					if _, err := itemShape.Admit(wrongRole, "entry"); err == nil {
						t.Fatal("accepted a known role for the wrong catalog path")
					}
				}
				tooMany := append(append([]any(nil), entries...), entries[0])
				if _, err := entryShape.Admit(tooMany, "entries"); err == nil {
					t.Fatal("accepted26entries")
				}
			}
			if state == "omitted" && len(value["omissions"].(map[string]any)["omittedRecognized"].([]any)) != 25 {
				t.Fatal("expected the complete omitted catalog")
			}
			if state == "oversize" {
				omitted := value["omissions"].(map[string]any)["omittedRecognized"].([]any)
				if len(omitted) != 1 || omitted[0].(map[string]any)["reason"] != "over_file_limit" {
					t.Fatal("expected the native oversize omission")
				}
			}
		})
	}
	omissions, _ := shape.Property("omissions")
	omitted, _ := omissions.Property("omittedRecognized")
	omission, _ := omitted.Element()
	reason, _ := omission.Property("reason")
	for _, value := range []string{"non_text", "over_file_limit"} {
		if _, err := reason.Admit(value, "reason"); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []any{"foreign", "non_text ", "", nil, false} {
		if _, err := reason.Admit(value, "reason"); err == nil {
			t.Fatal("accepted invalid omission reason enum member")
		}
	}
	for _, field := range []string{"rootEntryCount", "unrecognizedCount"} {
		count, _ := omissions.Property(field)
		for _, valid := range []json.Number{"0", "4096"} {
			if _, err := count.Admit(valid, field); err != nil {
				t.Fatal(err)
			}
		}
		for _, invalid := range []any{json.Number("-1"), json.Number("4097"), json.Number("0.5"), "0", nil} {
			if _, err := count.Admit(invalid, field); err == nil {
				t.Fatalf("accepted invalid %s", field)
			}
		}
	}
}
