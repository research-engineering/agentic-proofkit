package releasechange

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAdmitAndRenderVersionBoundChangeRecord(t *testing.T) {
	record, err := Admit(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireVersion(record, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(record, "@research-engineering/agentic-proofkit", "agentic-proofkit", true)
	for _, expected := range []string{
		"## Breaking Contract Changes", "## Additions", "## Migration", "Migration is required:",
		"## Platform Requirements", "## Known Limitations", "## Install", "## Rollback",
		"npm install -D @research-engineering/agentic-proofkit@1.2.3",
		"uv tool install agentic-proofkit==1.2.3",
		"`proofkit.contract.breaking`: Remove the inert field.",
	} {
		if !strings.Contains(notes, expected) {
			t.Fatalf("rendered notes missing %q:\n%s", expected, notes)
		}
	}
}

func TestAdmitRejectsAmbiguousOrIncompleteChangeRecords(t *testing.T) {
	t.Run("duplicate identity across sections", func(t *testing.T) {
		record := validRecord()
		record["additions"] = []any{map[string]any{"changeId": "proofkit.contract.breaking", "summary": "Duplicate identity."}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be unique") {
			t.Fatalf("Admit() error = %v, want duplicate identity rejection", err)
		}
	})
	t.Run("required migration without steps", func(t *testing.T) {
		record := validRecord()
		record["migration"] = map[string]any{"required": true, "steps": []any{}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be non-empty") {
			t.Fatalf("Admit() error = %v, want migration closure rejection", err)
		}
	})
	t.Run("no migration with steps", func(t *testing.T) {
		record := validRecord()
		record["migration"] = map[string]any{"required": false, "steps": []any{"Do something."}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "must be empty") {
			t.Fatalf("Admit() error = %v, want no-migration contradiction rejection", err)
		}
	})
	t.Run("version mismatch", func(t *testing.T) {
		record, err := Admit(validRecord())
		if err != nil {
			t.Fatal(err)
		}
		if err := RequireVersion(record, "1.2.4"); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("RequireVersion() error = %v, want mismatch", err)
		}
	})
	t.Run("multiline release-note field", func(t *testing.T) {
		record := validRecord()
		record["additions"] = []any{map[string]any{
			"changeId": "proofkit.release.license",
			"summary":  "Embed license evidence.\n## Forged Section",
		}}
		if _, err := Admit(record); err == nil || !strings.Contains(err.Error(), "single-line") {
			t.Fatalf("Admit() error = %v, want multiline rejection", err)
		}
	})
}

func TestReadRejectsDuplicateJSONKeys(t *testing.T) {
	content := `{"schemaVersion":1,"version":"1.2.3","version":"1.2.4"}`
	path := t.TempDir() + "/record.json"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("Read() error = %v, want duplicate-key rejection", err)
	}
}

func TestRenderRepresentsEmptyOptionalSectionsExplicitly(t *testing.T) {
	record := validRecord()
	record["knownLimitations"] = []any{}
	record["platformRequirements"] = []any{}
	admitted, err := Admit(record)
	if err != nil {
		t.Fatal(err)
	}
	notes := RenderMarkdown(admitted, "@research-engineering/agentic-proofkit", "agentic-proofkit", false)
	if strings.Count(notes, "- None.") < 2 {
		t.Fatalf("rendered notes must represent empty sections explicitly:\n%s", notes)
	}
}

func validRecord() map[string]any {
	return map[string]any{
		"schemaVersion": json.Number("1"),
		"version":       "1.2.3",
		"breakingChanges": []any{
			map[string]any{"changeId": "proofkit.contract.breaking", "summary": "Remove the inert field."},
		},
		"additions":            []any{map[string]any{"changeId": "proofkit.release.license", "summary": "Embed license evidence."}},
		"migration":            map[string]any{"required": true, "steps": []any{"Delete the obsolete input field."}},
		"platformRequirements": []any{"macOS 12.0 or later is required by Darwin wheels."},
		"knownLimitations":     []any{"TSX parsing remains unsupported."},
		"rollback":             map[string]any{"strategy": "previous_admitted_version"},
	}
}
