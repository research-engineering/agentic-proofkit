package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
)

type codecMutantManifest struct {
	SchemaVersion int           `json:"schemaVersion"`
	Kind          string        `json:"kind"`
	Mutants       []codecMutant `json:"mutants"`
}

type codecMutant struct {
	MutantID     string `json:"mutantId"`
	Layer        string `json:"layer"`
	ExpectedCode string `json:"expectedCode"`
	ExpectedPath string `json:"expectedPath"`
	Property     string `json:"property"`
}

func TestCodecMutantManifestClosesRepresentationFailures(t *testing.T) {
	manifest := readCodecMutants(t)
	if manifest.SchemaVersion != 1 || manifest.Kind != "proofkit.requirement-source-codec-mutants" {
		t.Fatalf("mutant manifest identity = %#v", manifest)
	}
	ids := make([]string, len(manifest.Mutants))
	allowedLayers := map[string]bool{"lexical": true, "model": true, "raw": true, "shape": true, "syntax": true}
	for index, mutant := range manifest.Mutants {
		ids[index] = mutant.MutantID
		if !allowedLayers[mutant.Layer] || mutant.ExpectedCode == "" || mutant.Property == "" {
			t.Fatalf("incomplete mutant row %#v", mutant)
		}
		payload := codecMutantPayload(t, mutant.MutantID)
		_, err := Parse(payload)
		assertDiagnostic(t, err, mutant.ExpectedCode, mutant.ExpectedPath)
		if strings.Contains(mutant.MutantID, "secret") || strings.Contains(mutant.MutantID, "dynamic_key") || strings.Contains(mutant.MutantID, "unknown_field") {
			const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
			if strings.Contains(err.Error(), sentinel) || strings.Contains(err.(*Error).Diagnostic().Path, sentinel) {
				t.Fatalf("mutant %s disclosed caller text", mutant.MutantID)
			}
		}
	}
	want := append([]string(nil), ids...)
	sort.Strings(want)
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("mutant IDs = %v, want sorted unique %v", ids, want)
	}
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			t.Fatalf("duplicate mutant ID %q", ids[index])
		}
	}
	expectedIDs := []string{
		"case_folded_field", "duplicate_field", "dynamic_key_wrong_type", "explicit_null",
		"fractional_integer", "invalid_utf8", "lone_surrogate", "missing_required",
		"multiple_values", "negative_zero", "secret_shaped_text", "semantic_duplicate_id",
		"unknown_field", "wrong_identity", "wrong_type",
	}
	if !reflect.DeepEqual(ids, expectedIDs) {
		t.Fatalf("mutant IDs = %v, want exact registry %v", ids, expectedIDs)
	}
}

func readCodecMutants(t *testing.T) codecMutantManifest {
	t.Helper()
	payload, err := os.ReadFile("testdata/codec-mutants.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := admission.DecodeTypedJSON[codecMutantManifest](bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var strict codecMutantManifest
	if err := decoder.Decode(&strict); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func codecMutantPayload(t *testing.T, mutantID string) []byte {
	t.Helper()
	const sentinel = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	valid := mustPayload(t)
	switch mutantID {
	case "case_folded_field":
		return mutateRoot(t, valid, func(root map[string]any) { root["SourceId"] = root["sourceId"]; delete(root, "sourceId") })
	case "duplicate_field":
		return duplicateRootField(t, valid, "sourceId")
	case "dynamic_key_wrong_type":
		return mutateRoot(t, valid, func(root map[string]any) {
			scenarios := root["scenarios"].([]any)
			examples := scenarios[0].(map[string]any)["examples"].([]any)
			examples[0].(map[string]any)["values"].(map[string]any)[sentinel] = true
		})
	case "explicit_null":
		return mutateRoot(t, valid, func(root map[string]any) { root["sourceId"] = nil })
	case "fractional_integer":
		return mutateRoot(t, valid, func(root map[string]any) { root["schemaVersion"] = json.Number("2.0") })
	case "invalid_utf8":
		return []byte{0xff}
	case "lone_surrogate":
		return bytes.Replace(valid, []byte(`"The codec does not prove implementation correctness."`), []byte(`"\ud800"`), 1)
	case "missing_required":
		return mutateRoot(t, valid, func(root map[string]any) { delete(root, "sourceId") })
	case "multiple_values":
		return append(append([]byte(nil), valid...), []byte("{}")...)
	case "negative_zero":
		return bytes.Replace(valid, []byte(`"start":0`), []byte(`"start":-0`), 1)
	case "secret_shaped_text":
		return mutateRoot(t, valid, func(root map[string]any) {
			definitions := root["nonClaimDefinitions"].([]any)
			definitions[0].(map[string]any)["statement"] = "token=" + sentinel
		})
	case "semantic_duplicate_id":
		return mutateRoot(t, valid, func(root map[string]any) {
			definitions := root["nonClaimDefinitions"].([]any)
			definitions[1].(map[string]any)["nonClaimId"] = definitions[0].(map[string]any)["nonClaimId"]
		})
	case "unknown_field":
		return mutateRoot(t, valid, func(root map[string]any) { root[sentinel] = true })
	case "wrong_identity":
		return mutateRoot(t, valid, func(root map[string]any) { root["schemaVersion"] = json.Number("3") })
	case "wrong_type":
		return mutateRoot(t, valid, func(root map[string]any) { root["sourceId"] = true })
	default:
		t.Fatalf("mutant %q has no executable factory", mutantID)
		return nil
	}
}
