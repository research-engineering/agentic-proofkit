package workflowsmoke

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceconversion"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

// sourceConversionInput is canonical grouped codec output, so the import of
// its flat export must reproduce exactly this value and basisDigest must be
// the sha256 of these bytes; neither expectation uses the converter.
const sourceConversionInput = `{
  "schemaVersion": 2,
  "kind": "proofkit.requirement-source",
  "sourceId": "proofkit.smoke.conversion",
  "specPackagePath": "docs/specs/smoke",
  "sourceNonClaims": ["Carrier smoke sources do not execute native witnesses."],
  "profiles": [
    {"profileId":"RPROF-SMOKE","fields":{"ownerId":"smoke.owner","claimLevel":"advisory","riskClass":"low"}}
  ],
  "groups": [
    {
      "groupId": "RGRP-SMOKE",
      "profileId": "RPROF-SMOKE",
      "statementStem": "The carrier must",
      "sharedPremises": ["The carrier is installed."],
      "members": [
        {"requirementId":"REQ-SMOKE-001","statementCompletion":"export grouped sources.","fields":{"nonClaims":[],"externalNonClaimRefs":[],"proofBindingRefs":[],"nonClaimRefs":[],"lifecycle":{"state":"active"},"deferral":null,"updatePolicy":{"reviewOwnerId":"smoke.owner"}}}
      , {"requirementId":"REQ-SMOKE-002","statementCompletion":"import flat documents.","fields":{"nonClaims":[],"externalNonClaimRefs":[],"proofBindingRefs":[],"nonClaimRefs":[],"lifecycle":{"state":"active"},"deferral":null,"updatePolicy":{"reviewOwnerId":"smoke.owner"}}}
      ]
    }
  ]
}
`

const sourceConversionLegacyInput = `{"schemaVersion":1,"sourceId":"proofkit.smoke.legacy","specPackagePath":"docs/specs/smoke","nonClaims":["Legacy smoke sources are refused."],"requirements":[]}`

// verifySourceConversion proves export, baseline-checked import and the four
// refusal classes through the installed carrier.
func verifySourceConversion(ctx context.Context, run Runner) (returnErr error) {
	input := []byte(sourceConversionInput)
	grouped, err := admission.DecodeJSON(bytes.NewReader(input), int64(len(input)))
	if err != nil {
		return fmt.Errorf("decode source conversion smoke fixture: %w", err)
	}
	expectedFlat, err := requirementsourceconversion.ExportFlat(grouped)
	if err != nil {
		return fmt.Errorf("build expected source conversion export: %w", err)
	}
	sum := sha256.Sum256(input)
	if expectedFlat["basisDigest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		return fmt.Errorf("source conversion smoke fixture is not canonical grouped source bytes")
	}
	directory, err := os.MkdirTemp("", "proofkit-conversion-smoke-")
	if err != nil {
		return fmt.Errorf("create source conversion smoke directory: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(directory)) }()
	baseline := filepath.Join(directory, "baseline.json")
	stale := filepath.Join(directory, "stale.json")
	if err := os.WriteFile(baseline, input, 0o600); err != nil {
		return fmt.Errorf("write source conversion smoke baseline: %w", err)
	}
	if err := os.WriteFile(stale, []byte(strings.Replace(sourceConversionInput, "import flat documents.", "import flat records.", 1)), 0o600); err != nil {
		return fmt.Errorf("write stale source conversion smoke baseline: %w", err)
	}

	exported, err := invoke(ctx, run, "source conversion export", bytesInvocation(input, "requirement-source-conversion", "--input", "-", "--to", "flat"))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(exported, expectedFlat, "source conversion export"); err != nil {
		return err
	}
	imported, err := invoke(ctx, run, "source conversion import", bytesInvocation(exported.Stdout, "requirement-source-conversion", "--input", "-", "--to", "grouped", "--baseline", baseline))
	if err != nil {
		return err
	}
	if err := verifyExactJSONObject(imported, grouped.(map[string]any), "source conversion import"); err != nil {
		return err
	}

	divergent, err := divergentProfileValue(expectedFlat)
	if err != nil {
		return err
	}
	refusals := []struct {
		label    string
		input    []byte
		args     []string
		fragment string
	}{
		{"source conversion missing baseline", exported.Stdout, []string{"--to", "grouped"}, "--to grouped requires --baseline"},
		{"source conversion stale baseline", exported.Stdout, []string{"--to", "grouped", "--baseline", stale}, "refused input: stale_baseline at /basisDigest"},
		{"source conversion divergent profile value", divergent, []string{"--to", "grouped", "--baseline", baseline}, "refused input: profile_value_disagreement at /requirements/1/fields/claimLevel"},
		{"source conversion legacy source", []byte(sourceConversionLegacyInput), []string{"--to", "flat"}, "refused input: legacy_source_unsupported at /schemaVersion"},
		{"source conversion unconfined output", input, []string{"--to", "flat", "--output", filepath.Join(directory, "flat.json")}, "must be a repository-relative POSIX path"},
	}
	for _, refusal := range refusals {
		args := append([]string{"requirement-source-conversion", "--input", "-"}, refusal.args...)
		if err := verifyFailure(ctx, run, refusal.label, bytesInvocation(refusal.input, args...), refusal.fragment); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "flat.json")); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("source conversion refusal created an output file")
	}
	return nil
}

// divergentProfileValue edits one member's copy of a profile-owned value.
func divergentProfileValue(flat map[string]any) ([]byte, error) {
	encoded, err := stablejson.Marshal(flat)
	if err != nil {
		return nil, fmt.Errorf("encode source conversion smoke export: %w", err)
	}
	copy, err := admission.DecodeJSON(bytes.NewReader(encoded), int64(len(encoded)))
	if err != nil {
		return nil, fmt.Errorf("decode source conversion smoke export: %w", err)
	}
	rows, _ := copy.(map[string]any)["requirements"].([]any)
	if len(rows) != 2 {
		return nil, fmt.Errorf("source conversion smoke export has %d records, want 2", len(rows))
	}
	rows[1].(map[string]any)["fields"].(map[string]any)["claimLevel"] = "blocking"
	return stablejson.Marshal(copy)
}
