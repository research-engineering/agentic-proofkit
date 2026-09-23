package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	adapter "github.com/research-engineering/agentic-proofkit/internal/command/jsonreportcliadaptersource"
	codec "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	model "github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

func TestSourceCoordinatesReachTheGeneratedTypeScriptParser(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for source-coordinate interoperability")
	}
	draft := model.Draft{
		SourceID: "source.coordinates", SpecPackagePath: "docs/specs/coordinates",
		SourceNonClaims: []string{"This synthetic source does not prove derivation provenance."},
		Groups: []model.Group{{GroupID: "RGRP-COORDINATES", Members: []model.Member{{
			RequirementID: "REQ-COORDINATES-001", StatementCompletion: "The consumer preserves coordinate identity.",
			Fields: model.MetadataFields{
				OwnerID: model.Own("owner.coordinates"), ClaimLevel: model.Own(model.ClaimAdvisory), RiskClass: model.Own(model.RiskLow),
				NonClaims: model.Own([]string{"No native witness is asserted."}), ExternalNonClaimRefs: model.Own([]string{}),
				NonClaimRefs: model.Own([]string{}), ProofBindingRefs: model.Own([]string{}),
				Lifecycle: model.Own(model.Lifecycle{State: model.LifecycleActive}), Deferral: model.Own[*model.Deferral](nil),
				UpdatePolicy: model.Own(model.UpdatePolicy{ReviewOwnerID: "owner.coordinates"}),
			},
		}}}},
		Derivations: []model.Derivation{{
			DerivationID: "DRV-COORDINATES-001", SourceKind: model.SourceOwnerDecision,
			SourceRef: model.GitBlobRef{ObjectFormat: model.ObjectSHA1,
				CommitOID: "0123456789abcdef0123456789abcdef01234567", Path: "docs/decisions/coordinates.md",
				SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			RequirementIDs: []string{"REQ-COORDINATES-001"},
		}},
	}
	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		name       string
		start, end int64
	}{
		{"small", 0, 1},
		{"wide", 9007199254740992, 9007199254740993},
		{"maximum", 9223372036854775806, 9223372036854775807},
	} {
		draft.Derivations[0].Selector = model.ByteRange{Start: item.start, End: item.end}
		admitted, err := model.Normalize(draft)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := codec.Format(admitted)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := codec.Parse(encoded)
		if err != nil || parsed.Model.References().Derivations[0].Selector != draft.Derivations[0].Selector {
			t.Fatalf("Go source-coordinate round trip: %v", err)
		}
		write(item.name+".json", encoded)
	}
	write("adapter.mts", []byte(adapter.TypeScriptSource()))
	write("check.mjs", []byte(`import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {parseProofkitJsonStrict} from "./adapter.mts";
for (const [name, start, end] of [
  ["small", "0", "1"],
  ["wide", "9007199254740992", "9007199254740993"],
  ["maximum", "9223372036854775806", "9223372036854775807"]
]) {
  const value = parseProofkitJsonStrict(readFileSync(new URL(name + ".json", import.meta.url), "utf8"));
  assert.equal(value.schemaVersion, 2);
  assert.equal(value.kind, "proofkit.requirement-source");
  assert.equal(value.derivations.length, 1);
  assert.deepEqual(value.derivations[0].selector, {start, end});
}
process.stdout.write("coordinate interoperability ok\n");
`))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "--experimental-strip-types", filepath.Join(dir, "check.mjs"))
	command.Dir = dir
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil || string(output) != "coordinate interoperability ok\n" {
		t.Fatalf("generated adapter did not confirm coordinate interoperability: %v\n%s", err, stderr.String())
	}
}
