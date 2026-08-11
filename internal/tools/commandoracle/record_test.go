package commandoracle

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func TestDiagnosticRoundTripUsesOneStrictOwner(t *testing.T) {
	root := t.TempDir()
	evidence := validSyntheticEvidence(t)
	if err := WriteDiagnostic(root, evidence); err != nil {
		t.Fatalf("WriteDiagnostic() error = %v", err)
	}
	read, err := ReadDiagnostic(root)
	if err != nil {
		t.Fatalf("ReadDiagnostic() error = %v", err)
	}
	if read.RecordDigest != evidence.RecordDigest || !bytes.Equal(read.RecordBytes, evidence.RecordBytes) || !reflect.DeepEqual(read.Record, evidence.Record) {
		t.Fatalf("diagnostic round trip drifted: got %#v want %#v", read, evidence)
	}
}

func TestReadDiagnosticRejectsUnknownFieldAndOwnerInvalidJoin(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "unknown field",
			mutate: func(record map[string]any) {
				record["unexpected"] = true
			},
		},
		{
			name: "candidate join drift",
			mutate: func(record map[string]any) {
				entries := record["entries"].([]any)
				entries[0].(map[string]any)["candidate"].(map[string]any)["expectedPublicOutcome"] = "Counterfeit outcome."
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			evidence := validSyntheticEvidence(t)
			raw, err := admission.DecodeJSON(bytes.NewReader(evidence.RecordBytes), int64(len(evidence.RecordBytes)))
			if err != nil {
				t.Fatal(err)
			}
			record := raw.(map[string]any)
			testCase.mutate(record)
			content, err := stablejson.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, filepath.FromSlash(RecordPath))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, content, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadDiagnostic(root); err == nil {
				t.Fatal("ReadDiagnostic() admitted owner-invalid record")
			}
		})
	}
}

func TestWriteDiagnosticRejectsBytesFromAnotherRecord(t *testing.T) {
	evidence := validSyntheticEvidence(t)
	evidence.RecordBytes = append([]byte(nil), evidence.RecordBytes...)
	evidence.RecordBytes[0] = '['
	if err := WriteDiagnostic(t.TempDir(), evidence); DecisionID(err) != "record.bytes_invalid" {
		t.Fatalf("WriteDiagnostic() error = %v, want record.bytes_invalid", err)
	}
}

func validSyntheticEvidence(t *testing.T) Evidence {
	t.Helper()
	candidates := syntheticCandidates()
	candidateDigest, err := CandidateSetDigest(candidates)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]JoinedEntry, 0, len(candidates))
	for _, candidate := range candidates {
		entries = append(entries, JoinedEntry{
			Candidate:         candidate,
			ExecutionState:    "passed",
			PackageImportPath: "example.test/proofkit/internal/sample",
		})
	}
	record := Record{
		ArtifactKind:            ArtifactKind,
		CandidateSetDigest:      candidateDigest,
		CommandID:               CommandID,
		CounterfeitCorpusDigest: strings.Repeat("2", 64),
		Entries:                 entries,
		ExecutionCommands:       ExecutionCommandsForCandidates(candidates),
		GoVersion:               runtime.Version(),
		NonClaims:               RecordNonClaims(),
		Platform:                runtime.GOOS + "/" + runtime.GOARCH,
		SchemaVersion:           SchemaVersion,
		SourceRevision:          strings.Repeat("a", 40),
		SourceSnapshotDigest:    strings.Repeat("3", 64),
		State:                   "passed",
	}
	evidence, err := EvidenceForRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}
