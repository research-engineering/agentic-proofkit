package commandoracle

import (
	"bytes"
	"context"
	"reflect"
	"runtime"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

func ValidateCurrent(ctx context.Context, root string, evidence Evidence) error {
	admitted, err := EvidenceForRecord(evidence.Record)
	if err != nil {
		return err
	}
	if admitted.RecordDigest != evidence.RecordDigest || !bytes.Equal(admitted.RecordBytes, evidence.RecordBytes) {
		return decision("current.record_bytes_mismatch")
	}
	candidates, err := app.CommandCoverageOracleCandidatesAtRoot(root)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(candidates, evidence.Candidates) {
		return decision("current.candidate_projection_mismatch")
	}
	candidateDigest, err := CandidateSetDigest(candidates)
	if err != nil || candidateDigest != evidence.Record.CandidateSetDigest {
		return decision("current.candidate_set_digest_mismatch")
	}
	corpusDigest, err := ValidateCounterfeitCorpus(root)
	if err != nil {
		return err
	}
	if corpusDigest != evidence.Record.CounterfeitCorpusDigest {
		return decision("current.counterfeit_corpus_digest_mismatch")
	}
	modulePath, err := readModulePath(root)
	if err != nil {
		return err
	}
	if err := validateJoinedEntries(candidates, evidence.Record.Entries, packageImportPaths(modulePath, candidates)); err != nil {
		return err
	}
	if evidence.Record.GoVersion != runtime.Version() || evidence.Record.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		return decision("current.runtime_identity_mismatch")
	}
	snapshot, err := repositorysnapshot.CaptureContext(ctx, root)
	if err != nil {
		return err
	}
	if snapshot.Revision != evidence.Record.SourceRevision || snapshot.Digest != evidence.Record.SourceSnapshotDigest {
		return decision("current.source_snapshot_mismatch")
	}
	return nil
}
