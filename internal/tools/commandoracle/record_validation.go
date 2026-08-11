package commandoracle

import (
	"errors"
	"reflect"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

type DecisionError struct {
	ID string
}

func (err *DecisionError) Error() string { return err.ID }

func decision(id string) error { return &DecisionError{ID: id} }

func DecisionID(err error) string {
	var typed *DecisionError
	if errors.As(err, &typed) {
		return typed.ID
	}
	return "internal_error"
}

func validateRecordShape(record Record) error {
	if record.ArtifactKind != ArtifactKind || record.CommandID != CommandID || record.SchemaVersion != SchemaVersion || record.State != "passed" {
		return decision("record.identity_invalid")
	}
	if !isSHA256(record.CandidateSetDigest) || !isSHA256(record.CounterfeitCorpusDigest) || !isSHA256(record.SourceSnapshotDigest) {
		return decision("record.digest_invalid")
	}
	if len(record.Entries) == 0 || len(record.ExecutionCommands) == 0 || len(record.NonClaims) != len(recordNonClaims) ||
		strings.TrimSpace(record.GoVersion) == "" || strings.TrimSpace(record.Platform) == "" || !repositorysnapshot.ValidRevision(record.SourceRevision) {
		return decision("record.closure_invalid")
	}
	for index := range record.NonClaims {
		if record.NonClaims[index] != recordNonClaims[index] {
			return decision("record.non_claims_invalid")
		}
	}
	candidates := make([]app.CommandCoverageOracleCandidate, 0, len(record.Entries))
	packageImports := map[string]string{}
	for _, entry := range record.Entries {
		candidates = append(candidates, entry.Candidate)
		if existing, exists := packageImports[entry.Candidate.PackagePath]; exists && existing != entry.PackageImportPath {
			return decision("record.package_import_conflict")
		}
		packageImports[entry.Candidate.PackagePath] = entry.PackageImportPath
	}
	if err := validateCandidates(candidates); err != nil {
		return err
	}
	if err := validateJoinedEntries(candidates, record.Entries, packageImports); err != nil {
		return err
	}
	candidateDigest, err := CandidateSetDigest(candidates)
	if err != nil || candidateDigest != record.CandidateSetDigest {
		return decision("record.candidate_set_digest_mismatch")
	}
	if !reflect.DeepEqual(record.ExecutionCommands, executionCommands(candidates)) {
		return decision("record.execution_commands_mismatch")
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
