package commandoracle

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

const (
	ArtifactKind  = "proofkit.command-oracle-execution.v1"
	CommandID     = "proofkit.command-oracle-execution"
	RecordPath    = "artifacts/proofkit/command-oracle-execution.json"
	SchemaVersion = 1
)

var recordNonClaims = [...]string{
	"Command oracle execution proves only that current owner-selected Go tests reached cooperative route attributes and passed from the recorded materialized source snapshot.",
	"Command oracle execution does not prove assertion-branch execution, mutation adequacy, exhaustive semantic correctness, malicious-test resistance, producer authentication, merge satisfaction, or production readiness.",
}

func RecordNonClaims() []string {
	return append([]string(nil), recordNonClaims[:]...)
}

type JoinedEntry struct {
	Candidate         app.CommandCoverageOracleCandidate `json:"candidate"`
	ExecutionState    string                             `json:"executionState"`
	PackageImportPath string                             `json:"packageImportPath"`
}

type ExecutionCommand struct {
	Argv        []string `json:"argv"`
	PackagePath string   `json:"packagePath"`
}

type Record struct {
	ArtifactKind            string             `json:"artifactKind"`
	CandidateSetDigest      string             `json:"candidateSetDigest"`
	CommandID               string             `json:"commandId"`
	CounterfeitCorpusDigest string             `json:"counterfeitCorpusDigest"`
	Entries                 []JoinedEntry      `json:"entries"`
	ExecutionCommands       []ExecutionCommand `json:"executionCommands"`
	GoVersion               string             `json:"goVersion"`
	NonClaims               []string           `json:"nonClaims"`
	Platform                string             `json:"platform"`
	SchemaVersion           int                `json:"schemaVersion"`
	SourceRevision          string             `json:"sourceRevision"`
	SourceSnapshotDigest    string             `json:"sourceSnapshotDigest"`
	State                   string             `json:"state"`
}

type Evidence struct {
	Candidates   []app.CommandCoverageOracleCandidate
	Record       Record
	RecordBytes  []byte
	RecordDigest string
}

func buildEvidence(snapshot repositorysnapshot.Snapshot, candidates []app.CommandCoverageOracleCandidate, packageImports map[string]string, commands []ExecutionCommand, corpusDigest string) (Evidence, error) {
	orderedCandidates := append([]app.CommandCoverageOracleCandidate(nil), candidates...)
	if err := validateCandidates(orderedCandidates); err != nil {
		return Evidence{}, err
	}
	entries := make([]JoinedEntry, 0, len(orderedCandidates))
	for _, candidate := range orderedCandidates {
		packageImport, ok := packageImports[candidate.PackagePath]
		if !ok {
			return Evidence{}, decision("join.package_import_missing")
		}
		entries = append(entries, JoinedEntry{
			Candidate:         candidate,
			ExecutionState:    "passed",
			PackageImportPath: packageImport,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		return joinedIdentity(entries[left]) < joinedIdentity(entries[right])
	})
	if err := validateJoinedEntries(orderedCandidates, entries, packageImports); err != nil {
		return Evidence{}, err
	}
	candidateDigest, err := CandidateSetDigest(orderedCandidates)
	if err != nil {
		return Evidence{}, err
	}
	record := Record{
		ArtifactKind:            ArtifactKind,
		CandidateSetDigest:      candidateDigest,
		CommandID:               CommandID,
		CounterfeitCorpusDigest: corpusDigest,
		Entries:                 entries,
		ExecutionCommands:       cloneExecutionCommands(commands),
		GoVersion:               runtime.Version(),
		NonClaims:               RecordNonClaims(),
		Platform:                runtime.GOOS + "/" + runtime.GOARCH,
		SchemaVersion:           SchemaVersion,
		SourceRevision:          snapshot.Revision,
		SourceSnapshotDigest:    snapshot.Digest,
		State:                   "passed",
	}
	if err := validateRecordShape(record); err != nil {
		return Evidence{}, err
	}
	content, recordDigest, err := encodeRecord(record)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Candidates:   orderedCandidates,
		Record:       record,
		RecordBytes:  content,
		RecordDigest: recordDigest,
	}, nil
}

func validateCandidates(candidates []app.CommandCoverageOracleCandidate) error {
	if len(candidates) == 0 {
		return decision("candidate.inventory_empty")
	}
	seenTestIDs := map[string]struct{}{}
	seenMarkers := map[string]struct{}{}
	for index, candidate := range candidates {
		fields := []string{
			candidate.AssertionOracleID,
			candidate.CommandRef,
			candidate.ExpectedPublicOutcome,
			candidate.FalsificationEventID,
			candidate.NegativeCaseID,
			candidate.OracleKind,
			candidate.OwnerInvariantID,
			candidate.PackagePath,
			candidate.Selector,
			candidate.SourceMarker,
			candidate.SourcePath,
			candidate.TestID,
			candidate.TestName,
			candidate.WrongImplementationClass,
		}
		for _, field := range fields {
			if strings.TrimSpace(field) == "" {
				return decision("candidate.field_empty")
			}
		}
		if candidate.OracleKind != "semantic_route_falsifier" ||
			!strings.HasPrefix(candidate.PackagePath, "./") ||
			candidate.Selector != candidate.SourcePath+"::"+candidate.TestName ||
			!strings.HasSuffix(candidate.SourcePath, "_test.go") ||
			"./"+filepath.ToSlash(filepath.Dir(candidate.SourcePath)) != candidate.PackagePath ||
			!commandcoverage.ValidSourceMarker(candidate.SourceMarker) {
			return decision("candidate.identity_invalid")
		}
		if _, duplicate := seenTestIDs[candidate.TestID]; duplicate {
			return decision("candidate.test_id_duplicate")
		}
		if _, duplicate := seenMarkers[candidate.SourceMarker]; duplicate {
			return decision("candidate.source_marker_duplicate")
		}
		seenTestIDs[candidate.TestID] = struct{}{}
		seenMarkers[candidate.SourceMarker] = struct{}{}
		if index > 0 && candidateIdentity(candidates[index-1]) >= candidateIdentity(candidate) {
			return decision("candidate.order_invalid")
		}
	}
	return nil
}

func validateJoinedEntries(candidates []app.CommandCoverageOracleCandidate, entries []JoinedEntry, packageImports map[string]string) error {
	if len(entries) != len(candidates) {
		return decision("join.cardinality_mismatch")
	}
	for index, candidate := range candidates {
		entry := entries[index]
		if !reflect.DeepEqual(entry.Candidate, candidate) {
			return candidateMismatchDecision(candidate, entry.Candidate)
		}
		if entry.ExecutionState != "passed" {
			return decision("join.execution_state_invalid")
		}
		if entry.PackageImportPath != packageImports[candidate.PackagePath] || entry.PackageImportPath == "" {
			return decision("join.package_import_mismatch")
		}
		if index > 0 && joinedIdentity(entries[index-1]) >= joinedIdentity(entry) {
			return decision("join.order_invalid")
		}
	}
	return nil
}

func candidateMismatchDecision(expected, actual app.CommandCoverageOracleCandidate) error {
	checks := []struct {
		name          string
		expectedValue string
		actualValue   string
	}{
		{"assertionOracleId", expected.AssertionOracleID, actual.AssertionOracleID},
		{"commandRef", expected.CommandRef, actual.CommandRef},
		{"expectedPublicOutcome", expected.ExpectedPublicOutcome, actual.ExpectedPublicOutcome},
		{"falsificationEventId", expected.FalsificationEventID, actual.FalsificationEventID},
		{"negativeCaseId", expected.NegativeCaseID, actual.NegativeCaseID},
		{"oracleKind", expected.OracleKind, actual.OracleKind},
		{"ownerInvariantId", expected.OwnerInvariantID, actual.OwnerInvariantID},
		{"packagePath", expected.PackagePath, actual.PackagePath},
		{"selector", expected.Selector, actual.Selector},
		{"sourceMarker", expected.SourceMarker, actual.SourceMarker},
		{"sourcePath", expected.SourcePath, actual.SourcePath},
		{"testId", expected.TestID, actual.TestID},
		{"testName", expected.TestName, actual.TestName},
		{"wrongImplementationClassId", expected.WrongImplementationClass, actual.WrongImplementationClass},
	}
	for _, check := range checks {
		if check.expectedValue != check.actualValue {
			return decision("join.candidate_mismatch." + check.name)
		}
	}
	return decision("join.candidate_mismatch.unknown")
}

func candidateIdentity(candidate app.CommandCoverageOracleCandidate) string {
	return strings.Join([]string{
		candidate.CommandRef,
		candidate.Selector,
		candidate.TestID,
		candidate.OwnerInvariantID,
		candidate.FalsificationEventID,
		candidate.NegativeCaseID,
		candidate.WrongImplementationClass,
		candidate.AssertionOracleID,
		candidate.OracleKind,
		candidate.ExpectedPublicOutcome,
		candidate.SourceMarker,
		candidate.SourcePath,
		candidate.PackagePath,
		candidate.TestName,
	}, "\x00")
}

func CandidateSetDigest(candidates []app.CommandCoverageOracleCandidate) (string, error) {
	values := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, candidateValue(candidate))
	}
	content, err := stablejson.MarshalLayout(values, stablejson.LayoutCompact)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func ExecutionCommandRefs(evidence Evidence) []string {
	seen := map[string]struct{}{}
	for _, candidate := range evidence.Candidates {
		seen[candidate.CommandRef] = struct{}{}
	}
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}
