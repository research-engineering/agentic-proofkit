package commandoracle

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/app"
)

func recordValue(record Record) map[string]any {
	entries := make([]any, 0, len(record.Entries))
	for _, entry := range record.Entries {
		entries = append(entries, map[string]any{
			"candidate":         candidateValue(entry.Candidate),
			"executionState":    entry.ExecutionState,
			"packageImportPath": entry.PackageImportPath,
		})
	}
	return map[string]any{
		"artifactKind":            record.ArtifactKind,
		"candidateSetDigest":      record.CandidateSetDigest,
		"commandId":               record.CommandID,
		"counterfeitCorpusDigest": record.CounterfeitCorpusDigest,
		"entries":                 entries,
		"executionCommands":       executionCommandsValue(record.ExecutionCommands),
		"goVersion":               record.GoVersion,
		"nonClaims":               stringsToAny(record.NonClaims),
		"platform":                record.Platform,
		"schemaVersion":           record.SchemaVersion,
		"sourceRevision":          record.SourceRevision,
		"sourceSnapshotDigest":    record.SourceSnapshotDigest,
		"state":                   record.State,
	}
}

func candidateValue(candidate app.CommandCoverageOracleCandidate) map[string]any {
	return map[string]any{
		"assertionOracleId":          candidate.AssertionOracleID,
		"commandRef":                 candidate.CommandRef,
		"expectedPublicOutcome":      candidate.ExpectedPublicOutcome,
		"falsificationEventId":       candidate.FalsificationEventID,
		"negativeCaseId":             candidate.NegativeCaseID,
		"oracleKind":                 candidate.OracleKind,
		"ownerInvariantId":           candidate.OwnerInvariantID,
		"packagePath":                candidate.PackagePath,
		"selector":                   candidate.Selector,
		"sourceMarker":               candidate.SourceMarker,
		"sourcePath":                 candidate.SourcePath,
		"testId":                     candidate.TestID,
		"testName":                   candidate.TestName,
		"wrongImplementationClassId": candidate.WrongImplementationClass,
	}
}

func joinedIdentity(entry JoinedEntry) string {
	parts := []string{
		entry.Candidate.CommandRef,
		entry.Candidate.Selector,
		entry.Candidate.TestID,
		entry.Candidate.OwnerInvariantID,
		entry.Candidate.FalsificationEventID,
		entry.Candidate.NegativeCaseID,
		entry.Candidate.WrongImplementationClass,
		entry.Candidate.AssertionOracleID,
		entry.Candidate.OracleKind,
		entry.Candidate.ExpectedPublicOutcome,
		entry.Candidate.SourceMarker,
		entry.Candidate.SourcePath,
		entry.Candidate.PackagePath,
		entry.Candidate.TestName,
		entry.PackageImportPath,
		entry.ExecutionState,
	}
	return strings.Join(parts, "\x00")
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func executionCommandsValue(commands []ExecutionCommand) []any {
	values := make([]any, 0, len(commands))
	for _, command := range commands {
		values = append(values, map[string]any{
			"argv":        stringsToAny(command.Argv),
			"packagePath": command.PackagePath,
		})
	}
	return values
}

func cloneExecutionCommands(commands []ExecutionCommand) []ExecutionCommand {
	cloned := make([]ExecutionCommand, 0, len(commands))
	for _, command := range commands {
		cloned = append(cloned, ExecutionCommand{
			Argv:        append([]string(nil), command.Argv...),
			PackagePath: command.PackagePath,
		})
	}
	return cloned
}
