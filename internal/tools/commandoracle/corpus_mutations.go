package commandoracle

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/app"
	"github.com/research-engineering/agentic-proofkit/internal/testsupport/commandcoverage"
	"github.com/research-engineering/agentic-proofkit/internal/tools/repositorysnapshot"
)

func evaluateCounterfeit(item counterfeitCase) string {
	if strings.HasPrefix(item.MutationID, "record-coordinate:") {
		coordinate := strings.TrimPrefix(item.MutationID, "record-coordinate:")
		mutated, err := syntheticRecordValue()
		if err != nil {
			return "internal_error"
		}
		if !mutateCoordinate(mutated, strings.TrimPrefix(coordinate, "record.")) {
			return "internal_error"
		}
		return admitMutatedRecord(mutated)
	}
	switch item.MutationID {
	case "positive-candidate":
		return decisionOrAdmit(validateCandidates(syntheticCandidates()))
	case "positive-joined":
		return evaluateJoinMutation("")
	case "positive-execution-shared-test":
		return evaluateEventMutation("positive")
	case "record-execution-command-drift":
		mutated, err := syntheticRecordValue()
		if err != nil {
			return "internal_error"
		}
		commands := mutated["executionCommands"].([]any)
		command := commands[0].(map[string]any)
		argv := command["argv"].([]any)
		argv[len(argv)-2] = "^TestCounterfeit$"
		return admitMutatedRecord(mutated)
	case "event-attribute-cross-test":
		return evaluateEventMutation("attribute-cross-test")
	case "event-attribute-duplicate":
		return evaluateEventMutation("attribute-duplicate")
	case "event-attribute-missing":
		return evaluateEventMutation("attribute-missing")
	case "event-descendant-skip":
		return evaluateEventMutation("descendant-skip")
	case "event-output-spoof":
		return evaluateEventMutation("output-spoof")
	case "event-package-pass-before-tests":
		return evaluateEventMutation("package-pass-before-tests")
	case "event-package-pass-missing":
		return evaluateEventMutation("package-pass-missing")
	case "event-pass-before-run":
		return evaluateEventMutation("pass-before-run")
	case "event-pass-duplicate":
		return evaluateEventMutation("pass-duplicate")
	case "event-pause-before-run":
		return evaluateEventMutation("pause-before-run")
	case "event-pause-duplicate":
		return evaluateEventMutation("pause-duplicate")
	case "event-run-duplicate":
		return evaluateEventMutation("run-duplicate")
	case "event-selected-fail":
		return evaluateEventMutation("selected-fail")
	case "event-selected-skip":
		return evaluateEventMutation("selected-skip")
	case "event-unknown-action":
		return evaluateEventMutation("unknown-action")
	case "join-correlated-command-identity":
		return evaluateJoinMutation("commandRef")
	case "join-correlated-outcome-marker":
		return evaluateJoinMutation("outcomeMarker")
	case "join-correlated-selector-test":
		return evaluateJoinMutation("selector")
	case "source-correlated-identity":
		left := repositorysnapshot.Snapshot{Digest: strings.Repeat("1", 64), Paths: []string{"go.mod"}, Revision: strings.Repeat("a", 40)}
		right := left
		right.Digest = strings.Repeat("2", 64)
		if repositorysnapshot.EqualIdentity(left, right) {
			return "admit"
		}
		return "source.current_snapshot_mismatch"
	default:
		return "internal_error"
	}
}

func evaluateJoinMutation(field string) string {
	candidates := syntheticCandidates()
	imports := map[string]string{"./internal/sample": "example.test/proofkit/internal/sample"}
	entries := make([]JoinedEntry, 0, len(candidates))
	for _, candidate := range candidates {
		entries = append(entries, JoinedEntry{Candidate: candidate, ExecutionState: "passed", PackageImportPath: imports[candidate.PackagePath]})
	}
	if field != "" {
		switch field {
		case "commandRef":
			entries[0].Candidate.CommandRef += ".counterfeit"
		case "outcomeMarker":
			entries[0].Candidate.ExpectedPublicOutcome += " Counterfeit."
			entries[0].Candidate.SourceMarker = strings.Repeat("9", len(entries[0].Candidate.SourceMarker))
		case "selector":
			entries[0].Candidate.Selector += ".counterfeit"
		}
	}
	return decisionOrAdmit(validateJoinedEntries(candidates, entries, imports))
}

func evaluateEventMutation(mutation string) string {
	candidates := syntheticCandidates()
	imports := map[string]string{"./internal/sample": "example.test/proofkit/internal/sample"}
	ledger, err := newEventLedger(candidates, imports)
	if err != nil {
		return DecisionID(err)
	}
	key := selectedTestKey{Package: imports["./internal/sample"], Test: "TestShared"}
	observe := func(event testEvent) string {
		if err := ledger.observe(event); err != nil {
			return DecisionID(err)
		}
		return ""
	}
	if got := observe(testEvent{Action: "start", Package: key.Package}); got != "" {
		return got
	}
	if mutation == "unknown-action" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "counterfeit", Package: key.Package}))
	}
	if mutation == "package-pass-before-tests" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pass", Package: key.Package}))
	}
	if mutation == "pass-before-run" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}))
	}
	if mutation == "pause-before-run" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pause", Package: key.Package, Test: key.Test}))
	}
	if got := observe(testEvent{Action: "run", Package: key.Package, Test: key.Test}); got != "" {
		return got
	}
	if mutation == "pause-duplicate" {
		if got := observe(testEvent{Action: "pause", Package: key.Package, Test: key.Test}); got != "" {
			return got
		}
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pause", Package: key.Package, Test: key.Test}))
	}
	if mutation == "run-duplicate" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "run", Package: key.Package, Test: key.Test}))
	}
	if mutation == "attribute-cross-test" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "attr", Package: key.Package, Test: "TestOther", Key: commandcoverage.ExecutionAttributeKey, Value: candidates[0].SourceMarker}))
	}
	if mutation == "descendant-skip" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "skip", Package: key.Package, Test: key.Test + "/child"}))
	}
	if mutation == "selected-fail" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "fail", Package: key.Package, Test: key.Test}))
	}
	if mutation == "selected-skip" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "skip", Package: key.Package, Test: key.Test}))
	}
	if mutation == "output-spoof" {
		if got := observe(testEvent{Action: "output", Package: key.Package, Test: key.Test, Value: candidates[0].SourceMarker}); got != "" {
			return got
		}
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}))
	}
	if mutation != "attribute-missing" {
		for _, candidate := range candidates {
			if got := observe(testEvent{Action: "attr", Package: key.Package, Test: key.Test, Key: commandcoverage.ExecutionAttributeKey, Value: candidate.SourceMarker}); got != "" {
				return got
			}
		}
	}
	if mutation == "attribute-duplicate" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "attr", Package: key.Package, Test: key.Test, Key: commandcoverage.ExecutionAttributeKey, Value: candidates[0].SourceMarker}))
	}
	if got := observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}); got != "" {
		return got
	}
	if mutation == "pass-duplicate" {
		return decisionOrAdmit(ledger.observe(testEvent{Action: "pass", Package: key.Package, Test: key.Test}))
	}
	if mutation != "package-pass-missing" {
		if got := observe(testEvent{Action: "pass", Package: key.Package}); got != "" {
			return got
		}
	}
	return decisionOrAdmit(ledger.finalize())
}

func decisionOrAdmit(err error) string {
	if err == nil {
		return "admit"
	}
	return DecisionID(err)
}

func syntheticCandidates() []app.CommandCoverageOracleCandidate {
	base := app.CommandCoverageOracleCandidate{
		AssertionOracleID:        "proofkit.oracle.one",
		CommandRef:               "proofkit.cli.sample",
		ExpectedPublicOutcome:    "Sample command rejects the counterfeit input.",
		FalsificationEventID:     "proofkit.falsifier.one",
		NegativeCaseID:           "proofkit.negative.one",
		OracleKind:               "semantic_route_falsifier",
		OwnerInvariantID:         "proofkit.invariant.one",
		PackagePath:              "./internal/sample",
		Selector:                 "internal/sample/sample_test.go::TestShared",
		SourceMarker:             "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000001",
		SourcePath:               "internal/sample/sample_test.go",
		TestID:                   "proofkit.test.one",
		TestName:                 "TestShared",
		WrongImplementationClass: "proofkit.wrong.one",
	}
	second := base
	second.AssertionOracleID = "proofkit.oracle.two"
	second.FalsificationEventID = "proofkit.falsifier.two"
	second.NegativeCaseID = "proofkit.negative.two"
	second.OwnerInvariantID = "proofkit.invariant.two"
	second.SourceMarker = "proofkit.command_coverage.source_oracle.v1.000000000000000000000000000000000000000000000000000000000000000000000000000002"
	second.TestID = "proofkit.test.two"
	second.WrongImplementationClass = "proofkit.wrong.two"
	return []app.CommandCoverageOracleCandidate{base, second}
}
