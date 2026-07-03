package changedpathset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type SourceInput struct {
	Paths    []string
	SourceID string
}

type Input struct {
	NonClaims           []string
	PreexistingFailures []string
	ReportID            string
	Sources             []SourceInput
}

type Diagnostic struct {
	Path     string
	Reason   string
	SourceID string
}

type SourceSummary struct {
	AdmittedPathCount          int
	DuplicateAdmittedPathCount int
	DuplicateInputPathCount    int
	InputPathCount             int
	InvalidPathCount           int
	SourceID                   string
}

type Result struct {
	ChangedPaths       []string
	ChangedPathSetHash string
	DuplicatePaths     []Diagnostic
	ExitCode           int
	Failures           []string
	InvalidPaths       []Diagnostic
	Report             report.Record
	SourceSummaries    []SourceSummary
}

func Build(raw any) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		failure := errorText(err)
		emptyHash := changedPathsHash([]string{})
		record := report.Record{
			SchemaVersion: 1,
			ReportKind:    "proofkit.changed-path-set",
			ReportID:      "invalid-input",
			State:         "failed",
			Summary: map[string]any{
				"changedPathCount":   0,
				"duplicatePathCount": 0,
				"invalidPathCount":   1,
				"sourceCount":        0,
			},
			Diagnostics: []report.Diagnostic{{Key: "changedPathSetHash", Value: emptyHash}},
			RuleResults: []report.RuleResult{rule("changed_path_set.input", "failed", failure)},
			NonClaims:   []any{"invalid input does not prove changed path completeness"},
		}
		return Result{
			ChangedPaths:       []string{},
			ChangedPathSetHash: emptyHash,
			DuplicatePaths:     []Diagnostic{},
			ExitCode:           1,
			Failures:           []string{failure},
			InvalidPaths:       []Diagnostic{{SourceID: "input", Path: "", Reason: failure}},
			Report:             record,
			SourceSummaries:    []SourceSummary{},
		}, nil
	}
	return build(input), nil
}

func AgentEnvelope(result Result) map[string]any {
	sourceRefs := map[string]string{
		"changedPathSetHash": "proofkit.changed-path-set.context.set-hash",
		"changedPaths":       "proofkit.changed-path-set.context.changed-paths",
		"duplicatePaths":     "proofkit.changed-path-set.context.duplicate-paths",
		"failures":           "proofkit.changed-path-set.context.failures",
		"invalidPaths":       "proofkit.changed-path-set.context.invalid-paths",
		"sourceSummaries":    "proofkit.changed-path-set.context.source-summaries",
	}
	failed := result.ExitCode != 0 || len(result.Failures) > 0
	omitted := changedPathOmissions([]omissionSeed{
		{"proofkit.changed-path-set.omitted.changed-paths", len(result.ChangedPaths), "Changed path values remain in the source report.", sourceRefs["changedPaths"]},
		{"proofkit.changed-path-set.omitted.source-summaries", len(result.SourceSummaries), "Source summaries remain in the source report.", sourceRefs["sourceSummaries"]},
		{"proofkit.changed-path-set.omitted.invalid-paths", len(result.InvalidPaths), "Invalid path diagnostics remain in the source report.", sourceRefs["invalidPaths"]},
		{"proofkit.changed-path-set.omitted.duplicate-paths", len(result.DuplicatePaths), "Duplicate path diagnostics remain in the source report.", sourceRefs["duplicatePaths"]},
		{"proofkit.changed-path-set.omitted.failures", len(result.Failures), "Failure diagnostics remain in the source report.", sourceRefs["failures"]},
	})
	fanout := "bounded"
	if failed {
		fanout = "full-gate"
	} else if len(result.ChangedPaths) > 100 {
		fanout = "wide"
	}
	escalation := "Feed the changed-path set into a caller-owned selective planner; inspect the source report when exact path values are needed."
	if failed {
		escalation = "Repair the caller-owned changed-path source or run a caller-owned full gate before selective routing."
	}
	clarification := []map[string]any{}
	if len(result.ChangedPaths) == 0 && !failed {
		clarification = append(clarification, map[string]any{
			"askWhen":            "The admitted changed-path set is empty and no source failure was reported.",
			"blocking":           false,
			"evidenceRefs":       []any{sourceRefs["changedPaths"], sourceRefs["sourceSummaries"]},
			"expectedAnswerKind": "policy_choice",
			"nonClaim":           "The clarification question does not infer no-op safety or proof sufficiency.",
			"owner":              "consumer_repository",
			"question":           "Should this be treated as a no-op change or as a missing changed-path source that requires a full gate?",
			"questionId":         "proofkit.changed-path-set.clarify.empty-set",
		})
	}
	blockers := []map[string]any{}
	if failed {
		blockers = append(blockers, map[string]any{
			"description":    "Changed-path source has fail-closed diagnostics.",
			"evidenceRefs":   []any{sourceRefs["failures"], sourceRefs["invalidPaths"]},
			"nonClaim":       "This blocker does not choose the consumer repository fallback gate.",
			"owner":          "consumer_repository",
			"preconditionId": "proofkit.changed-path-set.blocked.failed-source",
		})
	}
	planInstruction := "Pass the admitted changed-path set to the caller-owned selective planner."
	planRationale := "The admitted set is the earliest bounded input to selective proof planning."
	planEvidence := []any{sourceRefs["changedPaths"]}
	if failed {
		planInstruction = "Use a caller-owned full gate or repair the changed-path source before selective planning."
		planRationale = "Fail-closed source diagnostics prevent hidden under-testing from an invalid change source."
		planEvidence = []any{sourceRefs["failures"]}
	}
	return agentenvelope.Build(agentenvelope.Input{
		EnvelopeID: result.Report.ReportID + ".agent-envelope",
		SourceReport: map[string]any{
			"artifactRef": nil,
			"nonClaim":    "Changed path set report identity does not prove git diff freshness, source completeness, or selective proof adequacy.",
			"reportId":    result.Report.ReportID,
			"reportKind":  result.Report.ReportKind,
			"stableHash":  result.ChangedPathSetHash,
			"state":       result.Report.State,
		},
		Bounds: map[string]any{
			"escalation":      escalation,
			"fanout":          fanout,
			"maxActionItems":  3,
			"maxCommandRefs":  0,
			"maxContextRefs":  6,
			"maxOmittedItems": len(omitted),
			"maxReceiptRefs":  0,
			"maxTokenBudget":  2200,
			"nonClaim":        "Changed-path set envelope bounds do not prove path-source completeness, proof coverage, command adequacy, receipt freshness, or merge satisfaction.",
			"omittedCount":    omittedCount(omitted),
		},
		ContextRefs: []map[string]any{
			contextRef(sourceRefs["changedPathSetHash"], "json-pointer", "evidence", "/changedPathSetHash", "Stable digest of the admitted changed path set for caller-owned correlation.", "The set hash does not prove that the caller supplied a fresh or complete change source."),
			contextRef(sourceRefs["changedPaths"], "json-pointer", "supporting", "/changedPaths", "Admitted changed paths for caller-owned selective proof planning.", "Changed path refs do not prove git freshness, path ownership, or proof coverage."),
			contextRef(sourceRefs["sourceSummaries"], "json-pointer", "supporting", "/sourceSummaries", "Caller-provided source counts and admission diagnostics.", "Source summaries do not authenticate the source producer or prove completeness."),
			contextRef(sourceRefs["failures"], "json-pointer", "rule_reference", "/failures", "Fail-closed source or admission failures that block selective routing.", "Failure refs do not choose the caller-owned fallback gate."),
			contextRef(sourceRefs["invalidPaths"], "json-pointer", "rule_reference", "/invalidPaths", "Rejected path diagnostics that explain admission failures.", "Invalid path diagnostics do not repair the caller-owned path source."),
			contextRef(sourceRefs["duplicatePaths"], "json-pointer", "supporting", "/duplicatePaths", "Deduplicated path diagnostics for caller-owned source hygiene.", "Duplicate diagnostics are warnings and do not prove source completeness."),
		},
		RouteQuestions: []map[string]any{
			routeQuestion("proofkit.changed-path-set.question.what-changed", "what changed", []any{sourceRefs["changedPaths"], sourceRefs["changedPathSetHash"]}, "This routes admitted caller-supplied paths only; it does not discover repository changes."),
			routeQuestion("proofkit.changed-path-set.question.what-proves-it", "what proves it", evidenceWhen(failed, []any{sourceRefs["failures"], sourceRefs["invalidPaths"]}, []any{sourceRefs["sourceSummaries"]}), "Changed-path admission proves only path-shape normalization, not native test success or requirement coverage."),
			routeQuestion("proofkit.changed-path-set.question.who-owns-it", "who owns it", []any{sourceRefs["sourceSummaries"]}, "The consuming repository owns changed-path source authority, freshness policy, and fallback policy."),
		},
		ClarificationQuestion: clarification,
		ActionPlan: []map[string]any{
			action("proofkit.changed-path-set.action-check-failures", "route", "Inspect changed-path source failures before using the set for selective proof routing.", "A failed changed-path report must not become the root of a narrow proof plan.", []any{sourceRefs["failures"], sourceRefs["invalidPaths"]}, []any{"Failure inspection does not execute native witnesses or approve merge."}),
			action("proofkit.changed-path-set.action-plan-selective-proof", "route", planInstruction, planRationale, planEvidence, []any{"Proofkit does not infer command ids, requirement routes, proof adequacy, or receipt freshness."}),
			action("proofkit.changed-path-set.action-record-downstream-receipts", "verify", "Record caller-owned receipts for any downstream selective or full gates that execute.", "Changed-path admission is route input, not executable proof evidence.", []any{sourceRefs["changedPathSetHash"]}, []any{"The envelope does not create, authenticate, or freshen receipts."}),
		},
		Commands:             []map[string]any{},
		BlockedPreconditions: blockers,
		Omitted:              omitted,
		ReceiptRefs:          []map[string]any{},
		NonClaims: []string{
			"Changed path set envelopes do not run git, inspect the filesystem, or discover changed paths.",
			"Changed path set envelopes do not infer proof routes, command ids, gate selection, or fallback policy.",
			"Changed path set envelopes do not prove source freshness, source completeness, receipt freshness, merge approval, release approval, or rollout approval.",
		},
	})
}

func build(input Input) Result {
	admittedBySource := map[string]map[string]struct{}{}
	invalidPaths := []Diagnostic{}
	duplicatePaths := []Diagnostic{}
	sourceSummaries := []SourceSummary{}
	for _, source := range input.Sources {
		admitted := map[string]struct{}{}
		inputSeen := map[string]struct{}{}
		invalidCount := 0
		duplicateInputCount := 0
		duplicateAdmittedCount := 0
		for _, rawPath := range source.Paths {
			if _, ok := inputSeen[rawPath]; ok {
				duplicateInputCount++
				duplicatePaths = append(duplicatePaths, Diagnostic{SourceID: source.SourceID, Path: safeDiagnosticPath(rawPath), Reason: "duplicate_input_path"})
			}
			inputSeen[rawPath] = struct{}{}
			pathValue, err := admit.SafeRepoRelativePath(rawPath, fmt.Sprintf("changed path source %s path", source.SourceID))
			if err != nil {
				invalidCount++
				invalidPaths = append(invalidPaths, Diagnostic{SourceID: source.SourceID, Path: safeDiagnosticPath(rawPath), Reason: err.Error()})
				continue
			}
			if _, ok := admitted[pathValue]; ok {
				duplicateAdmittedCount++
				duplicatePaths = append(duplicatePaths, Diagnostic{SourceID: source.SourceID, Path: safeDiagnosticPath(pathValue), Reason: "duplicate_admitted_path"})
			}
			admitted[pathValue] = struct{}{}
		}
		admittedBySource[source.SourceID] = admitted
		sourceSummaries = append(sourceSummaries, SourceSummary{
			SourceID: source.SourceID, InputPathCount: len(source.Paths), AdmittedPathCount: len(admitted), InvalidPathCount: invalidCount,
			DuplicateInputPathCount: duplicateInputCount, DuplicateAdmittedPathCount: duplicateAdmittedCount,
		})
	}
	pathSourceIDs := map[string][]string{}
	for sourceID, paths := range admittedBySource {
		for pathValue := range paths {
			pathSourceIDs[pathValue] = append(pathSourceIDs[pathValue], sourceID)
		}
	}
	for pathValue, sourceIDs := range pathSourceIDs {
		if len(sourceIDs) > 1 {
			sort.Strings(sourceIDs)
			for _, sourceID := range sourceIDs {
				duplicatePaths = append(duplicatePaths, Diagnostic{SourceID: sourceID, Path: safeDiagnosticPath(pathValue), Reason: "duplicate_cross_source_path"})
			}
		}
	}
	changedPaths := make([]string, 0, len(pathSourceIDs))
	for pathValue := range pathSourceIDs {
		changedPaths = append(changedPaths, pathValue)
	}
	sort.Strings(changedPaths)
	sortDiagnostics(invalidPaths)
	sortDiagnostics(duplicatePaths)
	failures := append([]string{}, input.PreexistingFailures...)
	for _, diagnostic := range invalidPaths {
		failures = append(failures, diagnostic.SourceID+": "+diagnostic.Reason)
	}
	sort.Strings(failures)
	state := "passed"
	exitCode := 0
	if len(failures) > 0 {
		state = "failed"
		exitCode = 1
	}
	hash := changedPathsHash(changedPaths)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.changed-path-set",
		ReportID:      input.ReportID,
		State:         state,
		Summary: map[string]any{
			"changedPathCount":   len(changedPaths),
			"duplicatePathCount": len(duplicatePaths),
			"invalidPathCount":   len(invalidPaths),
			"sourceCount":        len(input.Sources),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "changedPathSetHash", Value: hash},
			{Key: "duplicatePaths", Value: diagnosticsJSON(duplicatePaths)},
			{Key: "invalidPaths", Value: diagnosticsJSON(invalidPaths)},
			{Key: "sourceSummaries", Value: sourceSummariesJSON(sourceSummaries)},
		},
		RuleResults: []report.RuleResult{
			rule("changed_path_set.admission", statusWhen(len(invalidPaths) == 0, "passed", "failed"), messageWhen(len(invalidPaths) == 0, "all caller-supplied changed paths are admitted", "caller-supplied changed paths include invalid entries")),
			rule("changed_path_set.duplicates", statusWhen(len(duplicatePaths) == 0, "passed", "warning"), messageWhen(len(duplicatePaths) == 0, "no duplicate changed path evidence", "duplicate changed path evidence was deduplicated")),
			rule("changed_path_set.preexisting_failures", statusWhen(len(input.PreexistingFailures) == 0, "passed", "failed"), messageWhen(len(input.PreexistingFailures) == 0, "no caller preexisting failures", "caller supplied preexisting failures")),
		},
		NonClaims: stringsToAny(input.NonClaims),
	}
	return Result{ChangedPaths: changedPaths, ChangedPathSetHash: hash, DuplicatePaths: duplicatePaths, ExitCode: exitCode, Failures: failures, InvalidPaths: invalidPaths, Report: record, SourceSummaries: sourceSummaries}
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("changed path set report input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"nonClaims", "preexistingFailures", "reportId", "schemaVersion", "sources"}, "changed path set report input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("changed path set report input schemaVersion must be 1")
	}
	reportID, err := admit.RuleID(record["reportId"], "changed path set reportId")
	if err != nil {
		return Input{}, err
	}
	sources, err := sourceInputs(record["sources"])
	if err != nil {
		return Input{}, err
	}
	preexistingFailures, err := sortedUniqueText(record["preexistingFailures"], "changed path set preexistingFailures")
	if err != nil {
		return Input{}, err
	}
	nonClaims, err := sortedUniqueText(record["nonClaims"], "changed path set nonClaims")
	if err != nil {
		return Input{}, err
	}
	return Input{ReportID: reportID, Sources: sources, PreexistingFailures: preexistingFailures, NonClaims: nonClaims}, nil
}

func sourceInputs(raw any) ([]SourceInput, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("changed path set sources must be an array")
	}
	result := []SourceInput{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("changed path set source %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"paths", "sourceId"}, fmt.Sprintf("changed path set source %d", index+1)); err != nil {
			return nil, err
		}
		sourceID, err := admit.RuleID(record["sourceId"], fmt.Sprintf("changed path set source %d sourceId", index+1))
		if err != nil {
			return nil, err
		}
		paths, err := stringArray(record["paths"], fmt.Sprintf("changed path set source %s paths", sourceID))
		if err != nil {
			return nil, err
		}
		result = append(result, SourceInput{SourceID: sourceID, Paths: paths})
	}
	sort.Slice(result, func(left int, right int) bool { return result[left].SourceID < result[right].SourceID })
	for index := 1; index < len(result); index++ {
		if result[index-1].SourceID == result[index].SourceID {
			return nil, fmt.Errorf("changed path set sourceId must be unique")
		}
	}
	return result, nil
}

func changedPathsHash(paths []string) string {
	value := map[string]any{"changedPaths": stringsToAny(paths), "schemaVersion": 1}
	encoded, err := stablejson.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func safeDiagnosticPath(pathValue string) string {
	sanitized := strings.ReplaceAll(pathValue, "\x00", "\\0")
	if _, err := admit.NonEmptyText(sanitized, "changed path diagnostic path"); err == nil {
		return sanitized
	}
	sum := sha256.Sum256([]byte(pathValue))
	return "redacted-path:" + hex.EncodeToString(sum[:])
}

func rule(ruleID string, status string, message string) report.RuleResult {
	return report.RuleResult{RuleID: ruleID, Status: status, Message: message, Diagnostics: []report.Diagnostic{}}
}

func sortDiagnostics(values []Diagnostic) {
	sort.Slice(values, func(left int, right int) bool {
		return values[left].SourceID+"\x00"+values[left].Path+"\x00"+values[left].Reason < values[right].SourceID+"\x00"+values[right].Path+"\x00"+values[right].Reason
	})
}

func diagnosticsJSON(values []Diagnostic) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{"path": item.Path, "reason": item.Reason, "sourceId": item.SourceID})
	}
	return result
}

func sourceSummariesJSON(values []SourceSummary) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{
			"admittedPathCount":          item.AdmittedPathCount,
			"duplicateAdmittedPathCount": item.DuplicateAdmittedPathCount,
			"duplicateInputPathCount":    item.DuplicateInputPathCount,
			"inputPathCount":             item.InputPathCount,
			"invalidPathCount":           item.InvalidPathCount,
			"sourceId":                   item.SourceID,
		})
	}
	return result
}

type omissionSeed struct {
	ID          string
	Count       int
	Reason      string
	EvidenceRef string
}

func changedPathOmissions(seeds []omissionSeed) []map[string]any {
	result := []map[string]any{}
	for _, seed := range seeds {
		if seed.Count > 0 {
			result = append(result, map[string]any{
				"escalation":   "Inspect the source changed-path-set JSON when exact values are needed.",
				"evidenceRefs": []any{seed.EvidenceRef},
				"nonClaim":     "Omitted values remain in the source report; this envelope is a bounded routing artifact only.",
				"omissionId":   seed.ID,
				"omittedCount": seed.Count,
				"reason":       seed.Reason,
			})
		}
	}
	return result
}

func contextRef(refID string, kind string, role string, ref string, purpose string, nonClaim string) map[string]any {
	return map[string]any{"kind": kind, "nonClaim": nonClaim, "owner": "consumer_repository", "purpose": purpose, "ref": ref, "refId": refID, "role": role}
}

func routeQuestion(id string, question string, evidence []any, nonClaim string) map[string]any {
	return map[string]any{"evidenceRefs": evidence, "nonClaim": nonClaim, "question": question, "questionId": id}
}

func action(id string, phase string, instruction string, rationale string, evidence []any, nonClaims []any) map[string]any {
	return map[string]any{"commandIds": []any{}, "evidenceRefs": evidence, "instruction": instruction, "nonClaims": nonClaims, "owner": "consumer_repository", "phase": phase, "rationale": rationale, "stepId": id}
}

func evidenceWhen(condition bool, yes []any, no []any) []any {
	if condition {
		return yes
	}
	return no
}

func omittedCount(items []map[string]any) int {
	total := 0
	for _, item := range items {
		total += item["omittedCount"].(int)
	}
	return total
}

func sortedUniqueText(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%s must not contain empty strings", context)
		}
	}
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result, nil
}

func stringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		result = append(result, text)
	}
	return result, nil
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func statusWhen(condition bool, yes string, no string) string {
	if condition {
		return yes
	}
	return no
}

func messageWhen(condition bool, yes string, no string) string {
	if condition {
		return yes
	}
	return no
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
