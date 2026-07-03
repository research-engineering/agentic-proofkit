package customruleboundary

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.custom-rule-boundary"

var severities = map[string]struct{}{
	"error":   {},
	"info":    {},
	"warning": {},
}

var findingEffects = map[string]struct{}{
	"append_only": {},
	"downgrade":   {},
	"suppress":    {},
}

var decisionEffects = map[string]struct{}{
	"downgrade":    {},
	"no_downgrade": {},
	"satisfy":      {},
}

var networkPolicies = map[string]struct{}{
	"external": {},
	"none":     {},
}

var credentialPolicies = map[string]struct{}{
	"live":         {},
	"local_secret": {},
	"none":         {},
}

var scopes = map[string]struct{}{
	"module_scoped":  {},
	"package_scoped": {},
	"profile_scoped": {},
}

var remediationKinds = map[string]struct{}{
	"command_ref":       {},
	"documentation_ref": {},
	"human_review":      {},
}

var boundaryRoles = map[string]struct{}{
	"local_diagnostics_only": {},
}

var boundaryNonClaims = []any{
	"Custom-rule boundary reports do not approve suppression or downgrade of generic Proofkit findings.",
	"Custom-rule boundary reports do not execute custom rules.",
	"Custom-rule boundary reports do not own product requirement meaning or repository policy.",
	"Custom-rule boundary reports do not prove custom-rule findings, receipt freshness, or merge readiness.",
	"Custom-rule boundary reports do not read repository state.",
}

type deterministicOutput struct {
	SecretRedaction  bool
	StableFindingIDs bool
	StableOrdering   bool
}

type remediation struct {
	CommandRefs []string
	Kind        string
	Summary     string
}

type useLimit struct {
	MaxAffectedPathGlobs int
	Rationale            string
	Scope                string
}

type removal struct {
	Condition string
	Owner     string
	ReviewRef string
}

type ruleInput struct {
	AffectedPathGlobs     []string
	BoundaryRole          string
	CredentialPolicy      string
	DeterministicOutput   deterministicOutput
	GenericDecisionEffect string
	GenericFindingEffect  string
	InputArtifactKinds    []string
	InputArtifactRefs     []string
	Namespace             string
	NetworkPolicy         string
	NonClaims             []string
	OutputSchemaRef       string
	Owner                 string
	Remediation           remediation
	Removal               removal
	RuleID                string
	Severity              string
	UseLimit              useLimit
}

type admittedInput struct {
	BoundaryID string
	NonClaims  []string
	ProfileRef string
	Rules      []ruleInput
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	failures := []string{}
	for _, rule := range input.Rules {
		failures = append(failures, customRuleFailures(rule)...)
	}
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(admit.AnySliceToString(boundaryNonClaims), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.BoundaryID,
		State:         state,
		Summary: map[string]any{
			"customRuleCount":    len(input.Rules),
			"errorSeverityCount": countSeverity(input.Rules, "error"),
			"failureCount":       len(failures),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
			{Key: "profileRef", Value: input.ProfileRef},
		},
		RuleResults: customRuleRuleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("custom-rule boundary input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"boundaryId", "nonClaims", "profileRef", "rules", "schemaVersion"}, "custom-rule boundary input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("custom-rule boundary schemaVersion must be 1")
	}
	boundaryID, err := admit.RuleID(record["boundaryId"], "custom-rule boundary boundaryId")
	if err != nil {
		return admittedInput{}, err
	}
	profileText, err := admit.NonEmptyText(record["profileRef"], "custom-rule boundary profileRef")
	if err != nil {
		return admittedInput{}, err
	}
	profileRef, err := admit.SafeRepoRelativePath(profileText, "custom-rule boundary profileRef")
	if err != nil {
		return admittedInput{}, err
	}
	rules, err := ruleArray(record["rules"])
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "custom-rule boundary nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		BoundaryID: boundaryID,
		NonClaims:  nonClaims,
		ProfileRef: profileRef,
		Rules:      rules,
	}, nil
}

func ruleArray(raw any) ([]ruleInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("custom-rule boundary rules must be a non-empty array")
	}
	rules := make([]ruleInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("custom-rule boundary rules[%d] must be an object", index)
		}
		rule, err := admitRule(record)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(left int, right int) bool {
		return rules[left].RuleID < rules[right].RuleID
	})
	for index := 1; index < len(rules); index++ {
		if rules[index-1].RuleID == rules[index].RuleID {
			return nil, fmt.Errorf("custom-rule boundary rule ids must be sorted and unique")
		}
	}
	return rules, nil
}

func admitRule(record map[string]any) (ruleInput, error) {
	if err := admit.KnownKeys(record, []string{"affectedPathGlobs", "boundaryRole", "credentialPolicy", "deterministicOutput", "genericDecisionEffect", "genericFindingEffect", "inputArtifactKinds", "inputArtifactRefs", "namespace", "networkPolicy", "nonClaims", "outputSchemaRef", "owner", "remediation", "removal", "ruleId", "severity", "useLimit"}, "custom-rule boundary rule"); err != nil {
		return ruleInput{}, err
	}
	ruleID, err := admit.RuleID(record["ruleId"], "custom-rule boundary ruleId")
	if err != nil {
		return ruleInput{}, err
	}
	namespace, err := admit.RuleID(record["namespace"], fmt.Sprintf("custom-rule %s namespace", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], fmt.Sprintf("custom-rule %s owner", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	outputSchemaText, err := admit.NonEmptyText(record["outputSchemaRef"], fmt.Sprintf("custom-rule %s outputSchemaRef", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	outputSchemaRef, err := admit.SafeRepoRelativePath(outputSchemaText, fmt.Sprintf("custom-rule %s outputSchemaRef", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	boundaryRole, err := admit.Enum(record["boundaryRole"], boundaryRoles, fmt.Sprintf("custom-rule %s boundaryRole", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	severity, err := admit.Enum(record["severity"], severities, fmt.Sprintf("custom-rule %s severity", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	genericFindingEffect, err := admit.Enum(record["genericFindingEffect"], findingEffects, fmt.Sprintf("custom-rule %s genericFindingEffect", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	genericDecisionEffect, err := admit.Enum(record["genericDecisionEffect"], decisionEffects, fmt.Sprintf("custom-rule %s genericDecisionEffect", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	networkPolicy, err := admit.Enum(record["networkPolicy"], networkPolicies, fmt.Sprintf("custom-rule %s networkPolicy", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	credentialPolicy, err := admit.Enum(record["credentialPolicy"], credentialPolicies, fmt.Sprintf("custom-rule %s credentialPolicy", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	affectedPathGlobs, err := sortedGlobs(record["affectedPathGlobs"], fmt.Sprintf("custom-rule %s affectedPathGlobs", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	inputArtifactKinds, err := sortedRuleIDs(record["inputArtifactKinds"], fmt.Sprintf("custom-rule %s inputArtifactKinds", ruleID))
	if err != nil {
		return ruleInput{}, err
	}
	inputArtifactRefs, err := admit.PreserveSortedPathArray(record["inputArtifactRefs"], fmt.Sprintf("custom-rule %s inputArtifactRefs", ruleID), false)
	if err != nil {
		return ruleInput{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], fmt.Sprintf("custom-rule %s nonClaims", ruleID), false)
	if err != nil {
		return ruleInput{}, err
	}
	deterministicOutput, err := admitDeterministicOutput(record["deterministicOutput"], ruleID)
	if err != nil {
		return ruleInput{}, err
	}
	remediation, err := admitRemediation(record["remediation"], ruleID)
	if err != nil {
		return ruleInput{}, err
	}
	useLimit, err := admitUseLimit(record["useLimit"], ruleID)
	if err != nil {
		return ruleInput{}, err
	}
	removal, err := admitRemoval(record["removal"], ruleID)
	if err != nil {
		return ruleInput{}, err
	}
	return ruleInput{
		AffectedPathGlobs:     affectedPathGlobs,
		BoundaryRole:          boundaryRole,
		CredentialPolicy:      credentialPolicy,
		DeterministicOutput:   deterministicOutput,
		GenericDecisionEffect: genericDecisionEffect,
		GenericFindingEffect:  genericFindingEffect,
		InputArtifactKinds:    inputArtifactKinds,
		InputArtifactRefs:     inputArtifactRefs,
		Namespace:             namespace,
		NetworkPolicy:         networkPolicy,
		NonClaims:             nonClaims,
		OutputSchemaRef:       outputSchemaRef,
		Owner:                 owner,
		Remediation:           remediation,
		Removal:               removal,
		RuleID:                ruleID,
		Severity:              severity,
		UseLimit:              useLimit,
	}, nil
}

func admitDeterministicOutput(raw any, ruleID string) (deterministicOutput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return deterministicOutput{}, fmt.Errorf("custom-rule %s deterministicOutput must be an object", ruleID)
	}
	if err := admit.KnownKeys(record, []string{"secretRedaction", "stableFindingIds", "stableOrdering"}, fmt.Sprintf("custom-rule %s deterministicOutput", ruleID)); err != nil {
		return deterministicOutput{}, err
	}
	stableFindingIDs, err := admit.Bool(record["stableFindingIds"], fmt.Sprintf("custom-rule %s deterministicOutput.stableFindingIds", ruleID))
	if err != nil {
		return deterministicOutput{}, err
	}
	stableOrdering, err := admit.Bool(record["stableOrdering"], fmt.Sprintf("custom-rule %s deterministicOutput.stableOrdering", ruleID))
	if err != nil {
		return deterministicOutput{}, err
	}
	secretRedaction, err := admit.Bool(record["secretRedaction"], fmt.Sprintf("custom-rule %s deterministicOutput.secretRedaction", ruleID))
	if err != nil {
		return deterministicOutput{}, err
	}
	return deterministicOutput{
		SecretRedaction:  secretRedaction,
		StableFindingIDs: stableFindingIDs,
		StableOrdering:   stableOrdering,
	}, nil
}

func admitRemediation(raw any, ruleID string) (remediation, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return remediation{}, fmt.Errorf("custom-rule %s remediation must be an object", ruleID)
	}
	if err := admit.KnownKeys(record, []string{"commandRefs", "kind", "summary"}, fmt.Sprintf("custom-rule %s remediation", ruleID)); err != nil {
		return remediation{}, err
	}
	kind, err := admit.Enum(record["kind"], remediationKinds, fmt.Sprintf("custom-rule %s remediation.kind", ruleID))
	if err != nil {
		return remediation{}, err
	}
	summary, err := admit.NonEmptyText(record["summary"], fmt.Sprintf("custom-rule %s remediation.summary", ruleID))
	if err != nil {
		return remediation{}, err
	}
	commandRefs, err := admit.PreserveSortedTextArray(record["commandRefs"], fmt.Sprintf("custom-rule %s remediation.commandRefs", ruleID), true)
	if err != nil {
		return remediation{}, err
	}
	return remediation{CommandRefs: commandRefs, Kind: kind, Summary: summary}, nil
}

func admitUseLimit(raw any, ruleID string) (useLimit, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return useLimit{}, fmt.Errorf("custom-rule %s useLimit must be an object", ruleID)
	}
	if err := admit.KnownKeys(record, []string{"maxAffectedPathGlobs", "rationale", "scope"}, fmt.Sprintf("custom-rule %s useLimit", ruleID)); err != nil {
		return useLimit{}, err
	}
	scope, err := admit.Enum(record["scope"], scopes, fmt.Sprintf("custom-rule %s useLimit.scope", ruleID))
	if err != nil {
		return useLimit{}, err
	}
	maxAffectedPathGlobs, err := admit.PositiveInteger(record["maxAffectedPathGlobs"], fmt.Sprintf("custom-rule %s useLimit.maxAffectedPathGlobs", ruleID))
	if err != nil {
		return useLimit{}, err
	}
	rationale, err := admit.NonEmptyText(record["rationale"], fmt.Sprintf("custom-rule %s useLimit.rationale", ruleID))
	if err != nil {
		return useLimit{}, err
	}
	return useLimit{MaxAffectedPathGlobs: maxAffectedPathGlobs, Rationale: rationale, Scope: scope}, nil
}

func admitRemoval(raw any, ruleID string) (removal, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return removal{}, fmt.Errorf("custom-rule %s removal must be an object", ruleID)
	}
	if err := admit.KnownKeys(record, []string{"condition", "owner", "reviewRef"}, fmt.Sprintf("custom-rule %s removal", ruleID)); err != nil {
		return removal{}, err
	}
	condition, err := admit.NonEmptyText(record["condition"], fmt.Sprintf("custom-rule %s removal.condition", ruleID))
	if err != nil {
		return removal{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], fmt.Sprintf("custom-rule %s removal.owner", ruleID))
	if err != nil {
		return removal{}, err
	}
	reviewText, err := admit.NonEmptyText(record["reviewRef"], fmt.Sprintf("custom-rule %s removal.reviewRef", ruleID))
	if err != nil {
		return removal{}, err
	}
	reviewRef, err := admit.SafeRepoRelativePath(reviewText, fmt.Sprintf("custom-rule %s removal.reviewRef", ruleID))
	if err != nil {
		return removal{}, err
	}
	return removal{Condition: condition, Owner: owner, ReviewRef: reviewRef}, nil
}

func customRuleFailures(rule ruleInput) []string {
	failures := []string{}
	if !strings.HasPrefix(rule.RuleID, rule.Namespace+".") {
		failures = append(failures, fmt.Sprintf("custom rule %s must be namespaced under %s", rule.RuleID, rule.Namespace))
	}
	if strings.HasPrefix(rule.Namespace, "proofkit") {
		failures = append(failures, fmt.Sprintf("custom rule %s must not use proofkit-owned namespace", rule.RuleID))
	}
	if rule.GenericFindingEffect != "append_only" {
		failures = append(failures, fmt.Sprintf("custom rule %s must add findings only", rule.RuleID))
	}
	if rule.GenericDecisionEffect != "no_downgrade" {
		failures = append(failures, fmt.Sprintf("custom rule %s must not downgrade or satisfy generic decision state", rule.RuleID))
	}
	if rule.NetworkPolicy != "none" {
		failures = append(failures, fmt.Sprintf("custom rule %s must not access network", rule.RuleID))
	}
	if rule.CredentialPolicy != "none" {
		failures = append(failures, fmt.Sprintf("custom rule %s must not access credentials", rule.RuleID))
	}
	if !rule.DeterministicOutput.StableFindingIDs {
		failures = append(failures, fmt.Sprintf("custom rule %s must declare stable finding ids", rule.RuleID))
	}
	if !rule.DeterministicOutput.StableOrdering {
		failures = append(failures, fmt.Sprintf("custom rule %s must declare stable ordering", rule.RuleID))
	}
	if !rule.DeterministicOutput.SecretRedaction {
		failures = append(failures, fmt.Sprintf("custom rule %s must declare secret redaction", rule.RuleID))
	}
	if len(rule.AffectedPathGlobs) > rule.UseLimit.MaxAffectedPathGlobs {
		failures = append(failures, fmt.Sprintf("custom rule %s exceeds maxAffectedPathGlobs", rule.RuleID))
	}
	for _, glob := range rule.AffectedPathGlobs {
		if glob == "*" || glob == "**" || glob == "**/*" {
			failures = append(failures, fmt.Sprintf("custom rule %s must not use repository-wide catch-all affected globs", rule.RuleID))
			break
		}
	}
	if rule.Remediation.Kind == "command_ref" && len(rule.Remediation.CommandRefs) == 0 {
		failures = append(failures, fmt.Sprintf("custom rule %s command_ref remediation must declare command refs", rule.RuleID))
	}
	if rule.Remediation.Kind != "command_ref" && len(rule.Remediation.CommandRefs) > 0 {
		failures = append(failures, fmt.Sprintf("custom rule %s non-command remediation must not declare command refs", rule.RuleID))
	}
	if isVagueRemovalCondition(rule.Removal.Condition) {
		failures = append(failures, fmt.Sprintf("custom rule %s removal condition must be concrete", rule.RuleID))
	}
	return failures
}

func customRuleRuleResults(failures []string) []report.RuleResult {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{
			Key:   fmt.Sprintf("failure.%03d", index+1),
			Value: failure,
		})
	}
	status := "passed"
	if len(failures) > 0 {
		status = "failed"
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.custom-rule-boundary.boundary",
			Status:      "passed",
			Message:     "custom rules are validated as caller-provided metadata without execution",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.custom-rule-boundary.monotone-removable",
			Status:      status,
			Message:     "custom rules must remain append-only, deterministic, bounded, credential-free, network-free, and removable",
			Diagnostics: diagnostics,
		},
	}
}

func sortedRuleIDs(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique rule-id array", context)
	}
	ruleIDs := make([]string, 0, len(values))
	for _, value := range values {
		ruleID, err := admit.RuleID(value, context)
		if err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return admit.PreserveSortedText(ruleIDs, context, false)
}

func sortedGlobs(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique glob array", context)
	}
	globs := make([]string, 0, len(values))
	for _, value := range values {
		glob, err := admit.NonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		if _, err := admit.SafeRepoRelativePath(glob, fmt.Sprintf("glob %s", glob)); err != nil {
			return nil, err
		}
		globs = append(globs, glob)
	}
	return admit.PreserveSortedText(globs, context, false)
}

func countSeverity(rules []ruleInput, severity string) int {
	count := 0
	for _, rule := range rules {
		if rule.Severity == severity {
			count++
		}
	}
	return count
}

func isVagueRemovalCondition(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "none" ||
		normalized == "n/a" ||
		normalized == "na" ||
		normalized == "never" ||
		normalized == "tbd" ||
		normalized == "later" ||
		len(normalized) < 12
}
