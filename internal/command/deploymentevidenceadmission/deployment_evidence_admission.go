package deploymentevidenceadmission

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
)

const reportKind = "proofkit.deployment-evidence-admission"

var (
	endpointKinds        = []string{"stable", "temporary"}
	endpointKindSet      = toSet(endpointKinds)
	shaPinnedImageRegexp = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)
	commitRegexp         = regexp.MustCompile(`^[a-f0-9]{40}$`)
	rfc3339UTCRegexp     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$`)
	boundaryNonClaims    = []string{
		"Deployment evidence admission reports do not authenticate evidence refs or producer identity.",
		"Deployment evidence admission reports do not decide consumer environment, credential, endpoint, or merge policy.",
		"Deployment evidence admission reports do not define consumer deployment topology or required fact vocabulary.",
		"Deployment evidence admission reports do not execute deployment, rollback, endpoint, or publication checks.",
		"Deployment evidence admission reports do not prove selected harness quality, rollout approval, or production readiness.",
		"Deployment evidence admission reports do not read files or repositories.",
	}
)

type rawOperatorEvidence struct {
	EvidenceRef string
	Payload     any
}

type policy struct {
	ExpectedEvidenceSchema        string
	ExpectedProofScope            string
	ExpectedDeploymentClaim       string
	RequiredNonClaims             []string
	RequiredFactIDs               []string
	RequiredFactKinds             []string
	LocalRefIndicators            []string
	ForbiddenValueIndicators      []string
	TemporaryEndpointHostSuffixes []string
	RequireDigestPinnedImageRefs  bool
	RequireLowercaseSourceCommits bool
}

type input struct {
	AdmissionID         string
	Evidence            map[string]any
	EvidencePresent     bool
	RawOperatorEvidence []rawOperatorEvidence
	Policy              policy
	NonClaims           []string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return invalidInputReport(err.Error()), 1, nil
	}

	blockedReasons := []string{}
	failures := []string{}
	evidenceID := any(nil)
	factCount := 0
	endpointCount := 0

	if !input.EvidencePresent {
		blockedReasons = append(blockedReasons, "deployment evidence is required")
	} else {
		if findings, err := scanSecretShapedJSON(input.Evidence, "evidence"); err != nil {
			return invalidInputReport(err.Error()), 1, nil
		} else {
			failures = append(failures, findings...)
		}
		scanForbiddenValueIndicators(input.Evidence, "evidence", input.Policy, &failures)
		if value := stringField(input.Evidence, "evidenceId", "evidence", &blockedReasons); value != nil {
			evidenceID = *value
		}
		validateExactKeys(input.Evidence, []string{"deploymentClaim", "evidenceId", "facts", "nonClaims", "proofScope", "schema"}, "evidence", &failures)
		validateCoreFields(input.Evidence, input.Policy, &blockedReasons, &failures)
		facts := factsField(input.Evidence, &blockedReasons, &failures)
		factCount = len(facts)
		endpointCount = validateFacts(facts, input.Policy, &blockedReasons, &failures)
	}

	if findings, err := scanRawOperatorEvidence(input.RawOperatorEvidence); err != nil {
		return invalidInputReport(err.Error()), 1, nil
	} else {
		failures = append(failures, findings...)
	}

	blockedReasons = uniqueSorted(blockedReasons)
	failures = uniqueSorted(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	} else if len(blockedReasons) > 0 {
		state = "blocked"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.AdmissionID,
		State:         state,
		Summary: map[string]any{
			"blockedReasonCount":    len(blockedReasons),
			"endpointCount":         endpointCount,
			"evidenceId":            evidenceID,
			"factCount":             factCount,
			"failureCount":          len(failures),
			"requiredFactIdCount":   len(input.Policy.RequiredFactIDs),
			"requiredFactKindCount": len(input.Policy.RequiredFactKinds),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "blockedReasons", Value: stringSliceToAny(blockedReasons)},
			{Key: "failures", Value: stringSliceToAny(failures)},
		},
		RuleResults: deploymentEvidenceRuleResults(state, blockedReasons, failures),
		NonClaims:   stringSliceToAny(sortedStrings(append(append([]string{}, boundaryNonClaims...), input.NonClaims...))),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("deployment evidence admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"admissionId", "evidence", "nonClaims", "policy", "rawOperatorEvidence", "schemaVersion"}, "deployment evidence admission input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("deployment evidence admission schemaVersion must be 1")
	}
	admissionID, err := admit.RuleID(record["admissionId"], "deployment evidence admissionId")
	if err != nil {
		return input{}, err
	}
	var evidence map[string]any
	evidencePresent := false
	rawEvidence, hasEvidence := record["evidence"]
	if !hasEvidence {
		return input{}, fmt.Errorf("deployment evidence admission evidence must be an object")
	}
	if rawEvidence != nil {
		evidence, err = objectValue(rawEvidence, "deployment evidence admission evidence")
		if err != nil {
			return input{}, err
		}
		evidencePresent = true
	}
	rawOperatorEvidence, err := rawOperatorEvidenceArray(record["rawOperatorEvidence"])
	if err != nil {
		return input{}, err
	}
	policy, err := admitPolicy(record["policy"])
	if err != nil {
		return input{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "deployment evidence admission nonClaims", false)
	if err != nil {
		return input{}, err
	}
	return input{
		AdmissionID:         admissionID,
		Evidence:            evidence,
		EvidencePresent:     evidencePresent,
		RawOperatorEvidence: rawOperatorEvidence,
		Policy:              policy,
		NonClaims:           nonClaims,
	}, nil
}

func rawOperatorEvidenceArray(raw any) ([]rawOperatorEvidence, error) {
	if raw == nil {
		return []rawOperatorEvidence{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("deployment evidence rawOperatorEvidence must be an array when present")
	}
	result := make([]rawOperatorEvidence, 0, len(values))
	for index, item := range values {
		record, err := objectValue(item, fmt.Sprintf("deployment evidence rawOperatorEvidence[%d]", index))
		if err != nil {
			return nil, err
		}
		context := fmt.Sprintf("deployment evidence rawOperatorEvidence[%d]", index)
		if err := admit.KnownKeys(record, []string{"evidenceRef", "payload"}, context); err != nil {
			return nil, err
		}
		evidenceRef, err := text(record["evidenceRef"], context+".evidenceRef")
		if err != nil {
			return nil, err
		}
		if _, exists := record["payload"]; !exists {
			return nil, fmt.Errorf("%s.payload is required", context)
		}
		result = append(result, rawOperatorEvidence{EvidenceRef: evidenceRef, Payload: record["payload"]})
	}
	return result, nil
}

func admitPolicy(raw any) (policy, error) {
	record, err := objectValue(raw, "deployment evidence admission policy")
	if err != nil {
		return policy{}, err
	}
	if err := admit.KnownKeys(record, []string{"expectedDeploymentClaim", "expectedEvidenceSchema", "expectedProofScope", "forbiddenValueIndicators", "localRefIndicators", "requireDigestPinnedImageRefs", "requireLowercaseSourceCommits", "requiredFactIds", "requiredFactKinds", "requiredNonClaims", "temporaryEndpointHostSuffixes"}, "deployment evidence admission policy"); err != nil {
		return policy{}, err
	}
	requiredFactIDs, err := sortedRuleIDs(record["requiredFactIds"], "deployment evidence requiredFactIds", true)
	if err != nil {
		return policy{}, err
	}
	requiredFactKinds, err := sortedRuleIDs(record["requiredFactKinds"], "deployment evidence requiredFactKinds", true)
	if err != nil {
		return policy{}, err
	}
	if len(requiredFactIDs) == 0 && len(requiredFactKinds) == 0 {
		return policy{}, fmt.Errorf("deployment evidence policy must declare requiredFactIds or requiredFactKinds")
	}
	expectedEvidenceSchema, err := text(record["expectedEvidenceSchema"], "deployment evidence expectedEvidenceSchema")
	if err != nil {
		return policy{}, err
	}
	expectedProofScope, err := text(record["expectedProofScope"], "deployment evidence expectedProofScope")
	if err != nil {
		return policy{}, err
	}
	expectedDeploymentClaim, err := text(record["expectedDeploymentClaim"], "deployment evidence expectedDeploymentClaim")
	if err != nil {
		return policy{}, err
	}
	requiredNonClaims, err := sortedText(record["requiredNonClaims"], "deployment evidence requiredNonClaims", false)
	if err != nil {
		return policy{}, err
	}
	localRefIndicators, err := sortedText(record["localRefIndicators"], "deployment evidence localRefIndicators", false)
	if err != nil {
		return policy{}, err
	}
	forbiddenValueIndicators, err := sortedText(record["forbiddenValueIndicators"], "deployment evidence forbiddenValueIndicators", true)
	if err != nil {
		return policy{}, err
	}
	temporaryEndpointHostSuffixes, err := sortedText(record["temporaryEndpointHostSuffixes"], "deployment evidence temporaryEndpointHostSuffixes", true)
	if err != nil {
		return policy{}, err
	}
	requireDigestPinnedImageRefs, err := boolValue(record["requireDigestPinnedImageRefs"], "deployment evidence requireDigestPinnedImageRefs")
	if err != nil {
		return policy{}, err
	}
	requireLowercaseSourceCommits, err := boolValue(record["requireLowercaseSourceCommits"], "deployment evidence requireLowercaseSourceCommits")
	if err != nil {
		return policy{}, err
	}
	return policy{
		ExpectedEvidenceSchema:        expectedEvidenceSchema,
		ExpectedProofScope:            expectedProofScope,
		ExpectedDeploymentClaim:       expectedDeploymentClaim,
		RequiredNonClaims:             requiredNonClaims,
		RequiredFactIDs:               requiredFactIDs,
		RequiredFactKinds:             requiredFactKinds,
		LocalRefIndicators:            localRefIndicators,
		ForbiddenValueIndicators:      forbiddenValueIndicators,
		TemporaryEndpointHostSuffixes: temporaryEndpointHostSuffixes,
		RequireDigestPinnedImageRefs:  requireDigestPinnedImageRefs,
		RequireLowercaseSourceCommits: requireLowercaseSourceCommits,
	}, nil
}

func validateCoreFields(evidence map[string]any, policy policy, blockedReasons *[]string, failures *[]string) {
	schema := stringField(evidence, "schema", "evidence", blockedReasons)
	if schema != nil && *schema != policy.ExpectedEvidenceSchema {
		*failures = append(*failures, "evidence.schema must be "+policy.ExpectedEvidenceSchema)
	}
	proofScope := stringField(evidence, "proofScope", "evidence", blockedReasons)
	if proofScope != nil && *proofScope != policy.ExpectedProofScope {
		*failures = append(*failures, "evidence.proofScope must be "+policy.ExpectedProofScope)
	}
	deploymentClaim := stringField(evidence, "deploymentClaim", "evidence", blockedReasons)
	if deploymentClaim != nil && *deploymentClaim != policy.ExpectedDeploymentClaim {
		*failures = append(*failures, "evidence.deploymentClaim must be "+policy.ExpectedDeploymentClaim)
	}
	nonClaims := stringArrayField(evidence, "nonClaims", "evidence", blockedReasons)
	nonClaimSet := toSet(nonClaims)
	for _, claim := range policy.RequiredNonClaims {
		if _, exists := nonClaimSet[claim]; !exists {
			*blockedReasons = append(*blockedReasons, "evidence.nonClaims must include: "+claim)
		}
	}
}

func factsField(evidence map[string]any, blockedReasons *[]string, failures *[]string) []map[string]any {
	raw, ok := evidence["facts"].([]any)
	if !ok || len(raw) == 0 {
		*blockedReasons = append(*blockedReasons, "evidence.facts must be a non-empty array")
		return []map[string]any{}
	}
	facts := make([]map[string]any, 0, len(raw))
	for index, item := range raw {
		record, ok := item.(map[string]any)
		context := fmt.Sprintf("evidence.facts[%d]", index)
		if !ok {
			*blockedReasons = append(*blockedReasons, context+" must be an object")
			continue
		}
		validateExactKeys(record, []string{"factId", "imageRefs", "kind", "metadata", "refs", "sourceCommits", "urls"}, context, failures)
		facts = append(facts, record)
	}
	return facts
}

func validateFacts(facts []map[string]any, policy policy, blockedReasons *[]string, failures *[]string) int {
	factIDs := []string{}
	factKinds := []string{}
	endpointCount := 0
	for index, fact := range facts {
		context := fmt.Sprintf("evidence.facts[%d]", index)
		if factID := ruleIDField(fact, "factId", context, blockedReasons); factID != nil {
			factIDs = append(factIDs, *factID)
		}
		if kind := ruleIDField(fact, "kind", context, blockedReasons); kind != nil {
			factKinds = append(factKinds, *kind)
		}
		refs := optionalStringArrayField(fact, "refs", context, blockedReasons)
		imageRefs := optionalStringArrayField(fact, "imageRefs", context, blockedReasons)
		sourceCommits := optionalStringArrayField(fact, "sourceCommits", context, blockedReasons)
		urls := optionalEndpointArrayField(fact, context, blockedReasons, failures)
		endpointCount += len(urls)
		if len(refs)+len(imageRefs)+len(sourceCommits)+len(urls) == 0 {
			*blockedReasons = append(*blockedReasons, context+" must include at least one refs, urls, imageRefs, or sourceCommits entry")
		}
		for refIndex, ref := range refs {
			requireNonLocalRef(&ref, fmt.Sprintf("%s.refs[%d]", context, refIndex), policy, failures)
		}
		for imageIndex, ref := range imageRefs {
			validateImageRef(ref, fmt.Sprintf("%s.imageRefs[%d]", context, imageIndex), policy, failures)
		}
		for commitIndex, commit := range sourceCommits {
			validateSourceCommit(commit, fmt.Sprintf("%s.sourceCommits[%d]", context, commitIndex), policy, failures)
		}
		for endpointIndex, endpoint := range urls {
			validateEndpoint(endpoint, fmt.Sprintf("%s.urls[%d]", context, endpointIndex), policy, blockedReasons, failures)
		}
		if metadata, exists := fact["metadata"]; exists {
			if _, ok := metadata.(map[string]any); !ok {
				*blockedReasons = append(*blockedReasons, context+".metadata must be an object when present")
			}
		}
	}
	validateUnique(factIDs, "evidence facts factId", failures)
	factIDSet := toSet(factIDs)
	for _, required := range policy.RequiredFactIDs {
		if _, exists := factIDSet[required]; !exists {
			*blockedReasons = append(*blockedReasons, "evidence.facts must include factId: "+required)
		}
	}
	factKindSet := toSet(factKinds)
	for _, required := range policy.RequiredFactKinds {
		if _, exists := factKindSet[required]; !exists {
			*blockedReasons = append(*blockedReasons, "evidence.facts must include kind: "+required)
		}
	}
	return endpointCount
}

func optionalEndpointArrayField(fact map[string]any, context string, blockedReasons *[]string, failures *[]string) []map[string]any {
	rawValue, exists := fact["urls"]
	if !exists {
		return []map[string]any{}
	}
	raw, ok := rawValue.([]any)
	if !ok || len(raw) == 0 {
		*blockedReasons = append(*blockedReasons, context+".urls must be a non-empty array when present")
		return []map[string]any{}
	}
	endpoints := make([]map[string]any, 0, len(raw))
	for index, item := range raw {
		record, ok := item.(map[string]any)
		childContext := fmt.Sprintf("%s.urls[%d]", context, index)
		if !ok {
			*blockedReasons = append(*blockedReasons, childContext+" must be an object")
			continue
		}
		validateExactKeys(record, []string{"endpointId", "endpointKind", "expiresAt", "replacementPlanRef", "temporaryEndpointApprovalRef", "url"}, childContext, failures)
		endpoints = append(endpoints, record)
	}
	return endpoints
}

func validateEndpoint(endpoint map[string]any, context string, policy policy, blockedReasons *[]string, failures *[]string) {
	ruleIDField(endpoint, "endpointId", context, blockedReasons)
	endpointKind := enumField(endpoint, "endpointKind", endpointKindSet, endpointKinds, context, blockedReasons)
	rawURL := stringField(endpoint, "url", context, blockedReasons)
	if rawURL == nil {
		return
	}
	parsed, err := url.Parse(*rawURL)
	if err != nil || parsed.Host == "" {
		*failures = append(*failures, context+".url must be a valid URL")
		return
	}
	if parsed.Scheme != "https" {
		*failures = append(*failures, context+".url must use https")
	}
	if parsed.User != nil {
		*failures = append(*failures, context+".url must not contain URL credentials")
	}
	if isLocalRef(parsed.Hostname(), policy) {
		*failures = append(*failures, context+".url must not be local or loopback")
	}
	if endpointKind != nil && *endpointKind == "stable" && hasTemporaryEndpointSuffix(parsed.Hostname(), policy) {
		*failures = append(*failures, context+".url stable endpoint must not use a temporary endpoint host")
	}
	if endpointKind != nil && *endpointKind == "stable" {
		for _, field := range []string{"temporaryEndpointApprovalRef", "replacementPlanRef", "expiresAt"} {
			if _, exists := endpoint[field]; exists {
				*failures = append(*failures, fmt.Sprintf("%s.%s must be omitted for stable endpoints", context, field))
			}
		}
	}
	if endpointKind != nil && *endpointKind == "temporary" {
		requireNonLocalRef(stringField(endpoint, "temporaryEndpointApprovalRef", context, blockedReasons), context+".temporaryEndpointApprovalRef", policy, failures)
		requireNonLocalRef(stringField(endpoint, "replacementPlanRef", context, blockedReasons), context+".replacementPlanRef", policy, failures)
		expiresAt := stringField(endpoint, "expiresAt", context, blockedReasons)
		if expiresAt != nil && !rfc3339UTCRegexp.MatchString(*expiresAt) {
			*failures = append(*failures, context+".expiresAt must be an RFC3339 UTC timestamp")
		}
	}
}

func validateImageRef(value string, context string, policy policy, failures *[]string) {
	requireNonLocalRef(&value, context, policy, failures)
	if policy.RequireDigestPinnedImageRefs && !shaPinnedImageRegexp.MatchString(value) {
		*failures = append(*failures, context+" must be pinned by digest with @sha256:<64 hex>")
	}
}

func validateSourceCommit(value string, context string, policy policy, failures *[]string) {
	if policy.RequireLowercaseSourceCommits && !commitRegexp.MatchString(value) {
		*failures = append(*failures, context+" must be a 40-character lowercase git commit SHA")
	}
}

func deploymentEvidenceRuleResults(state string, blockedReasons []string, failures []string) []report.RuleResult {
	shapeStatus := "failed"
	shapeMessage := strings.Join(blockedReasons, "; ")
	if len(blockedReasons) == 0 {
		shapeStatus = "passed"
		shapeMessage = "deployment evidence shape is complete"
	}
	safetyStatus := "failed"
	safetyMessage := strings.Join(failures, "; ")
	if len(failures) == 0 {
		safetyStatus = "passed"
		safetyMessage = "deployment evidence safety checks passed"
	}
	resultStatus := "failed"
	if state == "passed" {
		resultStatus = "passed"
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.deployment-evidence-admission.result",
			Status:      resultStatus,
			Message:     "deployment evidence admission state is " + state,
			Diagnostics: []report.Diagnostic{{Key: "state", Value: state}},
		},
		{
			RuleID:      "proofkit.deployment-evidence-admission.safety",
			Status:      safetyStatus,
			Message:     safetyMessage,
			Diagnostics: []report.Diagnostic{{Key: "failures", Value: stringSliceToAny(failures)}},
		},
		{
			RuleID:      "proofkit.deployment-evidence-admission.shape",
			Status:      shapeStatus,
			Message:     shapeMessage,
			Diagnostics: []report.Diagnostic{{Key: "blockedReasons", Value: stringSliceToAny(blockedReasons)}},
		},
	}
}

func invalidInputReport(message string) report.Record {
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "invalid_input",
		State:         "failed",
		Summary: map[string]any{
			"blockedReasonCount":    0,
			"endpointCount":         0,
			"evidenceId":            nil,
			"factCount":             0,
			"failureCount":          1,
			"requiredFactIdCount":   0,
			"requiredFactKindCount": 0,
		},
		Diagnostics: []report.Diagnostic{{Key: "failures", Value: []any{message}}},
		RuleResults: []report.RuleResult{
			{
				Diagnostics: []report.Diagnostic{{Key: "failure", Value: message}},
				Message:     message,
				RuleID:      "proofkit.deployment-evidence-admission.input",
				Status:      "failed",
			},
		},
		NonClaims: []any{"invalid deployment evidence admission input does not prove deployment evidence state"},
	}
}

func objectValue(value any, context string) (map[string]any, error) {
	record, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	return record, nil
}

func text(value any, context string) (string, error) {
	return admit.NonEmptyText(value, context)
}

func boolValue(value any, context string) (bool, error) {
	raw, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", context)
	}
	return raw, nil
}

func stringField(record map[string]any, field string, context string, blockedReasons *[]string) *string {
	value, err := admit.NonEmptyText(record[field], context+"."+field)
	if err != nil {
		*blockedReasons = append(*blockedReasons, err.Error())
		return nil
	}
	return &value
}

func ruleIDField(record map[string]any, field string, context string, blockedReasons *[]string) *string {
	value := stringField(record, field, context, blockedReasons)
	if value == nil {
		return nil
	}
	admitted, err := admit.RuleID(*value, context+"."+field)
	if err != nil {
		*blockedReasons = append(*blockedReasons, err.Error())
		return nil
	}
	return &admitted
}

func enumField(record map[string]any, field string, values map[string]struct{}, orderedValues []string, context string, blockedReasons *[]string) *string {
	value := stringField(record, field, context, blockedReasons)
	if value == nil {
		return nil
	}
	if _, exists := values[*value]; !exists {
		*blockedReasons = append(*blockedReasons, fmt.Sprintf("%s.%s must be one of: %s", context, field, strings.Join(orderedValues, ", ")))
		return nil
	}
	return value
}

func stringArrayField(record map[string]any, field string, context string, blockedReasons *[]string) []string {
	raw, ok := record[field]
	if !ok {
		*blockedReasons = append(*blockedReasons, fmt.Sprintf("%s.%s must be a non-empty string array", context, field))
		return []string{}
	}
	values, err := admit.TextArray(raw, context+"."+field, false)
	if err != nil {
		*blockedReasons = append(*blockedReasons, err.Error())
		return []string{}
	}
	return uniqueSorted(values)
}

func optionalStringArrayField(record map[string]any, field string, context string, blockedReasons *[]string) []string {
	if _, exists := record[field]; !exists {
		return []string{}
	}
	return stringArrayField(record, field, context, blockedReasons)
}

func sortedText(value any, context string, allowEmpty bool) ([]string, error) {
	values, err := admit.TextArray(value, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	values = uniqueSorted(values)
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	return values, nil
}

func sortedRuleIDs(value any, context string, allowEmpty bool) ([]string, error) {
	values, err := sortedText(value, context, allowEmpty)
	if err != nil {
		return nil, err
	}
	for index, item := range values {
		admitted, err := admit.RuleID(item, context)
		if err != nil {
			return nil, err
		}
		values[index] = admitted
	}
	return values, nil
}

func validateExactKeys(record map[string]any, allowed []string, context string, failures *[]string) {
	if err := admit.KnownKeys(record, allowed, context); err != nil {
		*failures = append(*failures, err.Error())
	}
}

func validateUnique(values []string, context string, failures *[]string) {
	seen := map[string]struct{}{}
	duplicates := map[string]struct{}{}
	for _, value := range values {
		if _, exists := seen[value]; exists {
			duplicates[value] = struct{}{}
		}
		seen[value] = struct{}{}
	}
	if len(duplicates) > 0 {
		names := make([]string, 0, len(duplicates))
		for value := range duplicates {
			names = append(names, value)
		}
		sort.Strings(names)
		*failures = append(*failures, fmt.Sprintf("%s must be unique; duplicate value(s): %s", context, strings.Join(names, ", ")))
	}
}

func requireNonLocalRef(value *string, context string, policy policy, failures *[]string) {
	if value != nil && isLocalRef(*value, policy) {
		*failures = append(*failures, context+" must not use local, loopback, or temporary development evidence")
	}
}

func isLocalRef(value string, policy policy) bool {
	normalized := strings.ToLower(value)
	for _, indicator := range policy.LocalRefIndicators {
		if strings.Contains(normalized, strings.ToLower(indicator)) {
			return true
		}
	}
	return false
}

func hasTemporaryEndpointSuffix(value string, policy policy) bool {
	for _, suffix := range policy.TemporaryEndpointHostSuffixes {
		if strings.HasSuffix(value, suffix) {
			return true
		}
	}
	return false
}

func scanForbiddenValueIndicators(value any, path string, policy policy, failures *[]string) {
	if text, ok := value.(string); ok {
		normalized := strings.ToLower(text)
		forbidden := []string{}
		for _, indicator := range policy.ForbiddenValueIndicators {
			if strings.Contains(normalized, strings.ToLower(indicator)) {
				forbidden = append(forbidden, indicator)
			}
		}
		sort.Strings(forbidden)
		if len(forbidden) > 0 {
			*failures = append(*failures, fmt.Sprintf("%s must not contain caller-forbidden value indicator(s): %s", path, strings.Join(forbidden, ", ")))
		}
		return
	}
	if values, ok := value.([]any); ok {
		for index, item := range values {
			scanForbiddenValueIndicators(item, fmt.Sprintf("%s[%d]", path, index), policy, failures)
		}
		return
	}
	if record, ok := value.(map[string]any); ok {
		keys := make([]string, 0, len(record))
		for key := range record {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			scanForbiddenValueIndicators(record[key], path+"."+key, policy, failures)
		}
	}
}

func scanRawOperatorEvidence(records []rawOperatorEvidence) ([]string, error) {
	failures := []string{}
	for index, record := range records {
		findings, err := scanSecretShapedJSON(map[string]any{
			"evidenceRef": record.EvidenceRef,
			"payload":     record.Payload,
		}, fmt.Sprintf("rawOperatorEvidence[%d]", index))
		if err != nil {
			return nil, err
		}
		failures = append(failures, findings...)
	}
	return failures, nil
}

func scanSecretShapedJSON(value any, rootPath string) ([]string, error) {
	findings, err := secretjson.Scan(value, rootPath)
	if err != nil {
		return nil, err
	}
	messages := []string{}
	for _, finding := range findings {
		messages = append(messages, secretFindingMessage(finding))
	}
	return messages, nil
}

func secretFindingMessage(finding secretjson.Finding) string {
	switch finding.Kind {
	case secretjson.KindSecretShapedKey:
		return finding.Path + " must not contain secret-shaped key material"
	case secretjson.KindURLCredentials:
		return finding.Path + " must not contain URL credentials"
	case secretjson.KindURLCredentialsKey:
		return finding.Path + " must not contain URL credentials in key material"
	default:
		return finding.Path + " must not contain secret-shaped material"
	}
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
		}
		previous = value
	}
	return result
}

func sortedStrings(values []string) []string {
	sort.Strings(values)
	return values
}

func stringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}
