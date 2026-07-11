package witnessschedulerplan

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

const reportKind = "proofkit.witness-scheduler-plan"

var sideEffectClasses = []string{"destructive", "local_write", "network", "none", "shared_resource"}
var sideEffectClassSet = toSet(sideEffectClasses)

var retryKinds = []string{"bounded", "none"}
var retryKindSet = toSet(retryKinds)

var cancellationKinds = []string{"cooperative", "not_supported"}
var cancellationKindSet = toSet(cancellationKinds)

var timeoutKinds = []string{"bounded"}
var timeoutKindSet = toSet(timeoutKinds)

var boundaryNonClaims = []string{
	"Witness scheduler plans do not authenticate producers or admit cache freshness.",
	"Witness scheduler plans do not decide CI runner allocation or merge approval.",
	"Witness scheduler plans do not execute commands.",
	"Witness scheduler plans do not inspect filesystem, network, locks, or cache state.",
	"Witness scheduler plans do not prove receipt freshness or command success.",
}

type retryPolicy struct {
	Kind        string
	MaxAttempts int
}

type cancellationPolicy struct {
	GraceMs *int
	Kind    string
}

type timeoutPolicy struct {
	Kind      string
	TimeoutMs int
}

type policy struct {
	CacheAdmissionRefs  []string
	CancellationPolicy  cancellationPolicy
	CommandID           string
	DeterministicOutput bool
	ExclusiveLocks      []string
	InputSelectors      []string
	NonClaims           []string
	OutputSelectors     []string
	ResourceReads       []string
	ResourceWrites      []string
	RetryPolicy         retryPolicy
	SideEffectClass     string
	TimeoutPolicy       timeoutPolicy
}

type executionGroup struct {
	CommandIDs        []string
	ExclusiveLocks    []string
	ParallelGroup     string
	SideEffectClasses []string
}

type CommandProjection struct {
	EnvironmentClasses []string
	ID                 string
}

type Projection struct {
	Commands        []CommandProjection
	SchedulerPlanID string
}

type admittedInput struct {
	Commands        []witnesscommand.Command
	NonClaims       []string
	Policies        []policy
	SchedulerPlanID string
}

func Build(raw any) (report.Record, int, error) {
	_, record, exitCode, err := Evaluate(raw)
	return record, exitCode, err
}

func Evaluate(raw any) (Projection, report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Projection{}, report.Record{}, 1, err
	}
	witnessPlan, err := witnesscommand.PlanCommands(input.Commands)
	if err != nil {
		return Projection{}, report.Record{}, 1, err
	}
	policiesByCommandID := map[string]policy{}
	for _, policy := range input.Policies {
		policiesByCommandID[policy.CommandID] = policy
	}
	executionGroups := make([]executionGroup, 0, len(witnessPlan.ParallelGroups))
	for _, group := range witnessPlan.ParallelGroups {
		groupPolicies := []policy{}
		for _, commandID := range group.CommandIDs {
			if policy, ok := policiesByCommandID[commandID]; ok {
				groupPolicies = append(groupPolicies, policy)
			}
		}
		executionGroups = append(executionGroups, executionGroup{
			CommandIDs:        group.CommandIDs,
			ExclusiveLocks:    uniqueSorted(flattenPolicyStrings(groupPolicies, func(policy policy) []string { return policy.ExclusiveLocks })),
			ParallelGroup:     group.ParallelGroup,
			SideEffectClasses: uniqueSorted(flattenPolicyStrings(groupPolicies, func(policy policy) []string { return []string{policy.SideEffectClass} })),
		})
	}
	failures := schedulerFailures(input.Commands, input.Policies, executionGroups)
	sort.Strings(failures)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]string{}, boundaryNonClaims...), input.NonClaims...)
	sort.Strings(nonClaims)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.SchedulerPlanID,
		State:         state,
		Summary: map[string]any{
			"cacheableCommandCount":   cacheableCommandCount(input.Commands),
			"commandCount":            len(input.Commands),
			"destructiveCommandCount": countDestructive(input.Policies),
			"executionGroupCount":     len(executionGroups),
			"exclusiveLockCount":      len(uniqueSorted(flattenPolicyStrings(input.Policies, func(policy policy) []string { return policy.ExclusiveLocks }))),
			"failureCount":            len(failures),
			"policyCount":             len(input.Policies),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "executionGroups", Value: executionGroupDiagnostics(executionGroups)},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	projection := Projection{
		Commands:        commandProjections(input.Commands),
		SchedulerPlanID: input.SchedulerPlanID,
	}
	if state == "passed" {
		return projection, record, 0, nil
	}
	return projection, record, 1, nil
}

func commandProjections(commands []witnesscommand.Command) []CommandProjection {
	result := make([]CommandProjection, 0, len(commands))
	for _, command := range commands {
		result = append(result, CommandProjection{
			EnvironmentClasses: append([]string{}, command.Environment.Classes...),
			ID:                 command.ID,
		})
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].ID < result[right].ID
	})
	return result
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("witness scheduler plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"commands", "nonClaims", "policies", "schedulerPlanId", "schemaVersion", "vocabulary"}, "witness scheduler plan input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("witness scheduler plan schemaVersion must be 1")
	}
	rawCommands, ok := record["commands"].([]any)
	if !ok || len(rawCommands) == 0 {
		return admittedInput{}, fmt.Errorf("witness scheduler plan commands must be a non-empty array")
	}
	vocabulary, err := witnesscommand.AdmitVocabulary(record["vocabulary"])
	if err != nil {
		return admittedInput{}, err
	}
	commands := make([]witnesscommand.Command, 0, len(rawCommands))
	for _, rawCommand := range rawCommands {
		command, err := witnesscommand.AdmitWithVocabulary(rawCommand, vocabulary)
		if err != nil {
			return admittedInput{}, err
		}
		commands = append(commands, command)
	}
	sort.Slice(commands, func(left int, right int) bool {
		return commands[left].ID < commands[right].ID
	})
	commandIDs := make([]string, 0, len(commands))
	for _, command := range commands {
		commandIDs = append(commandIDs, command.ID)
	}
	if err := preserveSortedUnique(commandIDs, "witness scheduler command ids", false); err != nil {
		return admittedInput{}, err
	}
	policies, err := policies(record["policies"])
	if err != nil {
		return admittedInput{}, err
	}
	policyCommandIDs := make([]string, 0, len(policies))
	for _, policy := range policies {
		policyCommandIDs = append(policyCommandIDs, policy.CommandID)
	}
	if err := preserveSortedUnique(policyCommandIDs, "witness scheduler policy command ids", false); err != nil {
		return admittedInput{}, err
	}
	schedulerPlanID, err := admit.RuleID(record["schedulerPlanId"], "witness scheduler plan schedulerPlanId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "witness scheduler plan nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		Commands:        commands,
		NonClaims:       nonClaims,
		Policies:        policies,
		SchedulerPlanID: schedulerPlanID,
	}, nil
}

func policies(raw any) ([]policy, error) {
	records, err := arrayOfRecords(raw, "witness scheduler policies")
	if err != nil {
		return nil, err
	}
	result := make([]policy, 0, len(records))
	for _, record := range records {
		item, err := admitPolicy(record)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	sort.Slice(result, func(left int, right int) bool {
		return result[left].CommandID < result[right].CommandID
	})
	return result, nil
}

func admitPolicy(record map[string]any) (policy, error) {
	if err := admit.KnownKeys(record, []string{"cacheAdmissionRefs", "cancellationPolicy", "commandId", "deterministicOutput", "exclusiveLocks", "inputSelectors", "nonClaims", "outputSelectors", "resourceReads", "resourceWrites", "retryPolicy", "sideEffectClass", "timeoutPolicy"}, "witness scheduler policy"); err != nil {
		return policy{}, err
	}
	commandID, err := admit.RuleID(record["commandId"], "witness scheduler policy commandId")
	if err != nil {
		return policy{}, err
	}
	inputSelectors, err := sortedSelectors(record["inputSelectors"], "witness scheduler "+commandID+" inputSelectors", true)
	if err != nil {
		return policy{}, err
	}
	outputSelectors, err := sortedSelectors(record["outputSelectors"], "witness scheduler "+commandID+" outputSelectors", true)
	if err != nil {
		return policy{}, err
	}
	resourceReads, err := sortedRuleIDs(record["resourceReads"], "witness scheduler "+commandID+" resourceReads", true)
	if err != nil {
		return policy{}, err
	}
	resourceWrites, err := sortedRuleIDs(record["resourceWrites"], "witness scheduler "+commandID+" resourceWrites", true)
	if err != nil {
		return policy{}, err
	}
	exclusiveLocks, err := sortedRuleIDs(record["exclusiveLocks"], "witness scheduler "+commandID+" exclusiveLocks", true)
	if err != nil {
		return policy{}, err
	}
	sideEffectClass, err := enum(record["sideEffectClass"], sideEffectClassSet, sideEffectClasses, "witness scheduler "+commandID+" sideEffectClass")
	if err != nil {
		return policy{}, err
	}
	deterministicOutput, err := boolField(record["deterministicOutput"], "witness scheduler "+commandID+" deterministicOutput")
	if err != nil {
		return policy{}, err
	}
	cacheAdmissionRefs, err := sortedPaths(record["cacheAdmissionRefs"], "witness scheduler "+commandID+" cacheAdmissionRefs", true)
	if err != nil {
		return policy{}, err
	}
	retryPolicy, err := admitRetryPolicy(record["retryPolicy"], commandID)
	if err != nil {
		return policy{}, err
	}
	cancellationPolicy, err := admitCancellationPolicy(record["cancellationPolicy"], commandID)
	if err != nil {
		return policy{}, err
	}
	timeoutPolicy, err := admitTimeoutPolicy(record["timeoutPolicy"], commandID)
	if err != nil {
		return policy{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "witness scheduler "+commandID+" nonClaims", false)
	if err != nil {
		return policy{}, err
	}
	return policy{
		CacheAdmissionRefs:  cacheAdmissionRefs,
		CancellationPolicy:  cancellationPolicy,
		CommandID:           commandID,
		DeterministicOutput: deterministicOutput,
		ExclusiveLocks:      exclusiveLocks,
		InputSelectors:      inputSelectors,
		NonClaims:           nonClaims,
		OutputSelectors:     outputSelectors,
		ResourceReads:       resourceReads,
		ResourceWrites:      resourceWrites,
		RetryPolicy:         retryPolicy,
		SideEffectClass:     sideEffectClass,
		TimeoutPolicy:       timeoutPolicy,
	}, nil
}

func admitRetryPolicy(raw any, commandID string) (retryPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return retryPolicy{}, fmt.Errorf("witness scheduler %s retryPolicy must be an object", commandID)
	}
	if err := admit.KnownKeys(record, []string{"kind", "maxAttempts"}, "witness scheduler "+commandID+" retryPolicy"); err != nil {
		return retryPolicy{}, err
	}
	kind, err := enum(record["kind"], retryKindSet, retryKinds, "witness scheduler "+commandID+" retryPolicy.kind")
	if err != nil {
		return retryPolicy{}, err
	}
	maxAttempts, err := positiveInteger(record["maxAttempts"], "witness scheduler "+commandID+" retryPolicy.maxAttempts")
	if err != nil {
		return retryPolicy{}, err
	}
	if kind == "none" && maxAttempts != 1 {
		return retryPolicy{}, fmt.Errorf("witness scheduler %s retryPolicy none must use maxAttempts 1", commandID)
	}
	if kind == "bounded" && (maxAttempts < 2 || maxAttempts > 10) {
		return retryPolicy{}, fmt.Errorf("witness scheduler %s retryPolicy bounded must use 2..10 attempts", commandID)
	}
	return retryPolicy{Kind: kind, MaxAttempts: maxAttempts}, nil
}

func admitCancellationPolicy(raw any, commandID string) (cancellationPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return cancellationPolicy{}, fmt.Errorf("witness scheduler %s cancellationPolicy must be an object", commandID)
	}
	if err := admit.KnownKeys(record, []string{"graceMs", "kind"}, "witness scheduler "+commandID+" cancellationPolicy"); err != nil {
		return cancellationPolicy{}, err
	}
	kind, err := enum(record["kind"], cancellationKindSet, cancellationKinds, "witness scheduler "+commandID+" cancellationPolicy.kind")
	if err != nil {
		return cancellationPolicy{}, err
	}
	var graceMs *int
	if record["graceMs"] != nil {
		value, err := positiveInteger(record["graceMs"], "witness scheduler "+commandID+" cancellationPolicy.graceMs")
		if err != nil {
			return cancellationPolicy{}, err
		}
		graceMs = &value
	}
	if kind == "cooperative" && graceMs == nil {
		return cancellationPolicy{}, fmt.Errorf("witness scheduler %s cooperative cancellation must declare graceMs", commandID)
	}
	if kind == "not_supported" && graceMs != nil {
		return cancellationPolicy{}, fmt.Errorf("witness scheduler %s unsupported cancellation must not declare graceMs", commandID)
	}
	return cancellationPolicy{GraceMs: graceMs, Kind: kind}, nil
}

func admitTimeoutPolicy(raw any, commandID string) (timeoutPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return timeoutPolicy{}, fmt.Errorf("witness scheduler %s timeoutPolicy must be an object", commandID)
	}
	if err := admit.KnownKeys(record, []string{"kind", "timeoutMs"}, "witness scheduler "+commandID+" timeoutPolicy"); err != nil {
		return timeoutPolicy{}, err
	}
	kind, err := enum(record["kind"], timeoutKindSet, timeoutKinds, "witness scheduler "+commandID+" timeoutPolicy.kind")
	if err != nil {
		return timeoutPolicy{}, err
	}
	timeoutMs, err := positiveInteger(record["timeoutMs"], "witness scheduler "+commandID+" timeoutPolicy.timeoutMs")
	if err != nil {
		return timeoutPolicy{}, err
	}
	return timeoutPolicy{Kind: kind, TimeoutMs: timeoutMs}, nil
}

func schedulerFailures(commands []witnesscommand.Command, policies []policy, executionGroups []executionGroup) []string {
	failures := []string{}
	commandsByID := map[string]witnesscommand.Command{}
	for _, command := range commands {
		commandsByID[command.ID] = command
	}
	policiesByCommandID := map[string]policy{}
	for _, policy := range policies {
		policiesByCommandID[policy.CommandID] = policy
	}
	for _, command := range commands {
		policy, ok := policiesByCommandID[command.ID]
		if !ok {
			failures = append(failures, "missing scheduler policy for witness command: "+command.ID)
			continue
		}
		failures = append(failures, commandPolicyFailures(command, policy)...)
	}
	for _, policy := range policies {
		if _, ok := commandsByID[policy.CommandID]; !ok {
			failures = append(failures, "scheduler policy references unknown witness command: "+policy.CommandID)
		}
	}
	failures = append(failures, parallelGroupFailures(executionGroups, policiesByCommandID)...)
	return failures
}

func commandPolicyFailures(command witnesscommand.Command, policy policy) []string {
	failures := []string{}
	if policy.TimeoutPolicy.TimeoutMs != command.TimeoutMs {
		failures = append(failures, "scheduler timeoutPolicy must match witness command timeoutMs: "+command.ID)
	}
	if command.CachePolicy != "disabled" {
		if !policy.DeterministicOutput {
			failures = append(failures, "cacheable command "+command.ID+" must declare deterministic output")
		}
		if command.NetworkPolicy != "none" {
			failures = append(failures, "cacheable command "+command.ID+" must not use network policy "+command.NetworkPolicy)
		}
		if command.CredentialClass != "none" {
			failures = append(failures, "cacheable command "+command.ID+" must not use credential class "+command.CredentialClass)
		}
		if len(policy.InputSelectors) == 0 {
			failures = append(failures, "cacheable command "+command.ID+" must declare input selectors")
		}
		if len(policy.CacheAdmissionRefs) == 0 {
			failures = append(failures, "cacheable command "+command.ID+" must cite cache admission refs")
		}
		for _, artifact := range command.ExpectedArtifacts {
			if artifact.Required && !contains(policy.OutputSelectors, artifact.Path) {
				failures = append(failures, "cacheable command "+command.ID+" must declare required artifact output selector: "+artifact.Path)
			}
		}
	}
	if command.CachePolicy == "disabled" && len(policy.CacheAdmissionRefs) > 0 {
		failures = append(failures, "non-cacheable command "+command.ID+" must not cite cache admission refs")
	}
	if command.NetworkPolicy != "none" && policy.SideEffectClass == "none" {
		failures = append(failures, "networked command "+command.ID+" must not declare sideEffectClass none")
	}
	if command.NetworkPolicy != "none" && policy.DeterministicOutput {
		failures = append(failures, "networked command "+command.ID+" must not declare deterministic output")
	}
	if command.NetworkPolicy == "none" && policy.SideEffectClass == "network" {
		failures = append(failures, "non-networked command "+command.ID+" must not declare sideEffectClass network")
	}
	if policy.SideEffectClass == "none" && len(policy.ResourceWrites) > 0 {
		failures = append(failures, "side-effect-free command "+command.ID+" must not declare resource writes")
	}
	if policy.SideEffectClass == "none" && len(policy.ExclusiveLocks) > 0 {
		failures = append(failures, "side-effect-free command "+command.ID+" must not declare exclusive locks")
	}
	if policy.SideEffectClass == "local_write" && len(policy.ResourceWrites) == 0 {
		failures = append(failures, "local-write command "+command.ID+" must declare resource writes")
	}
	if (policy.SideEffectClass == "shared_resource" || policy.SideEffectClass == "destructive") && len(policy.ResourceReads) == 0 && len(policy.ResourceWrites) == 0 {
		failures = append(failures, "shared or destructive command "+command.ID+" must declare resource reads or writes")
	}
	if (policy.SideEffectClass == "shared_resource" || policy.SideEffectClass == "destructive") && len(policy.ExclusiveLocks) == 0 {
		failures = append(failures, "shared or destructive command "+command.ID+" must declare exclusive locks")
	}
	if policy.SideEffectClass == "destructive" && policy.RetryPolicy.Kind != "none" {
		failures = append(failures, "destructive command "+command.ID+" must not retry automatically")
	}
	if policy.SideEffectClass == "destructive" && policy.CancellationPolicy.Kind != "cooperative" {
		failures = append(failures, "destructive command "+command.ID+" must support cooperative cancellation")
	}
	return failures
}

func parallelGroupFailures(groups []executionGroup, policiesByCommandID map[string]policy) []string {
	failures := []string{}
	for _, group := range groups {
		if parallelGroupIsConflictFreeByConstruction(group, policiesByCommandID) {
			continue
		}
		for leftIndex := 0; leftIndex < len(group.CommandIDs); leftIndex++ {
			left, ok := policiesByCommandID[group.CommandIDs[leftIndex]]
			if !ok {
				continue
			}
			for rightIndex := leftIndex + 1; rightIndex < len(group.CommandIDs); rightIndex++ {
				right, ok := policiesByCommandID[group.CommandIDs[rightIndex]]
				if !ok {
					continue
				}
				failures = append(failures, policyPairFailures(group.ParallelGroup, left, right)...)
			}
		}
	}
	return failures
}

func parallelGroupIsConflictFreeByConstruction(group executionGroup, policiesByCommandID map[string]policy) bool {
	for _, commandID := range group.CommandIDs {
		policy, ok := policiesByCommandID[commandID]
		if !ok || policy.SideEffectClass != "none" || len(policy.ExclusiveLocks) > 0 || len(policy.ResourceReads) > 0 || len(policy.ResourceWrites) > 0 {
			return false
		}
	}
	return true
}

func policyPairFailures(parallelGroup string, left policy, right policy) []string {
	failures := []string{}
	if left.SideEffectClass == "destructive" || right.SideEffectClass == "destructive" {
		failures = append(failures, "parallel group "+parallelGroup+" must not run destructive commands concurrently")
	}
	for _, lock := range intersection(left.ExclusiveLocks, right.ExclusiveLocks) {
		failures = append(failures, "parallel group "+parallelGroup+" has exclusive lock collision "+lock)
	}
	for _, resource := range intersection(left.ResourceWrites, right.ResourceWrites) {
		failures = append(failures, "parallel group "+parallelGroup+" has write/write resource collision "+resource)
	}
	for _, resource := range intersection(left.ResourceWrites, right.ResourceReads) {
		failures = append(failures, "parallel group "+parallelGroup+" has write/read resource collision "+resource)
	}
	for _, resource := range intersection(right.ResourceWrites, left.ResourceReads) {
		failures = append(failures, "parallel group "+parallelGroup+" has read/write resource collision "+resource)
	}
	return failures
}

func ruleResults(failures []string) []report.RuleResult {
	return []report.RuleResult{
		{
			RuleID:      "proofkit.witness-scheduler-plan.boundary",
			Status:      "passed",
			Message:     "proofkit validates caller-provided scheduler metadata without executing commands",
			Diagnostics: []report.Diagnostic{},
		},
		{
			RuleID:      "proofkit.witness-scheduler-plan.safety",
			Status:      statusFailedIf(len(failures) > 0),
			Message:     "witness scheduler metadata must declare safe cache, retry, cancellation, lock, resource, and timeout policy",
			Diagnostics: failureDiagnostics(failures),
		},
	}
}

func executionGroupDiagnostics(groups []executionGroup) []any {
	result := make([]any, 0, len(groups))
	for _, group := range groups {
		result = append(result, map[string]any{
			"commandIds":        admit.StringSliceToAny(group.CommandIDs),
			"exclusiveLocks":    admit.StringSliceToAny(group.ExclusiveLocks),
			"parallelGroup":     group.ParallelGroup,
			"sideEffectClasses": admit.StringSliceToAny(group.SideEffectClasses),
		})
	}
	return result
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	diagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		diagnostics = append(diagnostics, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: failure})
	}
	return diagnostics
}

func arrayOfRecords(raw any, context string) ([]map[string]any, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]map[string]any, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		result = append(result, record)
	}
	return result, nil
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, admit.RuleID)
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, pathField)
}

func sortedSelectors(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, selectorText)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	return sortedMapped(raw, context, allowEmpty, text)
}

func sortedMapped(raw any, context string, allowEmpty bool, mapper func(any, string) (string, error)) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		item, err := mapper(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return preserveSortedUniqueReturn(result, context, allowEmpty)
}

func preserveSortedUniqueReturn(values []string, context string, allowEmpty bool) ([]string, error) {
	if err := preserveSortedUnique(values, context, allowEmpty); err != nil {
		return nil, err
	}
	return values, nil
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return fmt.Errorf("%s must be non-empty", context)
	}
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	seen := map[string]struct{}{}
	for index, value := range values {
		if value != sorted[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func selectorText(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	if len(value) > 0 && (value[0] == '/' || containsStringPart(value, "..")) {
		return "", fmt.Errorf("%s must not escape the repository", context)
	}
	for _, char := range value {
		if char == '\\' {
			return "", fmt.Errorf("%s must not escape the repository", context)
		}
	}
	return value, nil
}

func pathField(raw any, context string) (string, error) {
	value, err := text(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func boolField(raw any, context string) (bool, error) {
	value, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be boolean", context)
	}
	return value, nil
}

func positiveInteger(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	value, err := number.Int64()
	if err != nil || value <= 0 || int64(int(value)) != value {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	return int(value), nil
}

func enum(raw any, values map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	return value, nil
}

func cacheableCommandCount(commands []witnesscommand.Command) int {
	count := 0
	for _, command := range commands {
		if command.CachePolicy != "disabled" {
			count++
		}
	}
	return count
}

func countDestructive(policies []policy) int {
	count := 0
	for _, policy := range policies {
		if policy.SideEffectClass == "destructive" {
			count++
		}
	}
	return count
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := []string{}
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func flattenPolicyStrings(policies []policy, mapper func(policy) []string) []string {
	result := []string{}
	for _, policy := range policies {
		result = append(result, mapper(policy)...)
	}
	return result
}

func intersection(left []string, right []string) []string {
	rightSet := map[string]struct{}{}
	for _, value := range right {
		rightSet[value] = struct{}{}
	}
	result := []string{}
	for _, value := range left {
		if _, ok := rightSet[value]; ok {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsStringPart(value string, target string) bool {
	start := 0
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == '/' {
			if value[start:index] == target {
				return true
			}
			start = index + 1
		}
	}
	return false
}

func statusFailedIf(value bool) string {
	if value {
		return "failed"
	}
	return "passed"
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func join(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += ", " + value
	}
	return result
}
