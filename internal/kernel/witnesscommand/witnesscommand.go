package witnesscommand

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var networkPolicies = []string{"external", "loopback", "none"}
var networkPolicySet = toSet(networkPolicies)

var cachePolicies = []string{"disabled", "read-only", "write-local"}
var cachePolicySet = toSet(cachePolicies)

var inheritanceModes = []string{"allowlist", "none"}
var inheritanceModeSet = toSet(inheritanceModes)

var exitCodePolicyKinds = []string{"listed", "zero"}
var exitCodePolicyKindSet = toSet(exitCodePolicyKinds)

var shellExecutables = map[string]struct{}{
	"ash":        {},
	"bash":       {},
	"busybox":    {},
	"command":    {},
	"csh":        {},
	"cmd":        {},
	"dash":       {},
	"fish":       {},
	"ksh":        {},
	"mksh":       {},
	"powershell": {},
	"pwsh":       {},
	"sh":         {},
	"tcsh":       {},
	"zsh":        {},
}

var commandDispatchExecutables = map[string]struct{}{
	"env": {},
}

type Vocabulary struct {
	ArtifactKinds                 []string
	CredentialClasses             []string
	EnvironmentClasses            []string
	EnvironmentClassPolicies      []EnvironmentClassPolicy
	MaxTimeoutMs                  int
	NonCacheableCredentialClasses []string
	ParallelGroups                []string
}

type EnvironmentClassPolicy struct {
	CachePolicies     []string
	CredentialClasses []string
	EnvironmentClass  string
	NetworkPolicies   []string
}

type EnvironmentPolicy struct {
	Allowlist []string
	Classes   []string
	Inherit   string
}

type ExpectedArtifact struct {
	Kind     string
	Path     string
	Required bool
}

type ExitCodePolicy struct {
	Kind         string
	SuccessCodes []int
}

type Command struct {
	Argv              []string
	CachePolicy       string
	CredentialClass   string
	Cwd               string
	Environment       EnvironmentPolicy
	ExitCodePolicy    ExitCodePolicy
	ExpectedArtifacts []ExpectedArtifact
	ID                string
	NetworkPolicy     string
	ParallelGroup     string
	TimeoutMs         int
}

type PlanGroup struct {
	CommandIDs    []string
	ParallelGroup string
}

type Plan struct {
	Commands       []Command
	ParallelGroups []PlanGroup
}

func (command Command) JSONValue() map[string]any {
	expectedArtifacts := make([]any, 0, len(command.ExpectedArtifacts))
	for _, artifact := range command.ExpectedArtifacts {
		expectedArtifacts = append(expectedArtifacts, map[string]any{
			"kind":     artifact.Kind,
			"path":     artifact.Path,
			"required": artifact.Required,
		})
	}
	return map[string]any{
		"argv":            stringSliceToAny(command.Argv),
		"cachePolicy":     command.CachePolicy,
		"credentialClass": command.CredentialClass,
		"cwd":             command.Cwd,
		"environment": map[string]any{
			"allowlist": stringSliceToAny(command.Environment.Allowlist),
			"classes":   stringSliceToAny(command.Environment.Classes),
			"inherit":   command.Environment.Inherit,
		},
		"exitCodePolicy": map[string]any{
			"kind":         command.ExitCodePolicy.Kind,
			"successCodes": intSliceToAny(command.ExitCodePolicy.SuccessCodes),
		},
		"expectedArtifacts": expectedArtifacts,
		"id":                command.ID,
		"networkPolicy":     command.NetworkPolicy,
		"parallelGroup":     command.ParallelGroup,
		"schemaVersion":     1,
		"timeoutMs":         command.TimeoutMs,
	}
}

func (plan Plan) JSONValue() map[string]any {
	commands := make([]any, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		commands = append(commands, command.JSONValue())
	}
	parallelGroups := make([]any, 0, len(plan.ParallelGroups))
	for _, group := range plan.ParallelGroups {
		parallelGroups = append(parallelGroups, map[string]any{
			"commandIds":    stringSliceToAny(group.CommandIDs),
			"parallelGroup": group.ParallelGroup,
		})
	}
	return map[string]any{
		"commands":       commands,
		"parallelGroups": parallelGroups,
	}
}

func Admit(raw any, rawVocabulary any) (Command, error) {
	vocabulary, err := AdmitVocabulary(rawVocabulary)
	if err != nil {
		return Command{}, err
	}
	return AdmitWithVocabulary(raw, vocabulary)
}

func AdmitWithVocabulary(raw any, vocabulary Vocabulary) (Command, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Command{}, fmt.Errorf("witness command must be an object")
	}
	if err := admit.KnownKeys(record, []string{"argv", "cachePolicy", "credentialClass", "cwd", "environment", "exitCodePolicy", "expectedArtifacts", "id", "networkPolicy", "parallelGroup", "schemaVersion", "timeoutMs"}, "witness command"); err != nil {
		return Command{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Command{}, fmt.Errorf("witness command schemaVersion must be 1")
	}
	id, err := witnessID(record["id"])
	if err != nil {
		return Command{}, err
	}
	cwd, err := witnessCwd(record["cwd"])
	if err != nil {
		return Command{}, err
	}
	argv, err := witnessArgv(record["argv"])
	if err != nil {
		return Command{}, err
	}
	environment, err := witnessEnvironment(record["environment"], vocabulary)
	if err != nil {
		return Command{}, err
	}
	timeoutMs, err := witnessTimeout(record["timeoutMs"], vocabulary.MaxTimeoutMs)
	if err != nil {
		return Command{}, err
	}
	networkPolicy, err := enum(record["networkPolicy"], networkPolicySet, networkPolicies, "witness networkPolicy")
	if err != nil {
		return Command{}, err
	}
	credentialClass, err := vocabularyValue(record["credentialClass"], vocabulary.CredentialClasses, "witness credentialClass")
	if err != nil {
		return Command{}, err
	}
	cachePolicy, err := enum(record["cachePolicy"], cachePolicySet, cachePolicies, "witness cachePolicy")
	if err != nil {
		return Command{}, err
	}
	expectedArtifacts, err := witnessExpectedArtifacts(record["expectedArtifacts"], vocabulary)
	if err != nil {
		return Command{}, err
	}
	parallelGroup, err := vocabularyValue(record["parallelGroup"], vocabulary.ParallelGroups, "witness parallelGroup")
	if err != nil {
		return Command{}, err
	}
	exitCodePolicy, err := witnessExitCodePolicy(record["exitCodePolicy"])
	if err != nil {
		return Command{}, err
	}
	command := Command{
		Argv:              argv,
		CachePolicy:       cachePolicy,
		CredentialClass:   credentialClass,
		Cwd:               cwd,
		Environment:       environment,
		ExitCodePolicy:    exitCodePolicy,
		ExpectedArtifacts: expectedArtifacts,
		ID:                id,
		NetworkPolicy:     networkPolicy,
		ParallelGroup:     parallelGroup,
		TimeoutMs:         timeoutMs,
	}
	if err := assertEnvironmentClassPolicies(command, vocabulary.EnvironmentClassPolicies); err != nil {
		return Command{}, err
	}
	if contains(vocabulary.NonCacheableCredentialClasses, command.CredentialClass) && command.CachePolicy != "disabled" {
		return Command{}, fmt.Errorf("witness command with non-cacheable credentials must disable cache")
	}
	return command, nil
}

func AdmitVocabulary(raw any) (Vocabulary, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Vocabulary{}, fmt.Errorf("witness vocabulary must be an object")
	}
	if err := admit.KnownKeys(record, []string{"artifactKinds", "credentialClasses", "environmentClasses", "environmentClassPolicies", "maxTimeoutMs", "nonCacheableCredentialClasses", "parallelGroups"}, "witness vocabulary"); err != nil {
		return Vocabulary{}, err
	}
	credentialClasses, err := sortedUniqueStringArray(record["credentialClasses"], "witness vocabulary credentialClasses", true)
	if err != nil {
		return Vocabulary{}, err
	}
	environmentClasses, err := sortedUniqueStringArray(record["environmentClasses"], "witness vocabulary environmentClasses", true)
	if err != nil {
		return Vocabulary{}, err
	}
	artifactKinds, err := sortedUniqueStringArray(record["artifactKinds"], "witness vocabulary artifactKinds", true)
	if err != nil {
		return Vocabulary{}, err
	}
	environmentClassPolicies, err := environmentClassPolicies(record["environmentClassPolicies"], environmentClasses, credentialClasses)
	if err != nil {
		return Vocabulary{}, err
	}
	parallelGroups, err := sortedUniqueStringArray(optionalArray(record["parallelGroups"]), "witness vocabulary parallelGroups", true)
	if err != nil {
		return Vocabulary{}, err
	}
	nonCacheable, err := sortedUniqueStringArray(optionalArray(record["nonCacheableCredentialClasses"]), "witness vocabulary nonCacheableCredentialClasses", true)
	if err != nil {
		return Vocabulary{}, err
	}
	if err := subset(nonCacheable, credentialClasses, "witness vocabulary nonCacheableCredentialClasses"); err != nil {
		return Vocabulary{}, err
	}
	maxTimeoutMs, err := maxTimeout(record["maxTimeoutMs"])
	if err != nil {
		return Vocabulary{}, err
	}
	return Vocabulary{
		ArtifactKinds:                 artifactKinds,
		CredentialClasses:             credentialClasses,
		EnvironmentClasses:            environmentClasses,
		EnvironmentClassPolicies:      environmentClassPolicies,
		MaxTimeoutMs:                  maxTimeoutMs,
		NonCacheableCredentialClasses: nonCacheable,
		ParallelGroups:                parallelGroups,
	}, nil
}

func PlanCommands(commands []Command) (Plan, error) {
	ids := make([]string, 0, len(commands))
	for _, command := range commands {
		ids = append(ids, command.ID)
	}
	sort.Strings(ids)
	if err := assertSortedUnique(ids, "witness command ids"); err != nil {
		return Plan{}, err
	}
	sortedCommands := append([]Command{}, commands...)
	sort.Slice(sortedCommands, func(left int, right int) bool {
		return sortedCommands[left].ID < sortedCommands[right].ID
	})
	byGroup := map[string][]string{}
	for _, command := range sortedCommands {
		byGroup[command.ParallelGroup] = append(byGroup[command.ParallelGroup], command.ID)
	}
	groupIDs := make([]string, 0, len(byGroup))
	for group := range byGroup {
		groupIDs = append(groupIDs, group)
	}
	sort.Strings(groupIDs)
	groups := make([]PlanGroup, 0, len(groupIDs))
	for _, group := range groupIDs {
		commandIDs := append([]string{}, byGroup[group]...)
		sort.Strings(commandIDs)
		groups = append(groups, PlanGroup{ParallelGroup: group, CommandIDs: commandIDs})
	}
	return Plan{Commands: sortedCommands, ParallelGroups: groups}, nil
}

func environmentClassPolicies(raw any, environmentClasses []string, credentialClasses []string) ([]EnvironmentClassPolicy, error) {
	if raw == nil {
		return []EnvironmentClassPolicy{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("witness vocabulary environmentClassPolicies must be an array")
	}
	policies := make([]EnvironmentClassPolicy, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("witness vocabulary environmentClassPolicies[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"cachePolicies", "credentialClasses", "environmentClass", "networkPolicies"}, fmt.Sprintf("witness vocabulary environmentClassPolicies[%d]", index)); err != nil {
			return nil, err
		}
		environmentClass, err := vocabularyValue(record["environmentClass"], environmentClasses, fmt.Sprintf("witness vocabulary environmentClassPolicies[%d].environmentClass", index))
		if err != nil {
			return nil, err
		}
		networkPolicies, err := enumArray(record["networkPolicies"], networkPolicySet, networkPolicies, fmt.Sprintf("witness vocabulary environmentClassPolicies[%d].networkPolicies", index))
		if err != nil {
			return nil, err
		}
		policyCredentialClasses, err := sortedUniqueStringArray(record["credentialClasses"], fmt.Sprintf("witness vocabulary environmentClassPolicies[%d].credentialClasses", index), true)
		if err != nil {
			return nil, err
		}
		if err := subset(policyCredentialClasses, credentialClasses, fmt.Sprintf("witness vocabulary environmentClassPolicies[%d].credentialClasses", index)); err != nil {
			return nil, err
		}
		policyCachePolicies, err := enumArray(record["cachePolicies"], cachePolicySet, cachePolicies, fmt.Sprintf("witness vocabulary environmentClassPolicies[%d].cachePolicies", index))
		if err != nil {
			return nil, err
		}
		policies = append(policies, EnvironmentClassPolicy{
			CachePolicies:     policyCachePolicies,
			CredentialClasses: policyCredentialClasses,
			EnvironmentClass:  environmentClass,
			NetworkPolicies:   networkPolicies,
		})
	}
	sort.Slice(policies, func(left int, right int) bool {
		return policies[left].EnvironmentClass < policies[right].EnvironmentClass
	})
	classes := make([]string, 0, len(policies))
	for _, policy := range policies {
		classes = append(classes, policy.EnvironmentClass)
	}
	return policies, assertSortedUnique(classes, "witness vocabulary environmentClassPolicies.environmentClass")
}

func assertEnvironmentClassPolicies(command Command, policies []EnvironmentClassPolicy) error {
	byClass := map[string]EnvironmentClassPolicy{}
	for _, policy := range policies {
		byClass[policy.EnvironmentClass] = policy
	}
	for _, environmentClass := range command.Environment.Classes {
		policy, ok := byClass[environmentClass]
		if !ok {
			return fmt.Errorf("witness environment class %s must declare an environmentClassPolicy", environmentClass)
		}
		if !contains(policy.NetworkPolicies, command.NetworkPolicy) {
			return fmt.Errorf("witness environment class %s does not admit networkPolicy", environmentClass)
		}
		if !contains(policy.CredentialClasses, command.CredentialClass) {
			return fmt.Errorf("witness environment class %s does not admit credentialClass", environmentClass)
		}
		if !contains(policy.CachePolicies, command.CachePolicy) {
			return fmt.Errorf("witness environment class %s does not admit cachePolicy", environmentClass)
		}
	}
	return nil
}

func witnessEnvironment(raw any, vocabulary Vocabulary) (EnvironmentPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return EnvironmentPolicy{}, fmt.Errorf("witness environment must be an object")
	}
	if err := admit.KnownKeys(record, []string{"allowlist", "classes", "inherit"}, "witness environment"); err != nil {
		return EnvironmentPolicy{}, err
	}
	inherit, err := enum(record["inherit"], inheritanceModeSet, inheritanceModes, "witness environment inherit")
	if err != nil {
		return EnvironmentPolicy{}, err
	}
	allowlist, err := sortedUniqueStringArray(record["allowlist"], "witness environment allowlist", true)
	if err != nil {
		return EnvironmentPolicy{}, err
	}
	classes, err := sortedUniqueStringArray(record["classes"], "witness environment classes", false)
	if err != nil {
		return EnvironmentPolicy{}, err
	}
	if err := subset(classes, vocabulary.EnvironmentClasses, "witness environment classes"); err != nil {
		return EnvironmentPolicy{}, err
	}
	if inherit == "none" && len(allowlist) > 0 {
		return EnvironmentPolicy{}, fmt.Errorf("witness environment with inherit=none must declare an empty allowlist")
	}
	if inherit == "allowlist" && len(allowlist) == 0 {
		return EnvironmentPolicy{}, fmt.Errorf("witness environment with inherit=allowlist must declare allowed variables")
	}
	for _, name := range allowlist {
		if !validEnvName(name) {
			return EnvironmentPolicy{}, fmt.Errorf("witness environment allowlist must contain environment variable names")
		}
	}
	return EnvironmentPolicy{Allowlist: allowlist, Classes: classes, Inherit: inherit}, nil
}

func witnessExpectedArtifacts(raw any, vocabulary Vocabulary) ([]ExpectedArtifact, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("witness expectedArtifacts must be an array")
	}
	artifacts := make([]ExpectedArtifact, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("witness expectedArtifacts[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"kind", "path", "required"}, fmt.Sprintf("witness expectedArtifacts[%d]", index)); err != nil {
			return nil, err
		}
		pathValue, err := pathField(record["path"], fmt.Sprintf("witness expectedArtifacts[%d].path", index))
		if err != nil {
			return nil, err
		}
		kind, err := vocabularyValue(record["kind"], vocabulary.ArtifactKinds, fmt.Sprintf("witness expectedArtifacts[%d].kind", index))
		if err != nil {
			return nil, err
		}
		required, err := boolField(record["required"], fmt.Sprintf("witness expectedArtifacts[%d].required", index))
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, ExpectedArtifact{Kind: kind, Path: pathValue, Required: required})
	}
	sort.Slice(artifacts, func(left int, right int) bool {
		leftKey := artifacts[left].Path + "\x00" + artifacts[left].Kind
		rightKey := artifacts[right].Path + "\x00" + artifacts[right].Kind
		return leftKey < rightKey
	})
	keys := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		keys = append(keys, artifact.Path+"\x00"+artifact.Kind)
	}
	return artifacts, assertSortedUnique(keys, "witness expectedArtifacts")
}

func witnessExitCodePolicy(raw any) (ExitCodePolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return ExitCodePolicy{}, fmt.Errorf("witness exitCodePolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"kind", "successCodes"}, "witness exitCodePolicy"); err != nil {
		return ExitCodePolicy{}, err
	}
	kind, err := enum(record["kind"], exitCodePolicyKindSet, exitCodePolicyKinds, "witness exitCodePolicy kind")
	if err != nil {
		return ExitCodePolicy{}, err
	}
	successCodes, err := successExitCodes(record["successCodes"], "witness exitCodePolicy successCodes")
	if err != nil {
		return ExitCodePolicy{}, err
	}
	if kind == "zero" && (len(successCodes) != 1 || successCodes[0] != 0) {
		return ExitCodePolicy{}, fmt.Errorf("witness exitCodePolicy zero must declare successCodes [0]")
	}
	return ExitCodePolicy{Kind: kind, SuccessCodes: successCodes}, nil
}

func successExitCodes(raw any, context string) ([]int, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty integer exit codes between 0 and 255", context)
	}
	result := make([]int, 0, len(values))
	for _, value := range values {
		number, ok := value.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%s must be non-empty integer exit codes between 0 and 255", context)
		}
		intValue, err := number.Int64()
		if err != nil || intValue < 0 || intValue > 255 || int64(int(intValue)) != intValue {
			return nil, fmt.Errorf("%s must be non-empty integer exit codes between 0 and 255", context)
		}
		result = append(result, int(intValue))
	}
	sorted := append([]int{}, result...)
	sort.Ints(sorted)
	seen := map[int]struct{}{}
	for index, value := range result {
		if value != sorted[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
		if _, ok := seen[value]; ok {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
		seen[value] = struct{}{}
	}
	return result, nil
}

func witnessID(raw any) (string, error) {
	value, err := stringField(raw, "witness command id")
	if err != nil {
		return "", err
	}
	if admit.ContainsSecretLikeValue(value) {
		return "", fmt.Errorf("witness command id must not contain secret-like values")
	}
	if !validWitnessID(value) {
		return "", fmt.Errorf("witness command id must be lowercase stable identifier text")
	}
	return value, nil
}

func witnessCwd(raw any) (string, error) {
	value, err := stringField(raw, "witness command cwd")
	if err != nil {
		return "", err
	}
	if value == "." {
		return value, nil
	}
	return admit.SafeRepoRelativePath(value, "witness cwd")
}

func witnessArgv(raw any) ([]string, error) {
	argv, err := orderedStringTuple(raw, "witness argv")
	if err != nil {
		return nil, err
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("witness argv must be non-empty")
	}
	executable := normalizedExecutableName(argv[0])
	if _, ok := shellExecutables[executable]; ok {
		return nil, fmt.Errorf("witness argv must not use shell executables")
	}
	if _, ok := commandDispatchExecutables[executable]; ok {
		return nil, fmt.Errorf("witness argv must not use command dispatch wrappers")
	}
	return argv, nil
}

func normalizedExecutableName(value string) string {
	normalized := strings.ReplaceAll(value, `\`, "/")
	executable := strings.ToLower(path.Base(normalized))
	for _, suffix := range []string{".exe", ".cmd", ".bat", ".com"} {
		executable = strings.TrimSuffix(executable, suffix)
	}
	return executable
}

func witnessTimeout(raw any, maxTimeoutMs int) (int, error) {
	value, err := positiveInteger(raw, "witness timeoutMs")
	if err != nil || value > maxTimeoutMs {
		return 0, fmt.Errorf("witness timeoutMs must be an integer between 1 and %d", maxTimeoutMs)
	}
	return value, nil
}

func maxTimeout(raw any) (int, error) {
	if raw == nil {
		return 3600000, nil
	}
	value, err := positiveInteger(raw, "witness vocabulary maxTimeoutMs")
	if err != nil {
		return 0, fmt.Errorf("witness vocabulary maxTimeoutMs must be a positive integer")
	}
	return value, nil
}

func optionalArray(raw any) any {
	if raw == nil {
		return []any{}
	}
	return raw
}

func enumArray(raw any, set map[string]struct{}, ordered []string, context string) ([]string, error) {
	values, err := sortedUniqueStringArray(raw, context, true)
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		if _, ok := set[value]; !ok {
			return nil, fmt.Errorf("%s must be one of: %s", context, join(ordered))
		}
	}
	return values, nil
}

func sortedUniqueStringArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" || strings.ContainsRune(text, '\x00') || admit.ContainsSecretLikeValue(text) {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		result = append(result, text)
	}
	if !allowEmpty && len(result) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	return result, assertSortedUnique(result, context)
}

func orderedStringTuple(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" || strings.ContainsRune(text, '\x00') || admit.ContainsSecretLikeValue(text) {
			return nil, fmt.Errorf("%s must be a string array", context)
		}
		result = append(result, text)
	}
	return result, nil
}

func subset(values []string, admitted []string, context string) error {
	admittedSet := map[string]struct{}{}
	for _, value := range admitted {
		admittedSet[value] = struct{}{}
	}
	unknown := []string{}
	for _, value := range values {
		if _, ok := admittedSet[value]; !ok {
			unknown = append(unknown, value)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%s contains unsupported value(s): %s", context, join(unknown))
	}
	return nil
}

func enum(raw any, set map[string]struct{}, ordered []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	if _, ok := set[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, join(ordered))
	}
	return value, nil
}

func vocabularyValue(raw any, admitted []string, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || value == "" || !contains(admitted, value) {
		return "", fmt.Errorf("%s must be an admitted value", context)
	}
	return value, nil
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

func pathField(raw any, context string) (string, error) {
	value, err := stringField(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func stringField(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s must be non-empty text", context)
	}
	return value, nil
}

func assertSortedUnique(values []string, context string) error {
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validEnvName(value string) bool {
	if value == "" {
		return false
	}
	first := value[0]
	if !(first == '_' || (first >= 'A' && first <= 'Z')) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !(character == '_' || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func validWitnessID(value string) bool {
	if value == "" {
		return false
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
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

func stringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func intSliceToAny(values []int) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
