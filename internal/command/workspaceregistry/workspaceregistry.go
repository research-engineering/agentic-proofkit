package workspaceregistry

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var registryNonClaims = []string{
	"Workspace registry admission does not execute scripts or native witnesses.",
	"Workspace registry admission does not generate, refresh, or authenticate lockfiles.",
	"Workspace registry admission does not infer required script policy, namespace policy, package-manager semantics, CI policy, or merge approval.",
	"Workspace registry admission reads only caller-provided facts and does not prove repository freshness.",
}

type dependencyRef struct {
	Field   string
	Name    string
	Version string
}

type scriptEntry struct {
	Command string
	Name    string
}

type scriptExpectation struct {
	Command *string
	Name    string
}

type rootFacts struct {
	DependencyRefs []dependencyRef
	Name           *string
	Scripts        []scriptEntry
}

type packageFacts struct {
	DependencyRefs []dependencyRef
	DirName        string
	Name           string
	Scripts        []scriptEntry
}

type scriptPolicy struct {
	AdmittedRootScriptNames []string
	ExactRootScripts        []scriptExpectation
	RequiredPackageScripts  []string
	RequiredRootScriptNames []string
	SelfTargetOptionNames   []string
	TargetNamePrefixes      []string
	TargetOptionNames       []string
}

type dependencyPolicy struct {
	InternalDependencyLabel *string
	InternalNamePrefixes    []string
	WorkspaceVersion        string
}

type expectedSnippet struct {
	FailureMessage string
	Snippet        string
}

type lockfilePolicy struct {
	ExpectedSnippets []expectedSnippet
	LockfileText     string
}

type registryInput struct {
	DependencyPolicy *dependencyPolicy
	KnownPackageName []string
	LockfilePolicy   *lockfilePolicy
	NonClaims        []string
	Packages         []packageFacts
	Root             rootFacts
	ScriptPolicy     scriptPolicy
}

type workspaceAdmissionReport struct {
	CheckedItemCount int
	Failures         []string
}

type scriptScope struct {
	OwnerLabel      string
	Scripts         []scriptEntry
	SelfPackageName *string
}

type dependencyOwner struct {
	OwnerLabel string
	Refs       []dependencyRef
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	record := buildReport(input)
	return record, exitCode(record), nil
}

func buildReport(input registryInput) report.Record {
	rulesInFailureOrder := []report.RuleResult{
		knownPackageFactsRule(input.KnownPackageName, input.Packages),
		rootScriptPolicyRule(input.Root.Scripts, input.ScriptPolicy),
		packageScriptPolicyRule(input.Packages, input.ScriptPolicy),
		scriptTargetsRule(input.KnownPackageName, input.Root.Scripts, input.Packages, input.ScriptPolicy),
		dependencyPolicyRule(input.KnownPackageName, input.Root.DependencyRefs, input.Packages, input.DependencyPolicy),
		lockfilePolicyRule(input.Root.Name, input.Packages, input.LockfilePolicy),
	}
	failures := aggregateFailures(rulesInFailureOrder)
	rules := append([]report.RuleResult{}, rulesInFailureOrder...)
	sort.Slice(rules, func(left int, right int) bool {
		return jsLocaleLess(rules[left].RuleID, rules[right].RuleID)
	})
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	nonClaims := append(append([]any{}, stringsToAny(registryNonClaims)...), stringsToAny(input.NonClaims)...)
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.workspace-registry",
		ReportID:      "proofkit.workspace-registry",
		State:         state,
		Summary: map[string]any{
			"checkedItemCount":        checkedItemCount(rulesInFailureOrder),
			"dependencyPolicyEnabled": input.DependencyPolicy != nil,
			"failureCount":            len(failures),
			"lockfilePolicyEnabled":   input.LockfilePolicy != nil,
			"packageCount":            len(input.Packages),
			"packageScriptCount":      packageScriptCount(input.Packages),
			"rootScriptCount":         len(input.Root.Scripts),
		},
		Diagnostics: failureDiagnostics(failures),
		RuleResults: rules,
		NonClaims:   nonClaims,
	}
}

func exitCode(record report.Record) int {
	if record.State == "passed" {
		return 0
	}
	return 1
}

func knownPackageFactsRule(knownPackageNames []string, packages []packageFacts) report.RuleResult {
	packageNames := make([]string, 0, len(packages))
	for _, item := range packages {
		packageNames = append(packageNames, item.Name)
	}
	failures := []string{}
	for _, name := range knownPackageNames {
		if !contains(packageNames, name) {
			failures = append(failures, fmt.Sprintf("known package missing package facts: %s", name))
		}
	}
	for _, name := range packageNames {
		if !contains(knownPackageNames, name) {
			failures = append(failures, fmt.Sprintf("package facts include unknown package: %s", name))
		}
	}
	dirNames := make([]string, 0, len(packages))
	for _, item := range packages {
		dirNames = append(dirNames, item.DirName)
	}
	sort.Strings(dirNames)
	if duplicate := firstDuplicate(dirNames); duplicate != nil {
		failures = append(failures, fmt.Sprintf("workspace package dirName must be unique: %s", *duplicate))
	}
	return reportRule("proofkit.workspace-registry.known-package-facts", failures, map[string]any{
		"checkedItemCount":  knownPackageNamesLength(knownPackageNames, packageNames),
		"knownPackageCount": len(knownPackageNames),
		"packageFactCount":  len(packageNames),
	}, "")
}

func rootScriptPolicyRule(rootScripts []scriptEntry, policy scriptPolicy) report.RuleResult {
	scriptsByName := scriptMap(rootScripts, "root")
	failures := []string{}
	if policy.AdmittedRootScriptNames != nil {
		admitted := toSet(policy.AdmittedRootScriptNames)
		for _, script := range rootScripts {
			if _, ok := admitted[script.Name]; !ok {
				failures = append(failures, fmt.Sprintf("root package.json has unexpected script %s", script.Name))
			}
		}
	}
	for _, name := range policy.RequiredRootScriptNames {
		if _, ok := scriptsByName[name]; !ok {
			failures = append(failures, fmt.Sprintf("root package.json missing required script %s", name))
		}
	}
	for _, expected := range policy.ExactRootScripts {
		actual, ok := scriptsByName[expected.Name]
		if !ok {
			failures = append(failures, fmt.Sprintf("root package.json missing exact script %s", expected.Name))
			continue
		}
		if expected.Command != nil && actual.Command != *expected.Command {
			failures = append(failures, fmt.Sprintf("root package.json script %s command drifted", expected.Name))
		}
	}
	return reportRule("proofkit.workspace-registry.root-scripts", failures, map[string]any{
		"checkedItemCount": len(rootScripts) + len(policy.RequiredRootScriptNames) + len(policy.ExactRootScripts),
		"rootScriptCount":  len(rootScripts),
	}, "")
}

func packageScriptPolicyRule(packages []packageFacts, policy scriptPolicy) report.RuleResult {
	failures := []string{}
	for _, item := range packages {
		scriptsByName := scriptMap(item.Scripts, item.Name)
		for _, scriptName := range policy.RequiredPackageScripts {
			if _, ok := scriptsByName[scriptName]; !ok {
				failures = append(failures, fmt.Sprintf("%s missing required script %s", item.Name, scriptName))
			}
		}
	}
	return reportRule("proofkit.workspace-registry.package-scripts", failures, map[string]any{
		"checkedItemCount":           len(packages) * len(policy.RequiredPackageScripts),
		"packageCount":               len(packages),
		"requiredPackageScriptCount": len(policy.RequiredPackageScripts),
	}, "")
}

func scriptTargetsRule(knownPackageNames []string, rootScripts []scriptEntry, packages []packageFacts, policy scriptPolicy) report.RuleResult {
	scopes := []scriptScope{{OwnerLabel: "root package.json", Scripts: rootScripts}}
	for _, item := range packages {
		name := item.Name
		scopes = append(scopes, scriptScope{OwnerLabel: item.Name, Scripts: item.Scripts, SelfPackageName: &name})
	}
	result := scriptTargetAdmission(workspaceScriptTargetInput{
		KnownPackageNames:     knownPackageNames,
		Scopes:                scopes,
		SelfTargetOptionNames: policy.SelfTargetOptionNames,
		TargetNamePrefixes:    policy.TargetNamePrefixes,
		TargetOptionNames:     policy.TargetOptionNames,
	})
	return reportRule("proofkit.workspace-registry.script-targets", result.Failures, map[string]any{
		"checkedItemCount": result.CheckedItemCount,
		"scopeCount":       len(scopes),
	}, "")
}

func dependencyPolicyRule(knownPackageNames []string, rootDependencyRefs []dependencyRef, packages []packageFacts, policy *dependencyPolicy) report.RuleResult {
	if policy == nil {
		return reportRule("proofkit.workspace-registry.dependencies", []string{}, map[string]any{
			"checkedItemCount":        0,
			"dependencyPolicyEnabled": false,
		}, "skipped")
	}
	owners := []dependencyOwner{{OwnerLabel: "root package.json", Refs: rootDependencyRefs}}
	for _, item := range packages {
		owners = append(owners, dependencyOwner{OwnerLabel: item.Name, Refs: item.DependencyRefs})
	}
	result := dependencyAdmission(workspaceDependencyInput{
		InternalDependencyLabel: policy.InternalDependencyLabel,
		InternalNamePrefixes:    policy.InternalNamePrefixes,
		KnownPackageNames:       knownPackageNames,
		Owners:                  owners,
		WorkspaceVersion:        policy.WorkspaceVersion,
	})
	return reportRule("proofkit.workspace-registry.dependencies", result.Failures, map[string]any{
		"checkedItemCount":        result.CheckedItemCount,
		"dependencyPolicyEnabled": true,
	}, "")
}

func lockfilePolicyRule(rootName *string, packages []packageFacts, policy *lockfilePolicy) report.RuleResult {
	if policy == nil {
		return reportRule("proofkit.workspace-registry.bun-lockfile", []string{}, map[string]any{
			"checkedItemCount":      0,
			"lockfilePolicyEnabled": false,
		}, "skipped")
	}
	result := bunLockfileAdmission(workspaceLockfileInput{
		ExpectedSnippets: policy.ExpectedSnippets,
		LockfileText:     policy.LockfileText,
		Packages:         packageRefs(packages),
		RootName:         rootName,
	})
	return reportRule("proofkit.workspace-registry.bun-lockfile", result.Failures, map[string]any{
		"checkedItemCount":      result.CheckedItemCount,
		"lockfilePolicyEnabled": true,
	}, "")
}

type workspaceScriptTargetInput struct {
	KnownPackageNames     []string
	Scopes                []scriptScope
	SelfTargetOptionNames []string
	TargetNamePrefixes    []string
	TargetOptionNames     []string
}

func scriptTargetAdmission(input workspaceScriptTargetInput) workspaceAdmissionReport {
	knownPackageNames := toSet(input.KnownPackageNames)
	selfTargetOptionLabel := strings.Join(input.SelfTargetOptionNames, "|")
	if selfTargetOptionLabel == "" {
		selfTargetOptionLabel = "self target"
	}
	failures := []string{}
	checkedItemCount := 0
	for _, scope := range input.Scopes {
		if scope.SelfPackageName != nil {
			if _, ok := knownPackageNames[*scope.SelfPackageName]; !ok {
				failures = append(failures, fmt.Sprintf("%s self package is not in known package names: %s", scope.OwnerLabel, *scope.SelfPackageName))
			}
		}
		for _, script := range scope.Scripts {
			checkedItemCount++
			for _, target := range internalOptionTargets(script.Command, input.SelfTargetOptionNames, input.TargetNamePrefixes) {
				if scope.SelfPackageName != nil && target != *scope.SelfPackageName {
					failures = append(failures, fmt.Sprintf("%s script %s %s must target itself, not %s", scope.OwnerLabel, script.Name, selfTargetOptionLabel, target))
				}
				if scope.SelfPackageName == nil {
					if _, ok := knownPackageNames[target]; !ok {
						failures = append(failures, fmt.Sprintf("%s script %s targets missing package %s", scope.OwnerLabel, script.Name, target))
					}
				}
			}
			for _, target := range internalOptionTargets(script.Command, input.TargetOptionNames, input.TargetNamePrefixes) {
				if _, ok := knownPackageNames[target]; !ok {
					failures = append(failures, fmt.Sprintf("%s script %s targets missing package %s", scope.OwnerLabel, script.Name, target))
				}
			}
		}
	}
	return workspaceAdmissionReport{CheckedItemCount: checkedItemCount, Failures: uniqueText(failures)}
}

type workspaceDependencyInput struct {
	InternalDependencyLabel *string
	InternalNamePrefixes    []string
	KnownPackageNames       []string
	Owners                  []dependencyOwner
	WorkspaceVersion        string
}

func dependencyAdmission(input workspaceDependencyInput) workspaceAdmissionReport {
	knownPackageNames := toSet(input.KnownPackageNames)
	dependencyLabel := "dependency"
	if input.InternalDependencyLabel != nil {
		dependencyLabel = *input.InternalDependencyLabel + " dependency"
	}
	failures := []string{}
	checkedItemCount := 0
	for _, owner := range input.Owners {
		for _, ref := range owner.Refs {
			if !hasPrefix(ref.Name, input.InternalNamePrefixes) {
				continue
			}
			checkedItemCount++
			if ref.Version != input.WorkspaceVersion {
				failures = append(failures, fmt.Sprintf("%s has non-workspace %s %s", owner.OwnerLabel, dependencyLabel, ref.Name))
				continue
			}
			if _, ok := knownPackageNames[ref.Name]; !ok {
				failures = append(failures, fmt.Sprintf("%s has stale workspace dependency %s", owner.OwnerLabel, ref.Name))
			}
		}
	}
	return workspaceAdmissionReport{CheckedItemCount: checkedItemCount, Failures: uniqueText(failures)}
}

type packageRef struct {
	DirName string
	Name    string
}

type workspaceLockfileInput struct {
	ExpectedSnippets []expectedSnippet
	LockfileText     string
	Packages         []packageRef
	RootName         *string
}

func bunLockfileAdmission(input workspaceLockfileInput) workspaceAdmissionReport {
	failures := []string{}
	checkedItemCount := 0
	if input.RootName == nil {
		failures = append(failures, "package.json must declare a string name before lockfile verification")
	} else {
		checkedItemCount++
		if !strings.Contains(input.LockfileText, fmt.Sprintf(`"name": "%s"`, *input.RootName)) {
			failures = append(failures, "bun.lock must contain the current root workspace name")
		}
	}
	for _, expected := range input.ExpectedSnippets {
		checkedItemCount++
		if !strings.Contains(input.LockfileText, expected.Snippet) {
			failures = append(failures, expected.FailureMessage)
		}
	}
	for _, item := range input.Packages {
		checkedItemCount += 2
		if !strings.Contains(input.LockfileText, fmt.Sprintf(`"packages/%s"`, item.DirName)) {
			failures = append(failures, fmt.Sprintf("bun.lock missing workspace entry for %s", item.Name))
		}
		if !strings.Contains(input.LockfileText, fmt.Sprintf(`"%s": ["%s@workspace:packages/%s"`, item.Name, item.Name, item.DirName)) {
			failures = append(failures, fmt.Sprintf("bun.lock missing package entry for %s", item.Name))
		}
	}
	return workspaceAdmissionReport{CheckedItemCount: checkedItemCount, Failures: uniqueText(failures)}
}

func reportRule(ruleID string, failures []string, diagnostics map[string]any, status string) report.RuleResult {
	admittedStatus := status
	if admittedStatus == "" {
		admittedStatus = "passed"
	}
	if len(failures) > 0 {
		admittedStatus = "failed"
	}
	message := "passed"
	if admittedStatus == "skipped" {
		message = "skipped"
	} else if len(failures) > 0 {
		message = fmt.Sprintf("%d workspace registry issue(s) found", len(failures))
	}
	ruleDiagnostics := append(sortedDiagnostics(diagnostics), failureDiagnostics(failures)...)
	sortDiagnostics(ruleDiagnostics)
	return report.RuleResult{
		Diagnostics: ruleDiagnostics,
		Message:     message,
		RuleID:      ruleID,
		Status:      admittedStatus,
	}
}

func admitInput(raw any) (registryInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return registryInput{}, fmt.Errorf("workspace registry admission input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencyPolicy", "knownPackageNames", "lockfilePolicy", "nonClaims", "packages", "root", "schemaVersion", "scriptPolicy"}, "workspace registry admission input"); err != nil {
		return registryInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return registryInput{}, fmt.Errorf("workspace registry admission input schemaVersion must be 1")
	}
	knownPackageNames, err := sortedTextArray(record["knownPackageNames"], "known package name", false)
	if err != nil {
		return registryInput{}, err
	}
	root, err := admitRoot(record["root"])
	if err != nil {
		return registryInput{}, err
	}
	packages, err := admitPackages(record["packages"])
	if err != nil {
		return registryInput{}, err
	}
	scriptPolicy, err := admitScriptPolicy(record["scriptPolicy"])
	if err != nil {
		return registryInput{}, err
	}
	dependencyPolicy, err := admitDependencyPolicy(record["dependencyPolicy"])
	if err != nil {
		return registryInput{}, err
	}
	lockfilePolicy, err := admitLockfilePolicy(record["lockfilePolicy"])
	if err != nil {
		return registryInput{}, err
	}
	nonClaims := []string{}
	if rawNonClaims, ok := record["nonClaims"]; ok {
		nonClaims, err = textArray(rawNonClaims, "workspace registry nonClaims")
		if err != nil {
			return registryInput{}, err
		}
	}
	return registryInput{
		DependencyPolicy: dependencyPolicy,
		KnownPackageName: knownPackageNames,
		LockfilePolicy:   lockfilePolicy,
		NonClaims:        nonClaims,
		Packages:         packages,
		Root:             root,
		ScriptPolicy:     scriptPolicy,
	}, nil
}

func admitRoot(raw any) (rootFacts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return rootFacts{}, fmt.Errorf("workspace registry root must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencyRefs", "name", "scripts"}, "workspace registry root"); err != nil {
		return rootFacts{}, err
	}
	var name *string
	if rawName, ok := record["name"]; ok {
		value, err := nonEmptyText(rawName, "workspace root name")
		if err != nil {
			return rootFacts{}, err
		}
		name = &value
	}
	refs, err := dependencyRefs(record["dependencyRefs"], true)
	if err != nil {
		return rootFacts{}, err
	}
	scripts, err := admittedScripts(record["scripts"], "root script")
	if err != nil {
		return rootFacts{}, err
	}
	return rootFacts{DependencyRefs: refs, Name: name, Scripts: scripts}, nil
}

func admitPackages(raw any) ([]packageFacts, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace packages must be an array")
	}
	result := make([]packageFacts, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace package facts must be an object")
		}
		if err := admit.KnownKeys(record, []string{"dependencyRefs", "dirName", "name", "scripts"}, "workspace package facts"); err != nil {
			return nil, err
		}
		name, err := nonEmptyText(record["name"], "workspace package name")
		if err != nil {
			return nil, err
		}
		dirName, err := packageDirName(record["dirName"], name)
		if err != nil {
			return nil, err
		}
		refs, err := dependencyRefs(record["dependencyRefs"], true)
		if err != nil {
			return nil, err
		}
		scripts, err := admittedScripts(record["scripts"], name+" script")
		if err != nil {
			return nil, err
		}
		result = append(result, packageFacts{DependencyRefs: refs, DirName: dirName, Name: name, Scripts: scripts})
	}
	sort.Slice(result, func(left int, right int) bool {
		return jsLocaleLess(result[left].Name, result[right].Name)
	})
	names := make([]string, 0, len(result))
	for _, item := range result {
		names = append(names, item.Name)
	}
	if duplicate := firstDuplicate(names); duplicate != nil {
		return nil, fmt.Errorf("workspace package name must be unique: %s", *duplicate)
	}
	return result, nil
}

func admitScriptPolicy(raw any) (scriptPolicy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return scriptPolicy{}, fmt.Errorf("workspace registry scriptPolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"admittedRootScriptNames", "exactRootScripts", "requiredPackageScriptNames", "requiredRootScriptNames", "selfTargetOptionNames", "targetNamePrefixes", "targetOptionNames"}, "workspace registry scriptPolicy"); err != nil {
		return scriptPolicy{}, err
	}
	admittedRootScriptNames, err := optionalSortedTextArray(record["admittedRootScriptNames"], "admitted root script name")
	if err != nil {
		return scriptPolicy{}, err
	}
	exactRootScripts, err := scriptExpectations(record["exactRootScripts"], "exact root script")
	if err != nil {
		return scriptPolicy{}, err
	}
	requiredPackageScriptNames, err := optionalSortedTextArray(record["requiredPackageScriptNames"], "required package script name")
	if err != nil {
		return scriptPolicy{}, err
	}
	requiredRootScriptNames, err := optionalSortedTextArray(record["requiredRootScriptNames"], "required root script name")
	if err != nil {
		return scriptPolicy{}, err
	}
	selfTargetOptionNames, err := sortedTextArray(record["selfTargetOptionNames"], "workspace script self target option", false)
	if err != nil {
		return scriptPolicy{}, err
	}
	targetNamePrefixes, err := nonEmptyTextArray(record["targetNamePrefixes"], "workspace script target name prefix")
	if err != nil {
		return scriptPolicy{}, err
	}
	targetOptionNames, err := sortedTextArray(record["targetOptionNames"], "workspace script target option", false)
	if err != nil {
		return scriptPolicy{}, err
	}
	return scriptPolicy{
		AdmittedRootScriptNames: admittedRootScriptNames,
		ExactRootScripts:        exactRootScripts,
		RequiredPackageScripts:  requiredPackageScriptNames,
		RequiredRootScriptNames: requiredRootScriptNames,
		SelfTargetOptionNames:   selfTargetOptionNames,
		TargetNamePrefixes:      targetNamePrefixes,
		TargetOptionNames:       targetOptionNames,
	}, nil
}

func admitDependencyPolicy(raw any) (*dependencyPolicy, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("workspace registry dependencyPolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"internalDependencyLabel", "internalNamePrefixes", "workspaceVersion"}, "workspace registry dependencyPolicy"); err != nil {
		return nil, err
	}
	var label *string
	if rawLabel, ok := record["internalDependencyLabel"]; ok {
		value, err := nonEmptyText(rawLabel, "workspace internal dependency label")
		if err != nil {
			return nil, err
		}
		label = &value
	}
	prefixes, err := nonEmptyTextArray(record["internalNamePrefixes"], "workspace internal name prefix")
	if err != nil {
		return nil, err
	}
	version, err := nonEmptyText(record["workspaceVersion"], "workspace dependency version")
	if err != nil {
		return nil, err
	}
	return &dependencyPolicy{InternalDependencyLabel: label, InternalNamePrefixes: prefixes, WorkspaceVersion: version}, nil
}

func admitLockfilePolicy(raw any) (*lockfilePolicy, error) {
	if raw == nil {
		return nil, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("workspace registry lockfilePolicy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"expectedSnippets", "lockfileText"}, "workspace registry lockfilePolicy"); err != nil {
		return nil, err
	}
	expectedSnippets, err := expectedSnippets(record["expectedSnippets"])
	if err != nil {
		return nil, err
	}
	lockfileText, err := nonEmptyText(record["lockfileText"], "workspace lockfile text")
	if err != nil {
		return nil, err
	}
	return &lockfilePolicy{ExpectedSnippets: expectedSnippets, LockfileText: lockfileText}, nil
}

func dependencyRefs(raw any, optional bool) ([]dependencyRef, error) {
	if raw == nil && optional {
		return []dependencyRef{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace dependency refs must be an array")
	}
	result := make([]dependencyRef, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace dependency ref must be an object")
		}
		if err := admit.KnownKeys(record, []string{"field", "name", "version"}, "workspace dependency ref"); err != nil {
			return nil, err
		}
		field, err := nonEmptyText(record["field"], "workspace dependency field")
		if err != nil {
			return nil, err
		}
		name, err := nonEmptyText(record["name"], "workspace dependency name")
		if err != nil {
			return nil, err
		}
		version, err := nonEmptyText(record["version"], "workspace dependency version")
		if err != nil {
			return nil, err
		}
		result = append(result, dependencyRef{Field: field, Name: name, Version: version})
	}
	return result, nil
}

func admittedScripts(raw any, context string) ([]scriptEntry, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]scriptEntry, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", context)
		}
		if err := admit.KnownKeys(record, []string{"command", "name"}, context); err != nil {
			return nil, err
		}
		command, err := packageScriptText(record["command"], context+" command")
		if err != nil {
			return nil, err
		}
		name, err := nonEmptyText(record["name"], context+" name")
		if err != nil {
			return nil, err
		}
		result = append(result, scriptEntry{Command: command, Name: name})
	}
	sort.Slice(result, func(left int, right int) bool {
		return jsLocaleLess(result[left].Name, result[right].Name)
	})
	names := make([]string, 0, len(result))
	for _, item := range result {
		names = append(names, item.Name)
	}
	if duplicate := firstDuplicate(names); duplicate != nil {
		return nil, fmt.Errorf("%s name must be unique: %s", context, *duplicate)
	}
	return result, nil
}

func scriptMap(scripts []scriptEntry, context string) map[string]scriptEntry {
	result := map[string]scriptEntry{}
	for _, script := range scripts {
		result[script.Name] = script
	}
	_ = context
	return result
}

func scriptExpectations(raw any, context string) ([]scriptExpectation, error) {
	if raw == nil {
		return []scriptExpectation{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]scriptExpectation, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", context)
		}
		if err := admit.KnownKeys(record, []string{"command", "name"}, context); err != nil {
			return nil, err
		}
		name, err := nonEmptyText(record["name"], context+" name")
		if err != nil {
			return nil, err
		}
		var command *string
		if rawCommand, ok := record["command"]; ok {
			text, err := packageScriptText(rawCommand, context+" command")
			if err != nil {
				return nil, err
			}
			command = &text
		}
		result = append(result, scriptExpectation{Command: command, Name: name})
	}
	sort.Slice(result, func(left int, right int) bool {
		return jsLocaleLess(result[left].Name, result[right].Name)
	})
	names := make([]string, 0, len(result))
	for _, item := range result {
		names = append(names, item.Name)
	}
	if duplicate := firstDuplicate(names); duplicate != nil {
		return nil, fmt.Errorf("%s name must be unique: %s", context, *duplicate)
	}
	return result, nil
}

func expectedSnippets(raw any) ([]expectedSnippet, error) {
	if raw == nil {
		return []expectedSnippet{}, nil
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace lockfile expected snippets must be an array")
	}
	result := make([]expectedSnippet, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace lockfile expected snippet must be an object")
		}
		if err := admit.KnownKeys(record, []string{"failureMessage", "snippet"}, "workspace lockfile expected snippet"); err != nil {
			return nil, err
		}
		message, err := admit.NonEmptyText(record["failureMessage"], "workspace lockfile expected snippet failure message")
		if err != nil {
			return nil, err
		}
		snippet, err := nonEmptyText(record["snippet"], "workspace lockfile expected snippet")
		if err != nil {
			return nil, err
		}
		result = append(result, expectedSnippet{FailureMessage: message, Snippet: snippet})
	}
	return result, nil
}

func packageRefs(packages []packageFacts) []packageRef {
	result := make([]packageRef, 0, len(packages))
	for _, item := range packages {
		result = append(result, packageRef{DirName: item.DirName, Name: item.Name})
	}
	return result
}

func packageDirName(raw any, packageName string) (string, error) {
	dirName, err := nonEmptyText(raw, fmt.Sprintf("workspace package %s dirName", packageName))
	if err != nil {
		return "", err
	}
	if strings.Contains(dirName, "/") || strings.Contains(dirName, `\`) || strings.ContainsRune(dirName, '\x00') || dirName == "." || dirName == ".." {
		return "", fmt.Errorf("workspace package %s dirName must be one path segment", packageName)
	}
	return dirName, nil
}

func nonEmptyText(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func packageScriptText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("%s must be single-line package script text", context)
	}
	return value, nil
}

func textArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := nonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

func optionalSortedTextArray(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return sortedTextArray(raw, context, true)
}

func sortedTextArray(raw any, context string, allowEmpty bool) ([]string, error) {
	values, err := textArray(raw, context)
	if err != nil {
		return nil, err
	}
	sort.Strings(values)
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must not be empty", context)
	}
	if duplicate := firstDuplicate(values); duplicate != nil {
		return nil, fmt.Errorf("%s must be unique: %s", context, *duplicate)
	}
	return values, nil
}

func nonEmptyTextArray(raw any, context string) ([]string, error) {
	return sortedTextArray(raw, context, false)
}

func aggregateFailures(rules []report.RuleResult) []string {
	failures := []string{}
	for _, rule := range rules {
		if rule.Status != "failed" {
			continue
		}
		for _, diagnostic := range rule.Diagnostics {
			if strings.HasPrefix(diagnostic.Key, "failure.") {
				failures = append(failures, fmt.Sprint(diagnostic.Value))
			}
		}
	}
	return failures
}

func checkedItemCount(rules []report.RuleResult) int {
	total := 0
	for _, rule := range rules {
		for _, diagnostic := range rule.Diagnostics {
			if diagnostic.Key == "checkedItemCount" {
				if value, ok := diagnostic.Value.(int); ok {
					total += value
				}
			}
		}
	}
	return total
}

func packageScriptCount(packages []packageFacts) int {
	count := 0
	for _, item := range packages {
		count += len(item.Scripts)
	}
	return count
}

func sortedDiagnostics(values map[string]any) []report.Diagnostic {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left int, right int) bool {
		return jsLocaleLess(keys[left], keys[right])
	})
	result := make([]report.Diagnostic, 0, len(keys))
	for _, key := range keys {
		result = append(result, report.Diagnostic{Key: key, Value: values[key]})
	}
	return result
}

func sortDiagnostics(values []report.Diagnostic) {
	sort.Slice(values, func(left int, right int) bool {
		return jsLocaleLess(values[left].Key, values[right].Key)
	})
}

func failureDiagnostics(failures []string) []report.Diagnostic {
	result := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		result = append(result, report.Diagnostic{Key: fmt.Sprintf("failure.%03d", index+1), Value: failure})
	}
	return result
}

func internalOptionTargets(command string, optionNames []string, targetNamePrefixes []string) []string {
	values := collectScriptOptionValues(command, optionNames)
	result := []string{}
	for _, target := range values {
		if hasPrefix(target, targetNamePrefixes) {
			result = append(result, target)
		}
	}
	return result
}

func collectScriptOptionValues(command string, optionNames []string) []string {
	options := toSet(optionNames)
	tokens := shellLikeTokens(command)
	values := []string{}
	for index := 0; index < len(tokens)-1; index++ {
		if _, ok := options[tokens[index]]; ok && tokens[index+1] != "" {
			values = append(values, tokens[index+1])
		}
	}
	return values
}

func shellLikeTokens(command string) []string {
	tokens := []string{}
	current := strings.Builder{}
	var quote rune
	escaping := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, char := range command {
		if escaping {
			current.WriteRune(char)
			escaping = false
			continue
		}
		if char == '\\' && quote != '\'' {
			escaping = true
			continue
		}
		if (char == '\'' || char == '"') && quote == 0 {
			quote = char
			continue
		}
		if char == quote {
			quote = 0
			continue
		}
		if quote == 0 && unicode.IsSpace(char) {
			flush()
			continue
		}
		current.WriteRune(char)
	}
	if escaping {
		current.WriteRune('\\')
	}
	flush()
	return tokens
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func uniqueText(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func firstDuplicate(values []string) *string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			duplicate := value
			return &duplicate
		}
		seen[value] = struct{}{}
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func toSet(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func knownPackageNamesLength(left []string, right []string) int {
	return len(left) + len(right)
}

func jsLocaleLess(left string, right string) bool {
	leftFolded := strings.ToLower(left)
	rightFolded := strings.ToLower(right)
	if leftFolded == rightFolded {
		return left < right
	}
	return leftFolded < rightFolded
}
