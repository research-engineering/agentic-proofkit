package workspaceplanning

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/pathpattern"
)

func BuildChangedPackagePlan(raw any) (map[string]any, error) {
	input, err := admitChangedPlanInput(raw)
	if err != nil {
		return nil, err
	}
	return buildChangedPlan(input), nil
}

func buildChangedPlan(input changedPlanInput) map[string]any {
	directRoots := selectPackageRoots(input.Packages, input.ChangedPaths, input.PackagesRoot)
	escalationReasons := escalationReasons(input.ChangedPaths, input.EscalationRules)
	fullWorkspace := len(escalationReasons) > 0
	var roots []packagePathNode
	if fullWorkspace {
		roots = input.Packages
	} else if input.IncludeReverseDependents {
		roots = reverseDependents(input.Packages, directRoots)
	} else {
		roots = directRoots
	}
	return map[string]any{
		"changedPaths":           stringsToAny(input.ChangedPaths),
		"directRootPackageNames": stringsToAny(packageNames(directRoots)),
		"directRoots":            pathNodesJSON(directRoots),
		"escalationReasons":      stringsToAny(escalationReasons),
		"fullWorkspace":          fullWorkspace,
		"rootPackageNames":       stringsToAny(packageNames(roots)),
		"roots":                  pathNodesJSON(roots),
		"schemaVersion":          1,
	}
}

func admitChangedPlanInput(raw any) (changedPlanInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return changedPlanInput{}, fmt.Errorf("workspace changed-package plan input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"changedPaths", "escalationRules", "includeReverseDependents", "packages", "packagesRoot", "schemaVersion"}, "workspace changed-package plan input"); err != nil {
		return changedPlanInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return changedPlanInput{}, fmt.Errorf("workspace changed-package plan schemaVersion must be 1")
	}
	changedPaths, err := sortedRepoPaths(require(record, "changedPaths"), "workspace changed path")
	if err != nil {
		return changedPlanInput{}, err
	}
	rules, err := escalationRuleInputs(require(record, "escalationRules"))
	if err != nil {
		return changedPlanInput{}, err
	}
	packages, err := pathNodeInputs(require(record, "packages"))
	if err != nil {
		return changedPlanInput{}, err
	}
	includeReverse := true
	if rawValue, ok := record["includeReverseDependents"]; ok {
		value, err := admit.Bool(rawValue, "workspace includeReverseDependents")
		if err != nil {
			return changedPlanInput{}, err
		}
		includeReverse = value
	}
	packagesRoot := "packages"
	if rawValue, ok := record["packagesRoot"]; ok {
		text, ok := rawValue.(string)
		if !ok {
			return changedPlanInput{}, fmt.Errorf("workspace packagesRoot must be a repository-relative POSIX path")
		}
		root, err := admit.SafeRepoRelativePath(text, "workspace packages root")
		if err != nil {
			return changedPlanInput{}, err
		}
		packagesRoot = root
	}
	if err := assertUniquePathNodes(packages); err != nil {
		return changedPlanInput{}, err
	}
	return changedPlanInput{ChangedPaths: changedPaths, EscalationRules: rules, IncludeReverseDependents: includeReverse, Packages: packages, PackagesRoot: packagesRoot}, nil
}

func pathNodeInputs(raw any) ([]packagePathNode, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace packages must be an array")
	}
	result := []packagePathNode{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace package %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"dirName", "name", "workspaceDependencies"}, fmt.Sprintf("workspace package %d", index+1)); err != nil {
			return nil, err
		}
		dirName, err := admit.RuleID(record["dirName"], fmt.Sprintf("workspace package %d dirName", index+1))
		if err != nil {
			return nil, err
		}
		node, err := dependencyNodeInput(record, fmt.Sprintf("workspace package %d", index+1))
		if err != nil {
			return nil, err
		}
		result = append(result, packagePathNode{DirName: dirName, dependencyNode: node})
	}
	return result, nil
}

func escalationRuleInputs(raw any) ([]escalationRule, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace escalationRules must be an array")
	}
	result := []escalationRule{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace escalation rule %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"pattern", "reason"}, fmt.Sprintf("workspace escalation rule %d", index+1)); err != nil {
			return nil, err
		}
		pattern, ok := record["pattern"].(string)
		if !ok {
			return nil, fmt.Errorf("workspace escalation pattern must be a repository-relative POSIX path")
		}
		if err := pathpattern.Validate(pattern, "path pattern"); err != nil {
			return nil, err
		}
		reason, err := admit.RuleID(record["reason"], "workspace escalation reason")
		if err != nil {
			return nil, err
		}
		result = append(result, escalationRule{Pattern: pattern, Reason: reason})
	}
	return result, nil
}

func selectPackageRoots(packages []packagePathNode, changedPaths []string, packagesRoot string) []packagePathNode {
	prefix := strings.TrimSuffix(packagesRoot, "/") + "/"
	byDir := map[string]packagePathNode{}
	for _, pkg := range packages {
		byDir[pkg.DirName] = pkg
	}
	rootNames := map[string]struct{}{}
	for _, pathValue := range changedPaths {
		if strings.HasPrefix(pathValue, prefix) {
			dirName := strings.SplitN(strings.TrimPrefix(pathValue, prefix), "/", 2)[0]
			if pkg, ok := byDir[dirName]; ok {
				rootNames[pkg.Name] = struct{}{}
			}
		}
	}
	result := []packagePathNode{}
	for _, pkg := range packages {
		if _, ok := rootNames[pkg.Name]; ok {
			result = append(result, pkg)
		}
	}
	return result
}

func escalationReasons(changedPaths []string, rules []escalationRule) []string {
	reasons := map[string]struct{}{}
	for _, rule := range rules {
		for _, pathValue := range changedPaths {
			if pathpattern.Match(rule.Pattern, pathValue) {
				reasons[rule.Reason] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(reasons))
	for reason := range reasons {
		result = append(result, reason)
	}
	sort.Strings(result)
	return result
}

func reverseDependents(packages []packagePathNode, roots []packagePathNode) []packagePathNode {
	reverse := map[string]map[string]struct{}{}
	for _, pkg := range packages {
		for _, dependency := range pkg.WorkspaceDependencies {
			if reverse[dependency] == nil {
				reverse[dependency] = map[string]struct{}{}
			}
			reverse[dependency][pkg.Name] = struct{}{}
		}
	}
	selected := map[string]struct{}{}
	queue := []string{}
	for _, root := range roots {
		selected[root.Name] = struct{}{}
		queue = append(queue, root.Name)
	}
	for index := 0; index < len(queue); index++ {
		for dependent := range reverse[queue[index]] {
			if _, ok := selected[dependent]; !ok {
				selected[dependent] = struct{}{}
				queue = append(queue, dependent)
			}
		}
	}
	result := []packagePathNode{}
	for _, pkg := range packages {
		if _, ok := selected[pkg.Name]; ok {
			result = append(result, pkg)
		}
	}
	return result
}

func assertUniquePathNodes(packages []packagePathNode) error {
	dirNames := []string{}
	names := []string{}
	for _, pkg := range packages {
		dirNames = append(dirNames, pkg.DirName)
		names = append(names, pkg.Name)
	}
	sort.Strings(dirNames)
	if duplicate := firstDuplicate(dirNames); duplicate != "" {
		return fmt.Errorf("workspace package dirName must be unique: %s", duplicate)
	}
	sort.Strings(names)
	if duplicate := firstDuplicate(names); duplicate != "" {
		return fmt.Errorf("workspace package name must be unique: %s", duplicate)
	}
	return nil
}
