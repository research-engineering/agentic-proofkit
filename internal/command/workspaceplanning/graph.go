package workspaceplanning

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func dependencyNodeInputs(raw any) ([]dependencyNode, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace packages must be an array")
	}
	result := []dependencyNode{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("workspace package %d must be an object", index+1)
		}
		if err := admit.KnownKeys(record, []string{"name", "workspaceDependencies"}, fmt.Sprintf("workspace package %d", index+1)); err != nil {
			return nil, err
		}
		node, err := dependencyNodeInput(record, fmt.Sprintf("workspace package %d", index+1))
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, nil
}

func dependencyNodeInput(record map[string]any, context string) (dependencyNode, error) {
	name, err := nonEmptyText(record["name"], context+" name")
	if err != nil {
		return dependencyNode{}, err
	}
	dependencies, err := sortedNonEmptyText(record["workspaceDependencies"], context+" workspaceDependencies")
	if err != nil {
		return dependencyNode{}, err
	}
	return dependencyNode{Name: name, WorkspaceDependencies: dependencies}, nil
}

func dependencyClosure(packages []dependencyNode, roots []dependencyNode) ([]dependencyNode, error) {
	byName, err := nodeMap(packages)
	if err != nil {
		return nil, err
	}
	selected := map[string]struct{}{}
	var visit func(dependencyNode) error
	visit = func(target dependencyNode) error {
		if _, ok := selected[target.Name]; ok {
			return nil
		}
		selected[target.Name] = struct{}{}
		for _, dependencyName := range target.WorkspaceDependencies {
			dependency, ok := byName[dependencyName]
			if !ok {
				return fmt.Errorf("%s depends on missing workspace package %s", target.Name, dependencyName)
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	for _, root := range roots {
		if err := visit(root); err != nil {
			return nil, err
		}
	}
	filtered := []dependencyNode{}
	for _, pkg := range packages {
		if _, ok := selected[pkg.Name]; ok {
			filtered = append(filtered, pkg)
		}
	}
	return topological(filtered)
}

func topological(packages []dependencyNode) ([]dependencyNode, error) {
	byName, err := nodeMap(packages)
	if err != nil {
		return nil, err
	}
	visited := map[string]struct{}{}
	visiting := map[string]struct{}{}
	ordered := []dependencyNode{}
	var visit func(dependencyNode) error
	visit = func(target dependencyNode) error {
		if _, ok := visited[target.Name]; ok {
			return nil
		}
		if _, ok := visiting[target.Name]; ok {
			return fmt.Errorf("workspace dependency cycle includes %s", target.Name)
		}
		visiting[target.Name] = struct{}{}
		for _, dependencyName := range target.WorkspaceDependencies {
			if dependency, ok := byName[dependencyName]; ok {
				if err := visit(dependency); err != nil {
					return err
				}
			}
		}
		delete(visiting, target.Name)
		visited[target.Name] = struct{}{}
		ordered = append(ordered, target)
		return nil
	}
	for _, pkg := range packages {
		if err := visit(pkg); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func nodeMap(packages []dependencyNode) (map[string]dependencyNode, error) {
	result := map[string]dependencyNode{}
	for _, pkg := range packages {
		if _, ok := result[pkg.Name]; ok {
			return nil, fmt.Errorf("workspace package name must be unique: %s", pkg.Name)
		}
		result[pkg.Name] = pkg
	}
	return result, nil
}

func sortedNonEmptyText(raw any, context string) ([]string, error) {
	values, err := stringArray(raw, context)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, value := range values {
		text, err := nonEmptyText(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return sortStrings(result), nil
}

func nonEmptyText(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}
