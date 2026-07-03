package workspacemanifestfacts

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

var commandNonClaims = []string{
	"Workspace manifest facts do not scan repositories or read package files.",
	"Workspace manifest facts do not interpret package-manager policy, dependency version policy, script policy, lockfile freshness, CI scheduling, or merge approval.",
	"Workspace manifest facts are derived only from caller-provided manifest records.",
}

type input struct {
	DependencyFields []string
	NonClaims        []string
	Packages         []manifestRecord
	ProjectionID     string
	Root             manifestRecord
}

type manifestRecord struct {
	DirName      string
	Manifest     manifestFacts
	ManifestPath string
	PackageDir   string
}

type manifestFacts struct {
	DependencyRefs []dependencyRef
	Name           string
	Scripts        []scriptEntry
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

type workspaceEdge struct {
	Field    string
	FromKind string
	FromName string
	ToName   string
	Version  string
}

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	return buildOutput(input), 0, nil
}

func admitInput(raw any) (input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return input{}, fmt.Errorf("workspace manifest facts input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"dependencyFields", "nonClaims", "packages", "projectionId", "root", "schemaVersion"}, "workspace manifest facts input"); err != nil {
		return input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return input{}, fmt.Errorf("workspace manifest facts schemaVersion must be 1")
	}
	projectionID, err := admit.RuleID(record["projectionId"], "workspace manifest facts projectionId")
	if err != nil {
		return input{}, err
	}
	dependencyFields, err := sortedRuleIDs(record["dependencyFields"], "workspace manifest facts dependencyFields", false)
	if err != nil {
		return input{}, err
	}
	root, err := admitManifestRecord(record["root"], dependencyFields, "workspace manifest facts root", false)
	if err != nil {
		return input{}, err
	}
	packages, err := admitPackages(record["packages"], dependencyFields)
	if err != nil {
		return input{}, err
	}
	for _, item := range packages {
		if item.ManifestPath == root.ManifestPath {
			return input{}, fmt.Errorf("workspace manifest facts manifestPath must be unique: %s", item.ManifestPath)
		}
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "workspace manifest facts nonClaims", false)
	if err != nil {
		return input{}, err
	}
	return input{
		DependencyFields: dependencyFields,
		NonClaims:        nonClaims,
		Packages:         packages,
		ProjectionID:     projectionID,
		Root:             root,
	}, nil
}

func admitPackages(raw any, dependencyFields []string) ([]manifestRecord, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("workspace manifest facts packages must be an array")
	}
	packages := make([]manifestRecord, 0, len(values))
	for index, value := range values {
		item, err := admitManifestRecord(value, dependencyFields, fmt.Sprintf("workspace manifest facts package %d", index+1), true)
		if err != nil {
			return nil, err
		}
		packages = append(packages, item)
	}
	sort.Slice(packages, func(left, right int) bool {
		return packages[left].Manifest.Name < packages[right].Manifest.Name
	})
	if duplicate := firstDuplicate(packageNames(packages)); duplicate != "" {
		return nil, fmt.Errorf("workspace manifest facts package name must be unique: %s", duplicate)
	}
	dirNames := packageDirNames(packages)
	if duplicate := firstDuplicate(dirNames); duplicate != "" {
		return nil, fmt.Errorf("workspace manifest facts package dirName must be unique: %s", duplicate)
	}
	manifestPaths := make([]string, 0, len(packages))
	for _, item := range packages {
		manifestPaths = append(manifestPaths, item.ManifestPath)
	}
	if duplicate := firstDuplicate(manifestPaths); duplicate != "" {
		return nil, fmt.Errorf("workspace manifest facts manifestPath must be unique: %s", duplicate)
	}
	return packages, nil
}

func admitManifestRecord(raw any, dependencyFields []string, context string, requireDirName bool) (manifestRecord, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return manifestRecord{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"dirName", "manifest", "manifestPath", "packageDir"}, context); err != nil {
		return manifestRecord{}, err
	}
	manifestPathText, err := admit.NonEmptyText(record["manifestPath"], context+" manifestPath")
	if err != nil {
		return manifestRecord{}, err
	}
	manifestPath, err := admit.SafeRepoRelativePath(manifestPathText, context+" manifestPath")
	if err != nil {
		return manifestRecord{}, err
	}
	dirName := ""
	if record["dirName"] != nil {
		dirName, err = admitDirName(record["dirName"], context+" dirName")
		if err != nil {
			return manifestRecord{}, err
		}
	} else if requireDirName {
		return manifestRecord{}, fmt.Errorf("%s dirName must be provided", context)
	}
	packageDir := ""
	if record["packageDir"] != nil {
		packageDirText, err := admit.NonEmptyText(record["packageDir"], context+" packageDir")
		if err != nil {
			return manifestRecord{}, err
		}
		packageDir, err = admit.SafeRepoRelativePath(packageDirText, context+" packageDir")
		if err != nil {
			return manifestRecord{}, err
		}
	}
	manifest, err := admitManifest(record["manifest"], dependencyFields, context+" manifest")
	if err != nil {
		return manifestRecord{}, err
	}
	return manifestRecord{DirName: dirName, Manifest: manifest, ManifestPath: manifestPath, PackageDir: packageDir}, nil
}

func admitManifest(raw any, dependencyFields []string, context string) (manifestFacts, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return manifestFacts{}, fmt.Errorf("%s must be an object", context)
	}
	admitted := append([]string{"name", "scripts"}, dependencyFields...)
	if err := admit.KnownKeys(record, admitted, context); err != nil {
		return manifestFacts{}, err
	}
	name, err := manifestScalarText(record["name"], context+" name")
	if err != nil {
		return manifestFacts{}, err
	}
	scripts, err := admitScripts(record["scripts"], context+" scripts")
	if err != nil {
		return manifestFacts{}, err
	}
	dependencies := []dependencyRef{}
	for _, field := range dependencyFields {
		refs, err := admitDependencyMap(record[field], field, context+" "+field)
		if err != nil {
			return manifestFacts{}, err
		}
		dependencies = append(dependencies, refs...)
	}
	sortDependencyRefs(dependencies)
	return manifestFacts{DependencyRefs: dependencies, Name: name, Scripts: scripts}, nil
}

func admitScripts(raw any, context string) ([]scriptEntry, error) {
	if raw == nil {
		return []scriptEntry{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	scripts := make([]scriptEntry, 0, len(record))
	names := make([]string, 0, len(record))
	for rawName, rawCommand := range record {
		name, err := manifestScalarText(rawName, context+" name")
		if err != nil {
			return nil, err
		}
		command, err := manifestScalarText(rawCommand, context+" command")
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, scriptEntry{Name: name, Command: command})
		names = append(names, name)
	}
	if duplicate := firstDuplicate(names); duplicate != "" {
		return nil, fmt.Errorf("%s script name must be unique: %s", context, duplicate)
	}
	sort.Slice(scripts, func(left, right int) bool {
		return scripts[left].Name < scripts[right].Name
	})
	return scripts, nil
}

func admitDependencyMap(raw any, field string, context string) ([]dependencyRef, error) {
	if raw == nil {
		return []dependencyRef{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", context)
	}
	refs := make([]dependencyRef, 0, len(record))
	names := make([]string, 0, len(record))
	for rawName, rawVersion := range record {
		name, err := manifestScalarText(rawName, context+" name")
		if err != nil {
			return nil, err
		}
		version, err := manifestScalarText(rawVersion, context+" version")
		if err != nil {
			return nil, err
		}
		refs = append(refs, dependencyRef{Field: field, Name: name, Version: version})
		names = append(names, name)
	}
	if duplicate := firstDuplicate(names); duplicate != "" {
		return nil, fmt.Errorf("%s dependency name must be unique: %s", context, duplicate)
	}
	sortDependencyRefs(refs)
	return refs, nil
}

func buildOutput(input input) map[string]any {
	edges := workspaceEdges(input.Root, input.Packages)
	return map[string]any{
		"schemaVersion":              1,
		"projectionId":               input.ProjectionID,
		"reportKind":                 "proofkit.workspace-manifest-facts",
		"reportId":                   input.ProjectionID,
		"state":                      "passed",
		"summary":                    summaryValue(input, edges),
		"knownPackageNames":          stringsToAny(packageNames(input.Packages)),
		"root":                       rootValue(input.Root),
		"packages":                   packagesValue(input.Packages),
		"manifestSources":            manifestSourcesValue(input),
		"packageUniverse":            packageUniverseValue(input, edges),
		"changedPackagePlanPackages": planningPackageValues(input.Packages),
		"shardPartitionPackages":     shardPackageValues(input.Packages),
		"diagnostics":                []any{},
		"nonClaims":                  stringsToAny(append(append([]string{}, commandNonClaims...), input.NonClaims...)),
	}
}

func summaryValue(input input, edges []workspaceEdge) map[string]any {
	return map[string]any{
		"dependencyFieldCount":         len(input.DependencyFields),
		"packageCount":                 len(input.Packages),
		"packageDependencyRefCount":    dependencyRefCount(input.Packages),
		"packageScriptCount":           scriptCount(input.Packages),
		"rootDependencyRefCount":       len(input.Root.Manifest.DependencyRefs),
		"rootScriptCount":              len(input.Root.Manifest.Scripts),
		"workspaceDependencyEdgeCount": len(edges),
	}
}

func rootValue(item manifestRecord) map[string]any {
	return map[string]any{
		"name":           item.Manifest.Name,
		"scripts":        scriptsValue(item.Manifest.Scripts),
		"dependencyRefs": dependencyRefsValue(item.Manifest.DependencyRefs),
	}
}

func packagesValue(values []manifestRecord) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{
			"name":           item.Manifest.Name,
			"dirName":        item.DirName,
			"scripts":        scriptsValue(item.Manifest.Scripts),
			"dependencyRefs": dependencyRefsValue(item.Manifest.DependencyRefs),
		})
	}
	return result
}

func manifestSourcesValue(input input) map[string]any {
	packages := make([]any, 0, len(input.Packages))
	for _, item := range input.Packages {
		packages = append(packages, map[string]any{
			"name":         item.Manifest.Name,
			"dirName":      item.DirName,
			"manifestPath": item.ManifestPath,
			"packageDir":   item.PackageDir,
		})
	}
	return map[string]any{
		"root": map[string]any{
			"name":         input.Root.Manifest.Name,
			"manifestPath": input.Root.ManifestPath,
			"packageDir":   input.Root.PackageDir,
		},
		"packages": packages,
	}
}

func packageUniverseValue(input input, edges []workspaceEdge) map[string]any {
	return map[string]any{
		"rootPackageName":          input.Root.Manifest.Name,
		"packageNames":             stringsToAny(packageNames(input.Packages)),
		"packageDirNames":          stringsToAny(packageDirNames(input.Packages)),
		"workspaceDependencyEdges": workspaceEdgesValue(edges),
	}
}

func planningPackageValues(values []manifestRecord) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{
			"name":                  item.Manifest.Name,
			"dirName":               item.DirName,
			"workspaceDependencies": stringsToAny(workspaceDependencies(item, values)),
		})
	}
	return result
}

func shardPackageValues(values []manifestRecord) []any {
	result := make([]any, 0, len(values))
	for _, item := range values {
		result = append(result, map[string]any{
			"name":                  item.Manifest.Name,
			"workspaceDependencies": stringsToAny(workspaceDependencies(item, values)),
		})
	}
	return result
}

func scriptsValue(values []scriptEntry) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{"name": value.Name, "command": value.Command})
	}
	return result
}

func dependencyRefsValue(values []dependencyRef) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{"field": value.Field, "name": value.Name, "version": value.Version})
	}
	return result
}

func workspaceEdgesValue(values []workspaceEdge) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"fromKind": value.FromKind,
			"fromName": value.FromName,
			"toName":   value.ToName,
			"field":    value.Field,
			"version":  value.Version,
		})
	}
	return result
}

func workspaceEdges(root manifestRecord, packages []manifestRecord) []workspaceEdge {
	workspaceNames := map[string]struct{}{}
	for _, item := range packages {
		workspaceNames[item.Manifest.Name] = struct{}{}
	}
	edges := []workspaceEdge{}
	for _, ref := range root.Manifest.DependencyRefs {
		if _, ok := workspaceNames[ref.Name]; ok {
			edges = append(edges, workspaceEdge{Field: ref.Field, FromKind: "root", FromName: root.Manifest.Name, ToName: ref.Name, Version: ref.Version})
		}
	}
	for _, item := range packages {
		for _, ref := range item.Manifest.DependencyRefs {
			if _, ok := workspaceNames[ref.Name]; ok {
				edges = append(edges, workspaceEdge{Field: ref.Field, FromKind: "package", FromName: item.Manifest.Name, ToName: ref.Name, Version: ref.Version})
			}
		}
	}
	sort.Slice(edges, func(left, right int) bool {
		return edgeKey(edges[left]) < edgeKey(edges[right])
	})
	return edges
}

func workspaceDependencies(item manifestRecord, packages []manifestRecord) []string {
	workspaceNames := map[string]struct{}{}
	for _, pkg := range packages {
		workspaceNames[pkg.Manifest.Name] = struct{}{}
	}
	values := []string{}
	for _, ref := range item.Manifest.DependencyRefs {
		if _, ok := workspaceNames[ref.Name]; ok {
			values = append(values, ref.Name)
		}
	}
	sort.Strings(values)
	return uniqueStrings(values)
}

func admitDirName(raw any, context string) (string, error) {
	value, err := admit.RuleID(raw, context)
	if err != nil {
		return "", err
	}
	if strings.Contains(value, "/") || strings.Contains(value, "\\") || value == "." || value == ".." {
		return "", fmt.Errorf("%s must be one path segment", context)
	}
	return value, nil
}

func manifestScalarText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	for _, item := range value {
		if unicode.IsControl(item) {
			return "", fmt.Errorf("%s must not contain control characters", context)
		}
	}
	return value, nil
}

func sortedRuleIDs(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		value, err := admit.RuleID(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return admit.PreserveSortedText(result, context, allowEmpty)
}

func packageNames(values []manifestRecord) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, item.Manifest.Name)
	}
	sort.Strings(result)
	return result
}

func packageDirNames(values []manifestRecord) []string {
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, item.DirName)
	}
	sort.Strings(result)
	return result
}

func dependencyRefCount(values []manifestRecord) int {
	total := 0
	for _, item := range values {
		total += len(item.Manifest.DependencyRefs)
	}
	return total
}

func scriptCount(values []manifestRecord) int {
	total := 0
	for _, item := range values {
		total += len(item.Manifest.Scripts)
	}
	return total
}

func sortDependencyRefs(values []dependencyRef) {
	sort.Slice(values, func(left, right int) bool {
		return dependencyRefKey(values[left]) < dependencyRefKey(values[right])
	})
}

func dependencyRefKey(value dependencyRef) string {
	return value.Field + "\x00" + value.Name + "\x00" + value.Version
}

func edgeKey(value workspaceEdge) string {
	return value.FromKind + "\x00" + value.FromName + "\x00" + value.ToName + "\x00" + value.Field + "\x00" + value.Version
}

func firstDuplicate(values []string) string {
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return values[index]
		}
	}
	return ""
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
			previous = value
		}
	}
	return append([]string{}, result...)
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
