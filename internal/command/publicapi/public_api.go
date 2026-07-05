package publicapi

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	defaultMachineContract = "public_api_surfaces"
	defaultPackagesRoot    = "packages"
	defaultSourceExtension = ".ts"
	defaultSourcePrefix    = "src/"
)

var (
	namedExportPattern    = regexp.MustCompile(`^export\s+(\{[^}]+\})\s+from\s+["'][^"']+["'];?$`)
	typeExportPattern     = regexp.MustCompile(`^export\s+type\s+(\{[^}]+\})\s+from\s+["'][^"']+["'];?$`)
	runtimeDeclPattern    = regexp.MustCompile(`^export\s+(?:abstract\s+)?(?:async\s+)?(?:function|class|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)
	typeDeclPattern       = regexp.MustCompile(`^export\s+(?:interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)
	varDeclPattern        = regexp.MustCompile(`^export\s+(?:const|let|var)\s+(.+?);?$`)
	exportClauseNameRegex = regexp.MustCompile(`\bas\s+([A-Za-z_$][A-Za-z0-9_$]*)$`)
	identifierRegex       = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
)

type Options struct {
	MachineContract string
	PackagesRoot    string
	RepoRoot        string
	SourceExtension string
	SourcePrefix    string
}

type entry struct {
	DeniedExportKeys []string
	ExportConditions []exportCondition
	ExportKey        string
	PackageName      string
	RuntimeExports   []string
	Source           string
	TypeExports      []string
}

type exportCondition struct {
	Condition string
	Path      string
}

func Verify(raw any, options Options) (map[string]any, int, error) {
	if options.MachineContract == "" {
		options.MachineContract = defaultMachineContract
	}
	if options.PackagesRoot == "" {
		options.PackagesRoot = defaultPackagesRoot
	}
	if options.SourceExtension == "" {
		options.SourceExtension = defaultSourceExtension
	}
	if options.SourcePrefix == "" {
		options.SourcePrefix = defaultSourcePrefix
	}
	repoRoot, err := filepath.EvalSymlinks(options.RepoRoot)
	if err != nil {
		return nil, 1, err
	}
	manifest, err := admitManifest(raw, options.MachineContract)
	if err != nil {
		return nil, 1, err
	}
	packages, err := packageDirs(repoRoot, options.PackagesRoot)
	if err != nil {
		return nil, 1, err
	}
	failures := []string{}
	verifyCoveredPackageExportKeys(repoRoot, packages, manifest, &failures)
	seenKeys := map[string]struct{}{}
	for _, item := range manifest {
		manifestKey := item.PackageName + ":" + item.ExportKey
		if _, ok := seenKeys[manifestKey]; ok {
			failures = append(failures, "duplicate TypeScript public API manifest entry "+manifestKey)
			continue
		}
		seenKeys[manifestKey] = struct{}{}
		packageDir, ok := packages[item.PackageName]
		if !ok {
			failures = append(failures, "TypeScript public API manifest references missing package "+item.PackageName)
			continue
		}
		source, err := safePackageRelativePath(item.Source, manifestKey, options.SourcePrefix, options.SourceExtension)
		if err != nil {
			return nil, 1, err
		}
		sourcePath := filepath.Join(packageDir, filepath.FromSlash(source))
		sourceBytes, err := readFileUnderRoot(repoRoot, sourcePath, manifestKey+" source")
		if err != nil {
			if os.IsNotExist(err) {
				failures = append(failures, fmt.Sprintf("%s source does not exist: %s", manifestKey, source))
				continue
			}
			return nil, 1, err
		}
		verifyPackageExportMap(repoRoot, packageDir, item, &failures)
		actualRuntime, actualTypes, err := CollectExports(string(sourceBytes))
		if err != nil {
			return nil, 1, err
		}
		compareExports(item.RuntimeExports, actualRuntime, manifestKey+" runtime exports", &failures)
		compareExports(item.TypeExports, actualTypes, manifestKey+" type exports", &failures)
	}
	exitCode := 0
	if len(failures) > 0 {
		sort.Strings(failures)
		exitCode = 1
	}
	return map[string]any{
		"entryCount":     len(manifest),
		"failures":       admit.StringSliceToAny(failures),
		"inputAuthority": "caller_manifest_plus_filesystem_snapshot",
		"nonClaims": []any{
			"TypeScript public API verification is a filesystem verifier for a caller-selected checkout.",
			"TypeScript public API verification does not claim pure JSON admission or repository freshness beyond the supplied repo root.",
		},
	}, exitCode, nil
}

func admitManifest(raw any, machineContract string) ([]entry, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("TypeScript public API manifest must be an object")
	}
	if err := admit.KnownKeys(record, []string{"entries", "machineContract", "schemaVersion"}, "TypeScript public API manifest"); err != nil {
		return nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return nil, fmt.Errorf("TypeScript public API manifest schemaVersion must be 1")
	}
	if record["machineContract"] != machineContract {
		return nil, fmt.Errorf("TypeScript public API manifest machineContract must be %s", machineContract)
	}
	values, ok := record["entries"].([]any)
	if !ok {
		return nil, fmt.Errorf("TypeScript public API manifest entries must be an array")
	}
	entries := make([]entry, 0, len(values))
	for index, value := range values {
		item, err := manifestEntry(value, fmt.Sprintf("public API manifest entry #%d", index+1))
		if err != nil {
			return nil, err
		}
		entries = append(entries, item)
	}
	return entries, nil
}

func manifestEntry(raw any, context string) (entry, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return entry{}, fmt.Errorf("%s must be an object", context)
	}
	if err := admit.KnownKeys(record, []string{"deniedExportKeys", "exportConditions", "exportKey", "packageName", "runtimeExports", "source", "typeExports"}, context); err != nil {
		return entry{}, err
	}
	conditions, err := exportConditions(record["exportConditions"], context+".exportConditions")
	if err != nil {
		return entry{}, err
	}
	denied, err := optionalStringArray(record["deniedExportKeys"], context+".deniedExportKeys")
	if err != nil {
		return entry{}, err
	}
	runtimeExports, err := requiredSortedStringArray(record["runtimeExports"], context+".runtimeExports")
	if err != nil {
		return entry{}, err
	}
	typeExports, err := requiredSortedStringArray(record["typeExports"], context+".typeExports")
	if err != nil {
		return entry{}, err
	}
	packageName, err := nonEmptyString(record["packageName"], context+".packageName")
	if err != nil {
		return entry{}, err
	}
	source, err := nonEmptyString(record["source"], context+".source")
	if err != nil {
		return entry{}, err
	}
	exportKey, err := nonEmptyString(record["exportKey"], context+".exportKey")
	if err != nil {
		return entry{}, err
	}
	return entry{
		DeniedExportKeys: denied, ExportConditions: conditions, ExportKey: exportKey,
		PackageName: packageName, RuntimeExports: runtimeExports, Source: source, TypeExports: typeExports,
	}, nil
}

func exportConditions(raw any, context string) ([]exportCondition, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty array", context)
	}
	conditions := make([]exportCondition, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", context, index)
		}
		if err := admit.KnownKeys(record, []string{"condition", "path"}, fmt.Sprintf("%s[%d]", context, index)); err != nil {
			return nil, err
		}
		condition, err := nonEmptyString(record["condition"], fmt.Sprintf("%s[%d].condition", context, index))
		if err != nil {
			return nil, err
		}
		path, err := nonEmptyString(record["path"], fmt.Sprintf("%s[%d].path", context, index))
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, exportCondition{Condition: condition, Path: path})
	}
	if err := assertSortedUnique(exportConditionNames(conditions), context+" conditions"); err != nil {
		return nil, err
	}
	return conditions, nil
}

func packageDirs(repoRoot string, packagesRootPath string) (map[string]string, error) {
	packagesRoot := filepath.Join(repoRoot, filepath.FromSlash(packagesRootPath))
	if _, err := resolvedPathUnderRoot(repoRoot, packagesRoot, "TypeScript public API packages root"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(packagesRoot)
	if err != nil {
		return nil, err
	}
	byName := map[string]string{}
	for _, dirent := range entries {
		if !dirent.IsDir() {
			continue
		}
		packageDir := filepath.Join(packagesRoot, dirent.Name())
		manifestPath := filepath.Join(packageDir, "package.json")
		if _, err := os.Lstat(manifestPath); err != nil {
			continue
		}
		manifest, err := readPackageManifest(repoRoot, manifestPath)
		if err != nil {
			return nil, err
		}
		if name, ok := manifest["name"].(string); ok {
			if previous, exists := byName[name]; exists {
				return nil, fmt.Errorf("duplicate package name %s in %s and %s", name, filepath.ToSlash(previous), filepath.ToSlash(packageDir))
			}
			byName[name] = packageDir
		}
	}
	return byName, nil
}

func readPackageManifest(repoRoot string, path string) (map[string]any, error) {
	source, err := readFileUnderRoot(repoRoot, path, "TypeScript public API package manifest")
	if err != nil {
		return nil, err
	}
	parsed, err := admission.DecodeJSON(strings.NewReader(string(source)), int64(len(source)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	record, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must contain a JSON object", path)
	}
	return record, nil
}

func readFileUnderRoot(repoRoot string, filePath string, context string) ([]byte, error) {
	resolved, err := resolvedPathUnderRoot(repoRoot, filePath, context)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

func resolvedPathUnderRoot(repoRoot string, filePath string, context string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(repoRoot, resolved)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%s must resolve inside repo root", context)
	}
	return resolved, nil
}

func safePackageRelativePath(path string, context string, sourcePrefix string, sourceExtension string) (string, error) {
	if filepath.IsAbs(path) ||
		strings.Contains(path, `\`) ||
		strings.ContainsRune(path, '\x00') ||
		path == "." ||
		path == ".." ||
		strings.HasPrefix(path, "../") ||
		strings.Contains(path, "/../") ||
		!strings.HasPrefix(path, sourcePrefix) ||
		!strings.HasSuffix(path, sourceExtension) {
		return "", fmt.Errorf("%s must be a package-relative %s*%s path without traversal", context, sourcePrefix, sourceExtension)
	}
	return path, nil
}

func CollectExports(source string) ([]string, []string, error) {
	runtimeExports := map[string]struct{}{}
	typeExports := map[string]struct{}{}
	for _, statement := range exportStatements(source) {
		if strings.HasPrefix(statement, "export *") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use export *")
		}
		if strings.HasPrefix(statement, "export default") || strings.HasPrefix(statement, "export =") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use default exports")
		}
		if strings.HasPrefix(statement, "export declare") {
			return nil, nil, fmt.Errorf("TypeScript public API entrypoints must not use ambient declare exports")
		}
		if match := typeExportPattern.FindStringSubmatch(statement); match != nil {
			addTypeClauseExports(match[1], typeExports)
			continue
		}
		if match := namedExportPattern.FindStringSubmatch(statement); match != nil {
			addNamedClauseExports(match[1], runtimeExports, typeExports)
			continue
		}
		if match := runtimeDeclPattern.FindStringSubmatch(statement); match != nil {
			runtimeExports[match[1]] = struct{}{}
			continue
		}
		if match := typeDeclPattern.FindStringSubmatch(statement); match != nil {
			typeExports[match[1]] = struct{}{}
			continue
		}
		if match := varDeclPattern.FindStringSubmatch(statement); match != nil {
			names, err := variableExportNames(match[1])
			if err != nil {
				return nil, nil, err
			}
			for _, name := range names {
				runtimeExports[name] = struct{}{}
			}
			continue
		}
		return nil, nil, fmt.Errorf("unsupported public export statement")
	}
	return sortedSet(runtimeExports), sortedSet(typeExports), nil
}

func exportStatements(source string) []string {
	statements := []string{}
	pending := []string{}
	for _, rawLine := range strings.Split(source, "\n") {
		line := strings.TrimSpace(rawLine)
		if len(pending) > 0 {
			pending = append(pending, line)
			if strings.Contains(line, ";") {
				statements = append(statements, strings.Join(pending, " "))
				pending = nil
			}
			continue
		}
		if !strings.HasPrefix(line, "export ") && line != "export" {
			continue
		}
		if startsMultilineReexport(line) && !strings.Contains(line, ";") {
			pending = append(pending, line)
			continue
		}
		statements = append(statements, line)
	}
	if len(pending) > 0 {
		statements = append(statements, strings.Join(pending, " "))
	}
	return statements
}

func startsMultilineReexport(line string) bool {
	return strings.HasPrefix(line, "export {") || strings.HasPrefix(line, "export type {")
}

func addTypeClauseExports(clause string, target map[string]struct{}) {
	addClauseExports(clause, nil, target, true)
}

func addNamedClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}) {
	addClauseExports(clause, runtimeTarget, typeTarget, false)
}

func addClauseExports(clause string, runtimeTarget map[string]struct{}, typeTarget map[string]struct{}, typeClause bool) {
	body := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(clause), "{"), "}")
	for _, rawPart := range strings.Split(body, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			continue
		}
		typeOnly := typeClause
		if isInlineTypeOnlyReexport(part) {
			typeOnly = true
			part = strings.TrimSpace(strings.TrimPrefix(part, "type "))
		}
		name := part
		if match := exportClauseNameRegex.FindStringSubmatch(part); match != nil {
			name = match[1]
		}
		if typeOnly {
			typeTarget[name] = struct{}{}
			continue
		}
		runtimeTarget[name] = struct{}{}
	}
}

func isInlineTypeOnlyReexport(part string) bool {
	if !strings.HasPrefix(part, "type ") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(part, "type "))
	return rest != "" && !strings.HasPrefix(rest, "as ")
}

func variableExportNames(declarations string) ([]string, error) {
	names := []string{}
	parts, err := splitTopLevelComma(declarations)
	if err != nil {
		return nil, err
	}
	for _, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if equals := strings.Index(part, "="); equals >= 0 {
			part = strings.TrimSpace(part[:equals])
		}
		if colon := strings.Index(part, ":"); colon >= 0 {
			part = strings.TrimSpace(part[:colon])
		}
		if !identifierRegex.MatchString(part) {
			return nil, fmt.Errorf("TypeScript public API variable exports must use identifier declarations")
		}
		names = append(names, part)
	}
	return names, nil
}

func splitTopLevelComma(value string) ([]string, error) {
	parts := []string{}
	start := 0
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	angleDepth := 0
	var quote rune
	escaped := false
	for index, char := range value {
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if char == '\\' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
			}
			continue
		}
		switch char {
		case '\'', '"', '`':
			quote = char
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '<':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				angleDepth++
			}
		case '>':
			if angleDepth > 0 {
				angleDepth--
			}
		case ',':
			if parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && angleDepth == 0 {
				parts = append(parts, value[start:index])
				start = index + len(string(char))
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("TypeScript public API variable exports must not contain unterminated string literals")
	}
	parts = append(parts, value[start:])
	return parts, nil
}

func verifyPackageExportMap(repoRoot string, packageDir string, item entry, failures *[]string) {
	manifest, err := readPackageManifest(repoRoot, filepath.Join(packageDir, "package.json"))
	if err != nil {
		*failures = append(*failures, err.Error())
		return
	}
	exportsField, ok := manifest["exports"].(map[string]any)
	if !ok {
		*failures = append(*failures, item.PackageName+" package.json must declare an exports object")
		return
	}
	exportEntry, ok := exportsField[item.ExportKey].(map[string]any)
	if !ok {
		*failures = append(*failures, fmt.Sprintf("%s package.json missing exports[%s]", item.PackageName, item.ExportKey))
		return
	}
	actualConditions := sortedKeys(exportEntry)
	expectedConditions := exportConditionNames(item.ExportConditions)
	sort.Strings(expectedConditions)
	compareExports(expectedConditions, actualConditions, fmt.Sprintf("%s exports[%s] conditions", item.PackageName, item.ExportKey), failures)
	for _, condition := range item.ExportConditions {
		if exportEntry[condition.Condition] != condition.Path {
			*failures = append(*failures, fmt.Sprintf("%s exports[%s].%s must be %s", item.PackageName, item.ExportKey, condition.Condition, condition.Path))
		}
		if !isAdmittedSourceExportTarget(item.Source, condition) {
			*failures = append(*failures, fmt.Sprintf("%s exports[%s].%s target %s must match scanned source %s or its compiled target", item.PackageName, item.ExportKey, condition.Condition, condition.Path, "./"+item.Source))
		}
	}
	for _, deniedKey := range item.DeniedExportKeys {
		deniedValue, ok := exportsField[deniedKey]
		if !ok || deniedValue != nil {
			*failures = append(*failures, fmt.Sprintf("%s package.json exports[%s] must be denied with null", item.PackageName, deniedKey))
		}
	}
}

func isAdmittedSourceExportTarget(source string, condition exportCondition) bool {
	if condition.Path == "./"+source {
		return true
	}
	compiledTarget, ok := compiledExportTargetForSource(source, condition.Condition)
	return ok && condition.Path == compiledTarget
}

func compiledExportTargetForSource(source string, condition string) (string, bool) {
	if !strings.HasPrefix(source, "src/") || !strings.HasSuffix(source, ".ts") {
		return "", false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(source, "src/"), ".ts")
	if condition == "types" {
		return "./dist/" + stem + ".d.ts", true
	}
	return "./dist/" + stem + ".js", true
}

func verifyCoveredPackageExportKeys(repoRoot string, packages map[string]string, entries []entry, failures *[]string) {
	expectedByPackage := map[string]map[string]struct{}{}
	for _, item := range entries {
		keys := expectedByPackage[item.PackageName]
		if keys == nil {
			keys = map[string]struct{}{}
			expectedByPackage[item.PackageName] = keys
		}
		keys[item.ExportKey] = struct{}{}
		for _, denied := range item.DeniedExportKeys {
			keys[denied] = struct{}{}
		}
	}
	packageNames := make([]string, 0, len(expectedByPackage))
	for packageName := range expectedByPackage {
		packageNames = append(packageNames, packageName)
	}
	sort.Strings(packageNames)
	for _, packageName := range packageNames {
		expectedSet := expectedByPackage[packageName]
		packageDir, ok := packages[packageName]
		if !ok {
			continue
		}
		manifest, err := readPackageManifest(repoRoot, filepath.Join(packageDir, "package.json"))
		if err != nil {
			*failures = append(*failures, err.Error())
			continue
		}
		exportsField, ok := manifest["exports"].(map[string]any)
		if !ok {
			continue
		}
		compareExports(sortedSet(expectedSet), sortedKeys(exportsField), packageName+" package.json export keys", failures)
	}
}

func compareExports(expected []string, actual []string, label string, failures *[]string) {
	expectedSet := stringSet(expected)
	actualSet := stringSet(actual)
	missing := []string{}
	extra := []string{}
	for _, item := range expected {
		if _, ok := actualSet[item]; !ok {
			missing = append(missing, item)
		}
	}
	for _, item := range actual {
		if _, ok := expectedSet[item]; !ok {
			extra = append(extra, item)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		*failures = append(*failures, fmt.Sprintf("%s drift: missing=[%s] extra=[%s]", label, strings.Join(missing, ", "), strings.Join(extra, ", ")))
	}
}

func optionalStringArray(raw any, context string) ([]string, error) {
	if raw == nil {
		return []string{}, nil
	}
	return requiredSortedStringArray(raw, context)
}

func requiredSortedStringArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, err := nonEmptyString(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	if err := assertSortedUnique(result, context); err != nil {
		return nil, err
	}
	return result, nil
}

func assertSortedUnique(values []string, context string) error {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	for index := range values {
		if values[index] != sorted[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
		if index > 0 && values[index-1] == values[index] {
			return fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return nil
}

func nonEmptyString(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func exportConditionNames(conditions []exportCondition) []string {
	values := make([]string, 0, len(conditions))
	for _, condition := range conditions {
		values = append(values, condition.Condition)
	}
	return values
}

func sortedKeys(record map[string]any) []string {
	keys := make([]string, 0, len(record))
	for key := range record {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func stringSet(values []string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
