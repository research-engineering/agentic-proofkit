package publicapi

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	defaultMachineContract  = "public_api_surfaces"
	maxSourceFileBytes      = 8 << 20
	maxPackageManifestBytes = 256 << 10
	maxAggregateScanBytes   = 64 << 20
	maxManifestEntries      = 1024
)

type Options struct {
	MachineContract string
	RepoRoot        string
}

type entry struct {
	DeniedExportKeys    []string
	ExportConditions    []exportCondition
	ExportKey           string
	PackageManifestPath string
	PackageName         string
	RuntimeExports      []string
	TypeExports         []string
}

type exportCondition struct {
	Condition  string
	Path       string
	SourcePath string
}

type packageSnapshot struct {
	dir      string
	manifest map[string]any
	name     string
}

type sourceExportSnapshot struct {
	runtimeExports []string
	typeExports    []string
}

type scanCache struct {
	repoRoot      string
	maxBytes      int64
	bytesRead     int64
	files         map[string][]byte
	sourceExports map[string]sourceExportSnapshot
}

func Verify(raw any, options Options) (map[string]any, int, error) {
	return verifyWithScanBudget(raw, options, maxAggregateScanBytes)
}

func verifyWithScanBudget(raw any, options Options, scanBudget int64) (map[string]any, int, error) {
	if options.MachineContract == "" {
		options.MachineContract = defaultMachineContract
	}
	repoRoot, err := filepath.EvalSymlinks(options.RepoRoot)
	if err != nil {
		return nil, 1, err
	}
	scan := newScanCache(repoRoot, scanBudget)
	manifest, err := admitManifest(raw, options.MachineContract)
	if err != nil {
		return nil, 1, err
	}
	packages, err := referencedPackages(scan, manifest)
	if err != nil {
		return nil, 1, err
	}
	failures := []string{}
	verifyCoveredPackageExportKeys(packages, manifest, &failures)
	seenKeys := map[string]struct{}{}
	for _, item := range manifest {
		manifestKey := item.PackageName + ":" + item.ExportKey
		if _, ok := seenKeys[manifestKey]; ok {
			failures = append(failures, "duplicate TypeScript public API manifest entry "+manifestKey)
			continue
		}
		seenKeys[manifestKey] = struct{}{}
		pkg, ok := packages[item.PackageManifestPath]
		if !ok {
			failures = append(failures, "TypeScript public API manifest references missing package manifest "+item.PackageManifestPath)
			continue
		}
		if pkg.name != item.PackageName {
			failures = append(failures, fmt.Sprintf("%s package manifest name is %s", manifestKey, pkg.name))
			continue
		}
		actualRuntimeSet := map[string]struct{}{}
		actualTypeSet := map[string]struct{}{}
		for _, sourcePath := range entrySourcePaths(item) {
			resolvedSource, err := resolvePackageSource(scan.repoRoot, pkg.dir, sourcePath, manifestKey+" source")
			if err != nil {
				if os.IsNotExist(err) {
					failures = append(failures, fmt.Sprintf("%s source does not exist: %s", manifestKey, sourcePath))
					continue
				}
				return nil, 1, err
			}
			actualRuntime, actualTypes, err := scan.collectSourceExports(resolvedSource, manifestKey+" source")
			if err != nil {
				return nil, 1, err
			}
			for _, value := range actualRuntime {
				actualRuntimeSet[value] = struct{}{}
			}
			for _, value := range actualTypes {
				actualTypeSet[value] = struct{}{}
			}
		}
		verifyPackageExportMap(pkg, item, &failures)
		compareExports(item.RuntimeExports, sortedSet(actualRuntimeSet), manifestKey+" runtime exports", &failures)
		compareExports(item.TypeExports, sortedSet(actualTypeSet), manifestKey+" type exports", &failures)
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
			"TypeScript source-to-export-condition mappings are caller-owned manifest facts; this command does not prove compiler output provenance.",
			"TypeScript public API verification does not parse JSX or admit TSX source files.",
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
	if len(values) > maxManifestEntries {
		return nil, fmt.Errorf("TypeScript public API manifest exceeds the %d-entry limit", maxManifestEntries)
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
	if err := admit.KnownKeys(record, []string{"deniedExportKeys", "exportConditions", "exportKey", "packageManifestPath", "packageName", "runtimeExports", "typeExports"}, context); err != nil {
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
	packageManifestPath, err := safeRepoPath(record["packageManifestPath"], context+".packageManifestPath")
	if err != nil {
		return entry{}, err
	}
	if filepath.Base(filepath.FromSlash(packageManifestPath)) != "package.json" {
		return entry{}, fmt.Errorf("%s.packageManifestPath must identify package.json", context)
	}
	exportKey, err := nonEmptyString(record["exportKey"], context+".exportKey")
	if err != nil {
		return entry{}, err
	}
	return entry{
		DeniedExportKeys: denied, ExportConditions: conditions, ExportKey: exportKey,
		PackageManifestPath: packageManifestPath, PackageName: packageName, RuntimeExports: runtimeExports, TypeExports: typeExports,
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
		if err := admit.KnownKeys(record, []string{"condition", "path", "sourcePath"}, fmt.Sprintf("%s[%d]", context, index)); err != nil {
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
		sourcePath, err := safeTypeScriptSourcePath(record["sourcePath"], fmt.Sprintf("%s[%d].sourcePath", context, index))
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, exportCondition{Condition: condition, Path: path, SourcePath: sourcePath})
	}
	if err := assertSortedUnique(exportConditionNames(conditions), context+" conditions"); err != nil {
		return nil, err
	}
	return conditions, nil
}

func referencedPackages(scan *scanCache, entries []entry) (map[string]packageSnapshot, error) {
	byManifest := map[string]packageSnapshot{}
	manifestByName := map[string]string{}
	for _, item := range entries {
		if _, exists := byManifest[item.PackageManifestPath]; exists {
			continue
		}
		manifestPath := filepath.Join(scan.repoRoot, filepath.FromSlash(item.PackageManifestPath))
		resolvedManifest, err := resolvedPathUnderRoot(scan.repoRoot, manifestPath, "TypeScript public API package manifest")
		if err != nil {
			return nil, err
		}
		manifest, err := readPackageManifest(scan, resolvedManifest)
		if err != nil {
			return nil, err
		}
		name, err := nonEmptyString(manifest["name"], item.PackageManifestPath+" name")
		if err != nil {
			return nil, err
		}
		if previous, exists := manifestByName[name]; exists && previous != item.PackageManifestPath {
			return nil, fmt.Errorf("duplicate referenced package name %s in %s and %s", name, previous, item.PackageManifestPath)
		}
		manifestByName[name] = item.PackageManifestPath
		byManifest[item.PackageManifestPath] = packageSnapshot{dir: filepath.Dir(resolvedManifest), manifest: manifest, name: name}
	}
	return byManifest, nil
}

func readPackageManifest(scan *scanCache, path string) (map[string]any, error) {
	source, _, err := scan.readFile(path, "TypeScript public API package manifest", maxPackageManifestBytes)
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

func newScanCache(repoRoot string, maxBytes int64) *scanCache {
	return &scanCache{
		repoRoot:      repoRoot,
		maxBytes:      maxBytes,
		files:         map[string][]byte{},
		sourceExports: map[string]sourceExportSnapshot{},
	}
}

func (scan *scanCache) readFile(filePath string, context string, maxFileBytes int64) ([]byte, string, error) {
	resolved, err := resolvedPathUnderRoot(scan.repoRoot, filePath, context)
	if err != nil {
		return nil, "", err
	}
	if content, ok := scan.files[resolved]; ok {
		if int64(len(content)) > maxFileBytes {
			return nil, "", fmt.Errorf("%s exceeds the %s file limit", context, byteLimitLabel(maxFileBytes))
		}
		return content, resolved, nil
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	remaining := scan.maxBytes - scan.bytesRead
	readLimit := maxFileBytes
	if remaining < readLimit {
		readLimit = remaining
	}
	if readLimit < 0 {
		readLimit = 0
	}
	content, err := io.ReadAll(io.LimitReader(file, readLimit+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(content)) > readLimit {
		if maxFileBytes <= remaining {
			return nil, "", fmt.Errorf("%s exceeds the %s file limit", context, byteLimitLabel(maxFileBytes))
		}
		return nil, "", fmt.Errorf("TypeScript public API scan exceeds the %s aggregate file-read limit", byteLimitLabel(scan.maxBytes))
	}
	scan.bytesRead += int64(len(content))
	scan.files[resolved] = content
	return content, resolved, nil
}

func (scan *scanCache) collectSourceExports(filePath string, context string) ([]string, []string, error) {
	source, resolved, err := scan.readFile(filePath, context, maxSourceFileBytes)
	if err != nil {
		return nil, nil, err
	}
	if snapshot, ok := scan.sourceExports[resolved]; ok {
		return snapshot.runtimeExports, snapshot.typeExports, nil
	}
	runtimeExports, typeExports, err := CollectExports(string(source))
	if err != nil {
		return nil, nil, err
	}
	scan.sourceExports[resolved] = sourceExportSnapshot{runtimeExports: runtimeExports, typeExports: typeExports}
	return runtimeExports, typeExports, nil
}

func byteLimitLabel(limit int64) string {
	if limit%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB", limit/(1<<20))
	}
	if limit%(1<<10) == 0 {
		return fmt.Sprintf("%d KiB", limit/(1<<10))
	}
	return fmt.Sprintf("%d-byte", limit)
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

func safeRepoPath(raw any, context string) (string, error) {
	value, err := nonEmptyString(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func safeTypeScriptSourcePath(raw any, context string) (string, error) {
	value, err := safeRepoPath(raw, context)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(filepath.Ext(filepath.FromSlash(value))) {
	case ".ts", ".mts", ".cts":
		return value, nil
	default:
		return "", fmt.Errorf("%s must identify a non-JSX TypeScript source (.ts, .mts, or .cts)", context)
	}
}

func resolvePackageSource(repoRoot string, packageDir string, sourcePath string, context string) (string, error) {
	resolved, err := resolvedPathUnderRoot(repoRoot, filepath.Join(repoRoot, filepath.FromSlash(sourcePath)), context)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(packageDir, resolved)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("%s must resolve under its referenced package manifest directory", context)
	}
	return resolved, nil
}

func verifyPackageExportMap(pkg packageSnapshot, item entry, failures *[]string) {
	exportsField, ok := pkg.manifest["exports"].(map[string]any)
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
	}
	for _, deniedKey := range item.DeniedExportKeys {
		deniedValue, ok := exportsField[deniedKey]
		if !ok || deniedValue != nil {
			*failures = append(*failures, fmt.Sprintf("%s package.json exports[%s] must be denied with null", item.PackageName, deniedKey))
		}
	}
}

func verifyCoveredPackageExportKeys(packages map[string]packageSnapshot, entries []entry, failures *[]string) {
	expectedByPackage := map[string]map[string]struct{}{}
	for _, item := range entries {
		keys := expectedByPackage[item.PackageManifestPath]
		if keys == nil {
			keys = map[string]struct{}{}
			expectedByPackage[item.PackageManifestPath] = keys
		}
		keys[item.ExportKey] = struct{}{}
		for _, denied := range item.DeniedExportKeys {
			keys[denied] = struct{}{}
		}
	}
	packagePaths := make([]string, 0, len(expectedByPackage))
	for packagePath := range expectedByPackage {
		packagePaths = append(packagePaths, packagePath)
	}
	sort.Strings(packagePaths)
	for _, packagePath := range packagePaths {
		expectedSet := expectedByPackage[packagePath]
		pkg, ok := packages[packagePath]
		if !ok {
			continue
		}
		exportsField, ok := pkg.manifest["exports"].(map[string]any)
		if !ok {
			continue
		}
		compareExports(sortedSet(expectedSet), sortedKeys(exportsField), pkg.name+" package.json export keys", failures)
	}
}

func entrySourcePaths(item entry) []string {
	set := map[string]struct{}{}
	for _, condition := range item.ExportConditions {
		set[condition.SourcePath] = struct{}{}
	}
	return sortedSet(set)
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
