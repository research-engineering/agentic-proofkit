package publicapi

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	pathpkg "path"
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
	root     *os.Root
}

type sourceExportSnapshot struct {
	runtimeExports []string
	typeExports    []string
	digest         [sha256.Size]byte
	identity       os.FileInfo
}

type admittedFileSnapshot struct {
	canonical string
	content   string
	digest    [sha256.Size]byte
	identity  os.FileInfo
}

type scanCache struct {
	root          *os.Root
	repoRoot      string
	initErr       error
	maxBytes      int64
	bytesRead     int64
	files         map[string]admittedFileSnapshot
	sourceExports map[string]sourceExportSnapshot
}

var scanAdmissionBarrier func(stage string, lexicalPath string)

func Verify(raw any, options Options) (map[string]any, int, error) {
	return verifyWithScanBudget(raw, options, maxAggregateScanBytes)
}

func verifyWithScanBudget(raw any, options Options, scanBudget int64) (map[string]any, int, error) {
	if options.MachineContract == "" {
		options.MachineContract = defaultMachineContract
	}
	scan := newScanCache(options.RepoRoot, scanBudget)
	if scan.initErr != nil {
		return nil, 1, scan.initErr
	}
	defer scan.root.Close()
	manifest, err := admitManifest(raw, options.MachineContract)
	if err != nil {
		return nil, 1, err
	}
	packages, err := referencedPackages(scan, manifest)
	if err != nil {
		return nil, 1, err
	}
	defer closePackageRoots(packages)
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
			actualRuntime, actualTypes, err := scan.collectSourceExports(sourcePath, pkg, manifestKey+" source")
			if err != nil {
				if os.IsNotExist(err) {
					failures = append(failures, fmt.Sprintf("%s source does not exist: %s", manifestKey, sourcePath))
					continue
				}
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
			"TypeScript public API verification admits a documented fail-closed export grammar subset; it does not parse unrestricted TypeScript.",
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

func referencedPackages(scan *scanCache, entries []entry) (_ map[string]packageSnapshot, returnErr error) {
	byManifest := map[string]packageSnapshot{}
	defer func() {
		if returnErr != nil {
			closePackageRoots(byManifest)
		}
	}()
	manifestByName := map[string]string{}
	for _, item := range entries {
		if _, exists := byManifest[item.PackageManifestPath]; exists {
			continue
		}
		manifest, _, packageDir, packageRoot, err := readPackageManifest(scan, item.PackageManifestPath)
		if err != nil {
			return nil, err
		}
		name, err := nonEmptyString(manifest["name"], item.PackageManifestPath+" name")
		if err != nil {
			_ = packageRoot.Close()
			return nil, err
		}
		if previous, exists := manifestByName[name]; exists && previous != item.PackageManifestPath {
			packageRoot.Close()
			return nil, fmt.Errorf("duplicate referenced package name %s in %s and %s", name, previous, item.PackageManifestPath)
		}
		manifestByName[name] = item.PackageManifestPath
		byManifest[item.PackageManifestPath] = packageSnapshot{dir: packageDir, manifest: manifest, name: name, root: packageRoot}
	}
	return byManifest, nil
}

func readPackageManifest(scan *scanCache, path string) (_ map[string]any, _ admittedFileSnapshot, _ string, _ *os.Root, returnErr error) {
	const context = "TypeScript public API package manifest"
	lexical, err := scan.relativePath(path, context)
	if err != nil {
		return nil, admittedFileSnapshot{}, "", nil, err
	}
	packageDir := pathpkg.Dir(lexical)
	root, err := scan.root.OpenRoot(filepath.FromSlash(packageDir))
	if err != nil {
		return nil, admittedFileSnapshot{}, "", nil, fmt.Errorf("open referenced package root %s: %w", packageDir, err)
	}
	defer func() {
		if returnErr != nil {
			_ = root.Close()
		}
	}()
	snapshot, err := scan.readRelativeFileSnapshot(
		root,
		lexical,
		pathpkg.Base(lexical),
		packageDir,
		context,
		maxPackageManifestBytes,
	)
	if err != nil {
		return nil, admittedFileSnapshot{}, "", nil, err
	}
	parsed, err := admission.DecodeJSON(strings.NewReader(snapshot.content), int64(len(snapshot.content)))
	if err != nil {
		return nil, admittedFileSnapshot{}, "", nil, fmt.Errorf("%s: %w", path, err)
	}
	record, ok := parsed.(map[string]any)
	if !ok {
		return nil, admittedFileSnapshot{}, "", nil, fmt.Errorf("%s must contain a JSON object", path)
	}
	return record, snapshot, packageDir, root, nil
}

func closePackageRoots(packages map[string]packageSnapshot) {
	for _, pkg := range packages {
		if pkg.root != nil {
			_ = pkg.root.Close()
		}
	}
}

func newScanCache(repoRoot string, maxBytes int64) *scanCache {
	root, err := os.OpenRoot(repoRoot)
	return &scanCache{
		root:          root,
		repoRoot:      repoRoot,
		initErr:       err,
		maxBytes:      maxBytes,
		files:         map[string]admittedFileSnapshot{},
		sourceExports: map[string]sourceExportSnapshot{},
	}
}

func (scan *scanCache) readFile(filePath string, context string, maxFileBytes int64) (string, string, error) {
	snapshot, err := scan.readFileSnapshot(filePath, context, maxFileBytes)
	if err != nil {
		return "", "", err
	}
	return snapshot.content, snapshot.canonical, nil
}

func (scan *scanCache) readFileSnapshot(filePath string, context string, maxFileBytes int64) (admittedFileSnapshot, error) {
	if scan.initErr != nil {
		return admittedFileSnapshot{}, scan.initErr
	}
	lexical, err := scan.relativePath(filePath, context)
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	return scan.readRelativeFileSnapshot(scan.root, lexical, lexical, "", context, maxFileBytes)
}

func (scan *scanCache) readFileSnapshotUnder(filePath string, pkg packageSnapshot, context string, maxFileBytes int64) (admittedFileSnapshot, error) {
	if scan.initErr != nil {
		return admittedFileSnapshot{}, scan.initErr
	}
	lexical, err := scan.relativePath(filePath, context)
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	if pkg.root == nil || !pathWithin(pkg.dir, lexical) {
		return admittedFileSnapshot{}, fmt.Errorf("%s must identify a file under its referenced package manifest directory", context)
	}
	packageRelative := strings.TrimPrefix(lexical, strings.TrimSuffix(pkg.dir, "/")+"/")
	return scan.readRelativeFileSnapshot(pkg.root, lexical, packageRelative, pkg.dir, context, maxFileBytes)
}

func (scan *scanCache) readRelativeFileSnapshot(root *os.Root, lexical string, rootRelative string, canonicalPrefix string, context string, maxFileBytes int64) (admittedFileSnapshot, error) {
	if snapshot, ok := scan.files[lexical]; ok {
		if int64(len(snapshot.content)) > maxFileBytes {
			return admittedFileSnapshot{}, fmt.Errorf("%s exceeds the %s file limit", context, byteLimitLabel(maxFileBytes))
		}
		return snapshot, nil
	}
	canonicalRelative, err := canonicalRelativePath(root, rootRelative, context)
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	canonical := canonicalRelative
	if canonicalPrefix != "" {
		canonical = pathpkg.Join(canonicalPrefix, canonicalRelative)
	}
	if scanAdmissionBarrier != nil {
		scanAdmissionBarrier("canonical_resolved", lexical)
	}
	file, err := root.Open(filepath.FromSlash(rootRelative))
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	defer file.Close()
	canonicalFile, err := root.Open(filepath.FromSlash(canonicalRelative))
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	canonicalInfo, err := canonicalFile.Stat()
	if closeErr := canonicalFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	before, err := file.Stat()
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	if !before.Mode().IsRegular() {
		return admittedFileSnapshot{}, fmt.Errorf("%s must identify a regular file", context)
	}
	if !os.SameFile(before, canonicalInfo) {
		return admittedFileSnapshot{}, fmt.Errorf("%s changed identity during confined admission", context)
	}
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
		return admittedFileSnapshot{}, err
	}
	if int64(len(content)) > readLimit {
		if maxFileBytes <= remaining {
			return admittedFileSnapshot{}, fmt.Errorf("%s exceeds the %s file limit", context, byteLimitLabel(maxFileBytes))
		}
		return admittedFileSnapshot{}, fmt.Errorf("TypeScript public API scan exceeds the %s aggregate file-read limit", byteLimitLabel(scan.maxBytes))
	}
	after, err := file.Stat()
	if err != nil {
		return admittedFileSnapshot{}, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || after.Size() != int64(len(content)) {
		return admittedFileSnapshot{}, fmt.Errorf("%s changed identity or size during confined read", context)
	}
	scan.bytesRead += int64(len(content))
	snapshot := admittedFileSnapshot{
		canonical: canonical,
		content:   string(content),
		digest:    sha256.Sum256(content),
		identity:  before,
	}
	scan.files[lexical] = snapshot
	return snapshot, nil
}

func (scan *scanCache) collectSourceExports(filePath string, pkg packageSnapshot, context string) ([]string, []string, error) {
	admitted, err := scan.readFileSnapshotUnder(filePath, pkg, context, maxSourceFileBytes)
	if err != nil {
		return nil, nil, err
	}
	if !pathWithin(pkg.dir, admitted.canonical) {
		return nil, nil, fmt.Errorf("%s must resolve under its referenced package manifest directory", context)
	}
	if err := requireTypeScriptSourceExtension(admitted.canonical, context+" canonical target"); err != nil {
		return nil, nil, err
	}
	if snapshot, ok := scan.sourceExports[admitted.canonical]; ok {
		if !os.SameFile(snapshot.identity, admitted.identity) || snapshot.digest != admitted.digest {
			return nil, nil, fmt.Errorf("%s canonical source changed identity or content during scan", context)
		}
		return append([]string(nil), snapshot.runtimeExports...), append([]string(nil), snapshot.typeExports...), nil
	}
	runtimeExports, typeExports, err := CollectExports(admitted.content)
	if err != nil {
		return nil, nil, err
	}
	scan.sourceExports[admitted.canonical] = sourceExportSnapshot{
		runtimeExports: append([]string(nil), runtimeExports...),
		typeExports:    append([]string(nil), typeExports...),
		digest:         admitted.digest,
		identity:       admitted.identity,
	}
	return append([]string(nil), runtimeExports...), append([]string(nil), typeExports...), nil
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

func (scan *scanCache) relativePath(filePath string, context string) (string, error) {
	value := filePath
	if filepath.IsAbs(value) {
		relative, err := filepath.Rel(scan.repoRoot, value)
		if err != nil {
			return "", fmt.Errorf("%s must resolve inside repo root", context)
		}
		value = relative
	}
	value = filepath.ToSlash(filepath.Clean(value))
	if value == "." {
		return "", fmt.Errorf("%s must identify a file under repo root", context)
	}
	relative, err := admit.SafeRepoRelativePath(value, context)
	if err != nil {
		return "", fmt.Errorf("%s must resolve inside repo root", context)
	}
	return relative, nil
}

func (scan *scanCache) canonicalRelativePath(lexical string, context string) (string, error) {
	return canonicalRelativePath(scan.root, lexical, context)
}

func canonicalRelativePath(root *os.Root, lexical string, context string) (string, error) {
	pending := strings.Split(lexical, "/")
	resolved := []string{}
	for links := 0; len(pending) > 0; {
		component := pending[0]
		pending = pending[1:]
		candidate := pathpkg.Join(append(resolved, component)...)
		info, err := root.Lstat(filepath.FromSlash(candidate))
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			resolved = append(resolved, component)
			continue
		}
		links++
		if links > 255 {
			return "", fmt.Errorf("%s contains too many symlink traversals", context)
		}
		target, err := root.Readlink(filepath.FromSlash(candidate))
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			return "", fmt.Errorf("%s uses an absolute symlink target; use a relative in-root symlink", context)
		}
		combined := pathpkg.Join(append([]string{pathpkg.Dir(candidate), filepath.ToSlash(target)}, pending...)...)
		safe, err := admit.SafeRepoRelativePath(combined, context)
		if err != nil {
			return "", fmt.Errorf("%s must resolve inside repo root", context)
		}
		pending = strings.Split(safe, "/")
		resolved = nil
	}
	if len(resolved) == 0 {
		return "", fmt.Errorf("%s must identify a file under repo root", context)
	}
	return pathpkg.Join(resolved...), nil
}

func pathWithin(parent, child string) bool {
	if parent == "." || parent == "" {
		return child != "." && child != ""
	}
	return child != parent && strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/")
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
	if err := requireTypeScriptSourceExtension(value, context); err != nil {
		return "", err
	}
	return value, nil
}

func requireTypeScriptSourceExtension(path string, context string) error {
	switch strings.ToLower(filepath.Ext(filepath.FromSlash(path))) {
	case ".ts", ".mts", ".cts":
		return nil
	default:
		return fmt.Errorf("%s must identify a non-JSX TypeScript source (.ts, .mts, or .cts)", context)
	}
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
