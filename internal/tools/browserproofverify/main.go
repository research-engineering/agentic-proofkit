package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const proofPath = "artifacts/proofkit/browser-runtime-proof.json"

var proofNonClaims = []string{
	"This record proves only that the listed content-bound Playwright tests passed in each recorded project before record creation.",
	"Playwright WebKit is not branded Safari compatibility proof.",
	"This record does not prove registry publication, rollout, or production readiness.",
	"A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
	"This record does not independently authenticate or sandbox the same-user proof runner, external toolchain packages, or browser binaries.",
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "--admit-playwright-report" {
		root, err := os.Getwd()
		if err == nil {
			err = writeAdmittedPlaywrightReport(root, os.Args[2])
		}
		if err != nil {
			exit(err)
		}
		return
	}
	root, err := repositoryRoot()
	if err != nil {
		exit(err)
	}
	switch {
	case len(os.Args) == 1:
		err = verifyCurrentProof(root)
	case len(os.Args) == 2 && os.Args[1] == "--resolve-inputs":
		err = writeCurrentInputResolution(root)
	case len(os.Args) == 2 && os.Args[1] == "--run":
		err = runBrowserProof(root)
	default:
		err = fmt.Errorf("usage: browserproofverify [--resolve-inputs | --run | --admit-playwright-report PATH]")
	}
	if err != nil {
		exit(err)
	}
}

func verifyCurrentProof(root string) error {
	manifest, err := loadProofInputManifest(root)
	if err != nil {
		return err
	}
	resolution, err := resolveProofInputs(root, manifest)
	if err != nil {
		return err
	}
	revision, state, err := currentSourceIdentity(root)
	if err != nil {
		return err
	}
	value, err := readRootedJSON(root, proofPath, 8<<20)
	if err != nil {
		return err
	}
	return verifyRecord(root, value, resolution, revision, state)
}

func writeCurrentInputResolution(root string) error {
	manifest, err := loadProofInputManifest(root)
	if err != nil {
		return err
	}
	resolution, err := resolveProofInputs(root, manifest)
	if err != nil {
		return err
	}
	encoded, err := encodeInputResolution(resolution)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(encoded)
	return err
}

func runBrowserProof(root string) (resultErr error) {
	manifest, err := loadProofInputManifest(root)
	if err != nil {
		return err
	}
	resolution, err := resolveProofInputs(root, manifest)
	if err != nil {
		return err
	}
	encoded, err := encodeInputResolution(resolution)
	if err != nil {
		return err
	}
	runPaths, err := prepareBrowserProofRun(root)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := cleanupBrowserProofRun(root, runPaths.RunDirectory); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clean browser proof run directory: %w", cleanupErr))
		}
	}()
	command := exec.Command("node", manifest.WriterPath)
	command.Dir = root
	environment := withEnvironmentValue(os.Environ(), proofInputResolutionEnvironment, strings.TrimSpace(string(encoded)))
	environment = withEnvironmentValue(environment, browserRunDirectoryEnvironment, runPaths.RunDirectory)
	environment = withEnvironmentValue(environment, browserProofCandidateEnvironment, runPaths.CandidatePath)
	command.Env = environment
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run browser proof writer: %w", err)
	}
	value, err := readRootedJSON(root, runPaths.CandidatePath, 8<<20)
	if err != nil {
		return fmt.Errorf("read browser proof candidate: %w", err)
	}
	revision, state, err := currentSourceIdentity(root)
	if err != nil {
		return err
	}
	if err := verifyRecord(root, value, resolution, revision, state); err != nil {
		return fmt.Errorf("admit browser proof candidate: %w", err)
	}
	if err := writeRootedJSON(root, proofPath, value); err != nil {
		return fmt.Errorf("write browser runtime proof: %w", err)
	}
	return verifyCurrentProof(root)
}

func currentSourceIdentity(root string) (string, string, error) {
	revision, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	status, err := gitOutput(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", "", err
	}
	state := "clean"
	if status != "" {
		state = "dirty"
	}
	return revision, state, nil
}

func encodeInputResolution(resolution proofInputResolution) ([]byte, error) {
	paths := make([]any, len(resolution.InputPaths))
	for index, path := range resolution.InputPaths {
		paths[index] = path
	}
	return stablejson.MarshalLayout(map[string]any{
		"inputPaths":    paths,
		"schemaVersion": 1,
		"serverTarget":  resolution.ServerTarget,
		"writerPath":    resolution.WriterPath,
	}, stablejson.LayoutCompact)
}

func withEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if !strings.HasPrefix(entry, prefix) {
			result = append(result, entry)
		}
	}
	return append(result, prefix+value)
}

func verifyRecord(root string, raw any, expectedResolution proofInputResolution, revision, treeState string) error {
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("browser runtime proof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"assets", "command", "engines", "inputDigest", "inputResolution", "nonClaims", "projects", "proofKind", "schemaVersion", "sourceRevision", "sourceTreeState", "state"}, "browser runtime proof"); err != nil {
		return err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 2) || record["proofKind"] != "proofkit.browser-runtime-proof" || record["state"] != "passed" || record["sourceRevision"] != revision || record["sourceTreeState"] != treeState {
		return fmt.Errorf("browser runtime proof identity or source state is invalid")
	}
	if err := exactTextArray(record["nonClaims"], proofNonClaims, "browser runtime proof nonClaims"); err != nil {
		return err
	}
	command, ok := record["command"].(map[string]any)
	if !ok || admit.KnownKeys(command, []string{"argv", "exitCode", "inputMode", "runner"}, "browser runtime proof command") != nil || command["inputMode"] != "materialized_snapshot" || command["runner"] != "node" || !admit.JSONNumberEquals(command["exitCode"], 0) {
		return fmt.Errorf("browser runtime proof command is invalid")
	}
	if err := exactTextArray(command["argv"], []string{"node_modules/@playwright/test/cli.js", "test"}, "browser runtime proof command argv"); err != nil {
		return err
	}
	inputResolution, ok := record["inputResolution"].(map[string]any)
	if !ok || admit.KnownKeys(inputResolution, []string{"serverTarget", "writerPath"}, "browser runtime proof inputResolution") != nil ||
		inputResolution["serverTarget"] != expectedResolution.ServerTarget || inputResolution["writerPath"] != expectedResolution.WriterPath {
		return fmt.Errorf("browser runtime proof input resolution is invalid")
	}
	assets, ok := record["assets"].([]any)
	if !ok || len(assets) != len(expectedResolution.InputPaths) {
		return fmt.Errorf("browser runtime proof assets do not match the input set")
	}
	identityAssets := make([]any, 0, len(assets))
	for index, rawAsset := range assets {
		asset, ok := rawAsset.(map[string]any)
		if !ok || admit.KnownKeys(asset, []string{"path", "sha256"}, "browser runtime proof asset") != nil || asset["path"] != expectedResolution.InputPaths[index] {
			return fmt.Errorf("browser runtime proof asset order or shape is invalid")
		}
		path, err := admit.SafeRepoRelativePath(expectedResolution.InputPaths[index], "browser runtime proof asset path")
		if err != nil {
			return err
		}
		sha, err := admit.LowercaseSHA256(asset["sha256"], "browser runtime proof asset sha256")
		if err != nil {
			return err
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		actual := sha256.Sum256(content)
		if sha != hex.EncodeToString(actual[:]) {
			return fmt.Errorf("browser runtime proof asset digest mismatch at %s", admit.RedactStructuralText(path))
		}
		identityAssets = append(identityAssets, map[string]any{"path": path, "sha256": sha})
	}
	encodedIdentity, err := json.Marshal(map[string]any{
		"assets": identityAssets,
		"inputResolution": map[string]any{
			"serverTarget": expectedResolution.ServerTarget,
			"writerPath":   expectedResolution.WriterPath,
		},
	})
	if err != nil {
		return err
	}
	expectedInputDigest := digest.SHA256TextRef(string(encodedIdentity))
	if record["inputDigest"] != expectedInputDigest {
		return fmt.Errorf("browser runtime proof inputDigest mismatch: got %s want %s", admit.RedactStructuralText(fmt.Sprint(record["inputDigest"])), expectedInputDigest)
	}
	engines, ok := record["engines"].([]any)
	if !ok || len(engines) != 3 {
		return fmt.Errorf("browser runtime proof must record three engines")
	}
	engineVersions := make([]string, len(engines))
	for index, name := range []string{"chromium", "firefox", "webkit"} {
		engine, ok := engines[index].(map[string]any)
		if !ok || admit.KnownKeys(engine, []string{"name", "version"}, "browser runtime proof engine") != nil || engine["name"] != name {
			return fmt.Errorf("browser runtime proof engine identity is invalid")
		}
		version, err := admit.NonEmptyText(engine["version"], "browser runtime proof engine version")
		if err != nil {
			return err
		}
		engineVersions[index] = version
	}
	projectVersions, err := verifyProjectExecutions(record["projects"])
	if err != nil {
		return err
	}
	if !slices.Equal(engineVersions, projectVersions) {
		return fmt.Errorf("browser runtime proof engine versions must come from the recorded project executions")
	}
	findings, err := secretjson.Scan(record, "browser_runtime_proof")
	if err != nil || len(findings) > 0 {
		return fmt.Errorf("browser runtime proof contains secret-shaped data")
	}
	return nil
}

func verifyProjectExecutions(raw any) ([]string, error) {
	projects, ok := raw.([]any)
	if !ok || len(projects) != 3 {
		return nil, fmt.Errorf("browser runtime proof must record three project executions")
	}
	var expectedTestIDs []string
	versions := make([]string, len(projects))
	for index, name := range []string{"chromium", "firefox", "webkit"} {
		project, ok := projects[index].(map[string]any)
		if !ok || admit.KnownKeys(project, []string{"browserName", "browserVersion", "executedTestCount", "name", "passedTestCount", "testIds"}, "browser runtime proof project") != nil || project["name"] != name || project["browserName"] != name {
			return nil, fmt.Errorf("browser runtime proof project identity is invalid")
		}
		version, err := admit.NonEmptyText(project["browserVersion"], "browser runtime proof project browserVersion")
		if err != nil {
			return nil, err
		}
		versions[index] = version
		executed, err := positiveJSONInteger(project["executedTestCount"], "browser runtime proof executedTestCount")
		if err != nil {
			return nil, err
		}
		passed, err := positiveJSONInteger(project["passedTestCount"], "browser runtime proof passedTestCount")
		if err != nil {
			return nil, err
		}
		testIDs, err := sortedUniqueTextArray(project["testIds"], "browser runtime proof testIds")
		if err != nil {
			return nil, err
		}
		if executed != passed || executed != len(testIDs) {
			return nil, fmt.Errorf("browser runtime proof project counts do not prove all recorded tests passed")
		}
		if index == 0 {
			expectedTestIDs = testIDs
		} else if !slices.Equal(testIDs, expectedTestIDs) {
			return nil, fmt.Errorf("browser runtime proof projects must record the same test identities")
		}
	}
	return versions, nil
}

func positiveJSONInteger(raw any, context string) (int, error) {
	number, ok := raw.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	value, err := strconv.Atoi(string(number))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", context)
	}
	return value, nil
}

func sortedUniqueTextArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty sorted unique array", context)
	}
	result := make([]string, len(values))
	for index, rawValue := range values {
		value, err := admit.NonEmptyText(rawValue, context)
		if err != nil {
			return nil, err
		}
		if index > 0 && value <= result[index-1] {
			return nil, fmt.Errorf("%s must be a non-empty sorted unique array", context)
		}
		result[index] = value
	}
	return result, nil
}

func collectInputPaths(root string, inputs []string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, input := range inputs {
		absolute := filepath.Join(root, filepath.FromSlash(input))
		info, err := os.Lstat(absolute)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("browser proof input selector must not be a symlink")
		}
		if info.Mode().IsRegular() {
			seen[input] = struct{}{}
			continue
		}
		err = filepath.WalkDir(absolute, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("browser proof input tree must not contain symlinks")
			}
			if entry.Type().IsRegular() {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				seen[filepath.ToSlash(relative)] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func exactTextArray(raw any, expected []string, context string) error {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return fmt.Errorf("%s must equal the owner-defined values", context)
	}
	for index, value := range values {
		if value != expected[index] {
			return fmt.Errorf("%s must equal the owner-defined values", context)
		}
	}
	return nil
}

func repositoryRoot() (string, error) {
	return gitOutput("", "rev-parse", "--show-toplevel")
}

func gitOutput(root string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, "browser runtime proof verification failed:", admit.RedactStructuralText(err.Error()))
	os.Exit(1)
}
