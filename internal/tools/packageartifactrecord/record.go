package packageartifactrecord

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	CommandID      = "proofkit.package-artifact"
	RecordPath     = "artifacts/proofkit/package-artifact-execution.json"
	SchemaVersion  = 1
	maxRecordBytes = 1 << 20
)

var (
	commandArgv   = []string{"npm", "run", "package:artifact"}
	executionArgv = []string{"npm", "run", "package:artifact:steps"}
)

var executionEnvironmentKeys = []string{
	"CGO_ENABLED",
	"CI",
	"GITHUB_ACTIONS",
	"GITHUB_REF_PROTECTED",
	"GOARCH",
	"GOFLAGS",
	"GOOS",
	"GOTOOLCHAIN",
	"LANG",
	"LC_ALL",
	"NPM_CONFIG_IGNORE_SCRIPTS",
	"PYTHONDONTWRITEBYTECODE",
	"PYTHONHASHSEED",
	"PYTHONOPTIMIZE",
	"SOURCE_DATE_EPOCH",
	"TZ",
	"npm_config_ignore_scripts",
}

var artifactEvidenceRoots = []string{
	"artifacts/package",
	"artifacts/pypi",
	"artifacts/release",
}

func CanonicalCommandArgv() []string {
	return append([]string(nil), commandArgv...)
}

func CanonicalExecutionArgv() []string {
	return append([]string(nil), executionArgv...)
}

type Record struct {
	Argv                            []string `json:"argv"`
	ArtifactFreshnessBaselineDigest string   `json:"artifactFreshnessBaselineDigest"`
	ArtifactFreshnessDigest         string   `json:"artifactFreshnessDigest"`
	ArtifactSnapshotDigest          string   `json:"artifactSnapshotDigest"`
	CommandID                       string   `json:"commandId"`
	EnvironmentDigest               string   `json:"environmentDigest"`
	ExecutionArgv                   []string `json:"executionArgv"`
	ExitCode                        int      `json:"exitCode"`
	FinishedAt                      string   `json:"finishedAt"`
	SchemaVersion                   int      `json:"schemaVersion"`
	SourceRevision                  string   `json:"sourceRevision"`
	SourceSnapshotDigest            string   `json:"sourceSnapshotDigest"`
	StartedAt                       string   `json:"startedAt"`
	Status                          string   `json:"status"`
	ToolchainDigest                 string   `json:"toolchainDigest"`
}

type ArtifactEvidence struct {
	FileCount       int
	FreshnessDigest string
	SnapshotDigest  string
}

func Read(root string) (Record, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(RecordPath)))
	if err != nil {
		return Record{}, err
	}
	defer file.Close()
	raw, err := admission.DecodeJSON(file, maxRecordBytes)
	if err != nil {
		return Record{}, err
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return Record{}, fmt.Errorf("package artifact execution record must be an object")
	}
	if err := admit.KnownKeys(object, []string{"argv", "artifactFreshnessBaselineDigest", "artifactFreshnessDigest", "artifactSnapshotDigest", "commandId", "environmentDigest", "executionArgv", "exitCode", "finishedAt", "schemaVersion", "sourceRevision", "sourceSnapshotDigest", "startedAt", "status", "toolchainDigest"}, "package artifact execution record"); err != nil {
		return Record{}, err
	}
	content, err := json.Marshal(raw)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(content, &record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Write(root string, record Record) error {
	value := map[string]any{
		"argv":                            stringsToAny(record.Argv),
		"artifactFreshnessBaselineDigest": record.ArtifactFreshnessBaselineDigest,
		"artifactFreshnessDigest":         record.ArtifactFreshnessDigest,
		"artifactSnapshotDigest":          record.ArtifactSnapshotDigest,
		"commandId":                       record.CommandID,
		"environmentDigest":               record.EnvironmentDigest,
		"executionArgv":                   stringsToAny(record.ExecutionArgv),
		"exitCode":                        record.ExitCode,
		"finishedAt":                      record.FinishedAt,
		"schemaVersion":                   record.SchemaVersion,
		"sourceRevision":                  record.SourceRevision,
		"sourceSnapshotDigest":            record.SourceSnapshotDigest,
		"startedAt":                       record.StartedAt,
		"status":                          record.Status,
		"toolchainDigest":                 record.ToolchainDigest,
	}
	content, err := stablejson.Marshal(value)
	if err != nil {
		return err
	}
	path := filepath.Join(root, filepath.FromSlash(RecordPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".package-artifact-execution-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func Invalidate(root string) error {
	err := os.Remove(filepath.Join(root, filepath.FromSlash(RecordPath)))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("invalidate package artifact execution record: %w", err)
	}
	return nil
}

func ValidateCurrent(root string, record Record) error {
	if record.SchemaVersion != SchemaVersion || record.CommandID != CommandID || !equalStrings(record.Argv, commandArgv) || !equalStrings(record.ExecutionArgv, executionArgv) {
		return fmt.Errorf("package artifact execution record identity is invalid")
	}
	if record.Status != "passed" || record.ExitCode != 0 || record.StartedAt == "" || record.FinishedAt == "" {
		return fmt.Errorf("package artifact execution record is not a successful execution")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, record.StartedAt)
	if err != nil {
		return fmt.Errorf("package artifact execution record startedAt must be RFC3339")
	}
	finishedAt, err := time.Parse(time.RFC3339Nano, record.FinishedAt)
	if err != nil || finishedAt.Before(startedAt) {
		return fmt.Errorf("package artifact execution record finishedAt must be RFC3339 and not precede startedAt")
	}
	if !isSHA256(record.SourceSnapshotDigest) ||
		!isSHA256(record.ArtifactSnapshotDigest) ||
		!isSHA256(record.ArtifactFreshnessBaselineDigest) ||
		!isSHA256(record.ArtifactFreshnessDigest) ||
		!isSHA256(record.EnvironmentDigest) ||
		!isSHA256(record.ToolchainDigest) {
		return fmt.Errorf("package artifact execution record snapshot digests must be lowercase sha256")
	}
	if record.ArtifactFreshnessBaselineDigest == record.ArtifactFreshnessDigest {
		return fmt.Errorf("package artifact execution record does not prove fresh artifacts")
	}
	revision, sourceDigest, err := SourceSnapshot(root)
	if err != nil {
		return err
	}
	if revision != record.SourceRevision || sourceDigest != record.SourceSnapshotDigest {
		return fmt.Errorf("package artifact execution record source snapshot is stale")
	}
	artifactEvidence, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		return err
	}
	if artifactEvidence.SnapshotDigest != record.ArtifactSnapshotDigest {
		return fmt.Errorf("package artifact execution record artifact snapshot is stale: recorded %s current %s", record.ArtifactSnapshotDigest, artifactEvidence.SnapshotDigest)
	}
	if artifactEvidence.FreshnessDigest != record.ArtifactFreshnessDigest {
		return fmt.Errorf("package artifact execution record artifact freshness is stale: recorded %s current %s", record.ArtifactFreshnessDigest, artifactEvidence.FreshnessDigest)
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func SourceSnapshot(root string) (string, string, error) {
	paths, err := gitPaths(root)
	if err != nil {
		return "", "", err
	}
	digest, err := digestPaths(root, paths)
	if err != nil {
		return "", "", err
	}
	head, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return "", "", err
	}
	status, err := gitOutput(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", "", err
	}
	revision := strings.TrimSpace(head)
	if strings.TrimSpace(status) != "" {
		revision += "+worktree.sha256:" + digest
	}
	return revision, digest, nil
}

func ArtifactSnapshot(root string) (string, error) {
	evidence, err := ArtifactEvidenceSnapshot(root)
	if err != nil {
		return "", err
	}
	return evidence.SnapshotDigest, nil
}

func ArtifactEvidenceBaseline(root string) (ArtifactEvidence, error) {
	return artifactEvidenceSnapshot(root, false)
}

func ArtifactEvidenceSnapshot(root string) (ArtifactEvidence, error) {
	return artifactEvidenceSnapshot(root, true)
}

func artifactEvidenceSnapshot(root string, requireFiles bool) (ArtifactEvidence, error) {
	paths := []string{}
	for _, relativeRoot := range artifactEvidenceRoots {
		artifactRoot := filepath.Join(root, filepath.FromSlash(relativeRoot))
		err := filepath.WalkDir(artifactRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				paths = append(paths, filepath.ToSlash(relative))
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return ArtifactEvidence{}, err
		}
	}
	if len(paths) == 0 {
		if !requireFiles {
			return emptyArtifactEvidence(), nil
		}
		return ArtifactEvidence{}, fmt.Errorf("package artifact execution produced no artifacts")
	}
	snapshotDigest, err := digestPaths(root, paths)
	if err != nil {
		return ArtifactEvidence{}, err
	}
	freshnessDigest, err := digestPathFreshness(root, paths)
	if err != nil {
		return ArtifactEvidence{}, err
	}
	return ArtifactEvidence{FileCount: len(paths), FreshnessDigest: freshnessDigest, SnapshotDigest: snapshotDigest}, nil
}

func emptyArtifactEvidence() ArtifactEvidence {
	emptyDigest := hex.EncodeToString(sha256.New().Sum(nil))
	return ArtifactEvidence{FreshnessDigest: emptyDigest, SnapshotDigest: emptyDigest}
}

func EnvironmentDigest(environment []string) string {
	byName := map[string]string{}
	for _, value := range environment {
		name, fieldValue, found := strings.Cut(value, "=")
		if found {
			byName[name] = fieldValue
		}
	}
	hash := sha256.New()
	for _, name := range executionEnvironmentKeys {
		writeDigestField(hash, []byte(name))
		writeDigestField(hash, []byte(byName[name]))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func ToolchainDigest() (string, error) {
	hash := sha256.New()
	writeDigestField(hash, []byte(runtime.GOOS))
	writeDigestField(hash, []byte(runtime.GOARCH))
	writeDigestField(hash, []byte(runtime.Version()))
	for _, name := range []string{"go", "node", "npm", "python3"} {
		path, err := exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("resolve toolchain executable %s: %w", name, err)
		}
		resolvedPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", fmt.Errorf("resolve toolchain executable target %s: %w", name, err)
		}
		absolutePath, err := filepath.Abs(resolvedPath)
		if err != nil {
			return "", err
		}
		info, content, err := readRegularFile(absolutePath)
		if err != nil {
			return "", fmt.Errorf("snapshot toolchain executable %s: %w", name, err)
		}
		writeDigestField(hash, []byte(name))
		writeDigestField(hash, []byte(filepath.ToSlash(filepath.Clean(absolutePath))))
		writeDigestField(hash, []byte(normalizedFileMode(info)))
		writeDigestField(hash, content)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func gitPaths(root string) ([]string, error) {
	command := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(output), "\x00")
	paths := make([]string, 0, len(parts))
	for _, path := range parts {
		if path != "" {
			paths = append(paths, filepath.ToSlash(path))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func gitOutput(root string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = root
	output, err := command.Output()
	return string(output), err
}

func digestPaths(root string, paths []string) (string, error) {
	orderedPaths := append([]string(nil), paths...)
	sort.Strings(orderedPaths)
	hash := sha256.New()
	for _, path := range orderedPaths {
		normalizedPath, fullPath, err := normalizedSnapshotPath(root, path)
		if err != nil {
			return "", err
		}
		info, content, err := readRegularFile(fullPath)
		if err != nil {
			return "", fmt.Errorf("snapshot %s: %w", normalizedPath, err)
		}
		writeDigestField(hash, []byte(normalizedPath))
		writeDigestField(hash, []byte("regular"))
		writeDigestField(hash, []byte(normalizedFileMode(info)))
		writeDigestField(hash, content)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestPathFreshness(root string, paths []string) (string, error) {
	orderedPaths := append([]string(nil), paths...)
	sort.Strings(orderedPaths)
	hash := sha256.New()
	for _, path := range orderedPaths {
		normalizedPath, fullPath, err := normalizedSnapshotPath(root, path)
		if err != nil {
			return "", err
		}
		info, _, err := readRegularFile(fullPath)
		if err != nil {
			return "", fmt.Errorf("snapshot freshness %s: %w", normalizedPath, err)
		}
		writeDigestField(hash, []byte(normalizedPath))
		writeDigestField(hash, []byte("regular"))
		writeDigestField(hash, []byte(normalizedFileMode(info)))
		writeDigestField(hash, []byte(fmt.Sprintf("%d", info.Size())))
		writeDigestField(hash, []byte(fmt.Sprintf("%d", info.ModTime().UnixNano())))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizedSnapshotPath(root string, path string) (string, string, error) {
	normalizedPath := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if normalizedPath == "." || filepath.IsAbs(filepath.FromSlash(path)) || normalizedPath == ".." || strings.HasPrefix(normalizedPath, "../") {
		return "", "", fmt.Errorf("snapshot path %q must be a normalized relative path", path)
	}
	if path != normalizedPath {
		return "", "", fmt.Errorf("snapshot path %q is not normalized as %q", path, normalizedPath)
	}
	return normalizedPath, filepath.Join(root, filepath.FromSlash(normalizedPath)), nil
}

func readRegularFile(path string) (fs.FileInfo, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("symlinks are not admitted")
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("non-regular files are not admitted: mode %s", info.Mode())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return info, content, nil
}

func normalizedFileMode(info fs.FileInfo) string {
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

func writeDigestField(hash interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write(value)
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
