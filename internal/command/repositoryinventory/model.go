// Package repositoryinventory owns the bounded, read-only repository root
// inventory used by adoption planning.
package repositoryinventory

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	SchemaVersion = 1
	InventoryKind = "proofkit.repository-inventory"
	PolicyID      = "proofkit.repository-root-catalog.v1"

	MaximumRootEntries    = 4096
	MaximumFileBytes      = 1 << 20
	MaximumAggregateBytes = 8 << 20
	MaximumOutputBytes    = 128 << 10
)

const (
	OmissionNonText  = "non_text"
	OmissionOversize = "over_file_limit"
)

var boundaryNonClaims = []string{
	"Repository inventory records a bounded read observation and does not prove an atomic repository snapshot or continuing freshness.",
	"Repository inventory re-admission proves canonical structure and content identity; it does not authenticate scanner execution or filesystem origin.",
	"Repository inventory does not evaluate version-control trackedness, ignored state, manifest syntax, dependencies, source semantics, stack identity, requirement meaning, proof adequacy, merge readiness, release readiness, rollout, or production readiness.",
	"Unrecognized root entry names are used only for fixed-catalog membership and aggregate counting; their names and metadata are not retained or disclosed, and their file contents are not opened.",
}

type catalogItem struct {
	Path string
	Role string
}

var rootCatalog = [...]catalogItem{
	{Path: "AGENTS.md", Role: "agent_instructions"},
	{Path: "Cargo.lock", Role: "dependency_lock"},
	{Path: "Cargo.toml", Role: "ecosystem_manifest"},
	{Path: "Gemfile", Role: "ecosystem_manifest"},
	{Path: "Gemfile.lock", Role: "dependency_lock"},
	{Path: "README.md", Role: "human_overview"},
	{Path: "build.gradle", Role: "build_configuration"},
	{Path: "build.gradle.kts", Role: "build_configuration"},
	{Path: "bun.lock", Role: "dependency_lock"},
	{Path: "composer.json", Role: "ecosystem_manifest"},
	{Path: "composer.lock", Role: "dependency_lock"},
	{Path: "deno.json", Role: "ecosystem_manifest"},
	{Path: "deno.jsonc", Role: "ecosystem_manifest"},
	{Path: "go.mod", Role: "ecosystem_manifest"},
	{Path: "go.sum", Role: "dependency_lock"},
	{Path: "package-lock.json", Role: "dependency_lock"},
	{Path: "package.json", Role: "ecosystem_manifest"},
	{Path: "pnpm-lock.yaml", Role: "dependency_lock"},
	{Path: "poetry.lock", Role: "dependency_lock"},
	{Path: "pom.xml", Role: "ecosystem_manifest"},
	{Path: "pyproject.toml", Role: "ecosystem_manifest"},
	{Path: "requirements.txt", Role: "dependency_declaration"},
	{Path: "tsconfig.json", Role: "build_configuration"},
	{Path: "uv.lock", Role: "dependency_lock"},
	{Path: "yarn.lock", Role: "dependency_lock"},
}

type Entry struct {
	ByteLength    int
	ContentSHA256 string
	Path          string
	Role          string
	SyntaxState   string
}

type OmittedRecognizedEntry struct {
	Path   string
	Reason string
}

type Omissions struct {
	OmittedRecognized []OmittedRecognizedEntry
	RootEntryCount    int
	UnrecognizedCount int
}

type Snapshot struct {
	Entries     []Entry
	InventoryID string
	Omissions   Omissions
}

func CatalogPaths() []string {
	paths := make([]string, 0, len(rootCatalog))
	for _, item := range rootCatalog {
		paths = append(paths, item.Path)
	}
	return paths
}

func CatalogRole(path string) (string, bool) {
	index, found := slices.BinarySearchFunc(rootCatalog[:], path, func(item catalogItem, target string) int {
		switch {
		case item.Path < target:
			return -1
		case item.Path > target:
			return 1
		default:
			return 0
		}
	})
	if !found {
		return "", false
	}
	return rootCatalog[index].Role, true
}

func (snapshot Snapshot) JSONValue() map[string]any {
	entries := make([]any, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		entries = append(entries, entryValue(entry))
	}
	omitted := make([]any, 0, len(snapshot.Omissions.OmittedRecognized))
	for _, entry := range snapshot.Omissions.OmittedRecognized {
		omitted = append(omitted, map[string]any{"path": entry.Path, "reason": entry.Reason})
	}
	return map[string]any{
		"entries":       entries,
		"inventoryId":   snapshot.InventoryID,
		"inventoryKind": InventoryKind,
		"nonClaims":     admit.StringSliceToAny(boundaryNonClaims),
		"omissions": map[string]any{
			"omittedRecognized": omitted,
			"rootEntryCount":    json.Number(fmt.Sprintf("%d", snapshot.Omissions.RootEntryCount)),
			"unrecognizedCount": json.Number(fmt.Sprintf("%d", snapshot.Omissions.UnrecognizedCount)),
		},
		"policyId":      PolicyID,
		"schemaVersion": json.Number("1"),
		"scope": map[string]any{
			"class":               "root_catalog",
			"repositoryRootState": "caller_selected_not_disclosed",
			"versionControlState": "not_evaluated",
		},
	}
}

func entryValue(entry Entry) map[string]any {
	return map[string]any{
		"byteLength":    json.Number(fmt.Sprintf("%d", entry.ByteLength)),
		"contentSha256": entry.ContentSHA256,
		"path":          entry.Path,
		"role":          entry.Role,
		"syntaxState":   entry.SyntaxState,
	}
}

func identityValue(snapshot Snapshot) map[string]any {
	entries := make([]any, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		entries = append(entries, entryValue(entry))
	}
	omitted := make([]any, 0, len(snapshot.Omissions.OmittedRecognized))
	for _, entry := range snapshot.Omissions.OmittedRecognized {
		omitted = append(omitted, map[string]any{"path": entry.Path, "reason": entry.Reason})
	}
	return map[string]any{
		"entries": entries,
		"omissions": map[string]any{
			"omittedRecognized": omitted,
			"rootEntryCount":    json.Number(fmt.Sprintf("%d", snapshot.Omissions.RootEntryCount)),
			"unrecognizedCount": json.Number(fmt.Sprintf("%d", snapshot.Omissions.UnrecognizedCount)),
		},
		"policyId": PolicyID,
	}
}

func finalize(snapshot Snapshot) (Snapshot, error) {
	id, err := digest.StableJSONSHA256Ref(identityValue(snapshot))
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.InventoryID = id
	encoded, err := stablejson.Marshal(snapshot.JSONValue())
	if err != nil {
		return Snapshot{}, err
	}
	if len(encoded) > MaximumOutputBytes {
		return Snapshot{}, fmt.Errorf("repository inventory exceeds output byte limit")
	}
	return snapshot, nil
}
