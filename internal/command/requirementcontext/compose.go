package requirementcontext

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	maxSourceBytes = 4 << 20
	maxTotalBytes  = 12 << 20
)

type catalogSource struct {
	ExpectedDigest string
	Kind           string
	NodeID         string
	Path           string
	SourceRef      string
}

func Compose(repoRoot string, raw any) (map[string]any, error) {
	catalogID, entries, err := admitCatalog(raw)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	defer root.Close()
	projections := map[string]any{}
	requirementSources := []any{}
	requirementSourceIDs := map[string]struct{}{}
	requirementIDs := map[string]struct{}{}
	requirementSourceNodes := map[string]string{}
	treeRequirementSourceIDs := map[string]struct{}{}
	treeRequirementSourceNodes := map[string]map[string]struct{}{}
	sources := make([]Source, 0, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		value, content, currentDigest, err := readCatalogSource(root, entry.Path)
		if err != nil {
			return nil, err
		}
		totalBytes += len(content)
		if totalBytes > maxTotalBytes {
			return nil, fmt.Errorf("requirement context sources exceed total byte limit")
		}
		if entry.ExpectedDigest != "" && entry.ExpectedDigest != currentDigest {
			return nil, fmt.Errorf("requirement context expected digest mismatch")
		}
		switch entry.Kind {
		case "spec_tree":
			result, err := requirementspectree.Evaluate(value)
			if err != nil || result.ExitCode != 0 {
				return nil, fmt.Errorf("admit specification tree")
			}
			projections["specTree"] = requirementspectree.TreeValue(result.Tree)
			entry.SourceRef = "spec_tree:" + result.Tree.TreeID
			for _, node := range result.Tree.Nodes {
				for _, ref := range node.SourceRefs {
					if ref.SourceRole == "requirements" && ref.SourceID != "" {
						treeRequirementSourceIDs[ref.SourceID] = struct{}{}
						if treeRequirementSourceNodes[ref.SourceID] == nil {
							treeRequirementSourceNodes[ref.SourceID] = map[string]struct{}{}
						}
						treeRequirementSourceNodes[ref.SourceID][node.NodeID] = struct{}{}
					}
				}
			}
		case "requirement_source":
			result, err := requirementsourceadmission.Evaluate(value)
			if err != nil || result.ExitCode != 0 {
				return nil, fmt.Errorf("admit requirement source")
			}
			if _, exists := requirementSourceIDs[result.Source.SourceID]; exists {
				return nil, fmt.Errorf("requirement context requirement source ids must be unique")
			}
			requirementSources = append(requirementSources, requirementsourceadmission.SourceValue(result.Source))
			entry.SourceRef = result.Source.SourceID
			requirementSourceIDs[result.Source.SourceID] = struct{}{}
			requirementSourceNodes[result.Source.SourceID] = entry.NodeID
			for _, requirement := range result.Source.Requirements {
				if _, exists := requirementIDs[requirement.RequirementID]; exists {
					return nil, fmt.Errorf("requirement context requirement ids must be unique across sources")
				}
				requirementIDs[requirement.RequirementID] = struct{}{}
			}
		case "proof_binding":
			result, err := requirementbinding.Build(value)
			if err != nil || result.Record.State != "passed" {
				return nil, fmt.Errorf("admit proof binding")
			}
			projections["proofBinding"] = requirementbinding.InputValue(result.Input)
			entry.SourceRef = "proof_binding:" + result.Input.BindingID
		case "coverage":
			view, exitCode, err := requirementcoverageview.BuildJSON(value, requirementcoverageview.Options{})
			if err != nil || exitCode != 0 {
				return nil, fmt.Errorf("admit coverage input")
			}
			admittedView, err := requirementcoverageview.AdmitOutput(view)
			if err != nil {
				return nil, fmt.Errorf("admit coverage output: %w", err)
			}
			projections["coverage"] = admittedView
			entry.SourceRef = "coverage:" + admittedView["viewInputId"].(string)
		}
		sourceRole := ""
		if entry.Kind == "requirement_source" {
			sourceRole = "requirements"
		}
		sources = append(sources, Source{CurrentDigest: currentDigest, ExpectedDigest: entry.ExpectedDigest, Kind: entry.Kind, NodeID: entry.NodeID, Path: entry.Path, SourceRef: entry.SourceRef, SourceRole: sourceRole})
	}
	if len(requirementSources) == 0 || projections["specTree"] == nil {
		return nil, fmt.Errorf("requirement context requires a spec tree and at least one requirement source")
	}
	for sourceID := range requirementSourceIDs {
		if _, ok := treeRequirementSourceIDs[sourceID]; !ok {
			return nil, fmt.Errorf("requirement context source is not referenced by the specification tree")
		}
		if _, ok := treeRequirementSourceNodes[sourceID][requirementSourceNodes[sourceID]]; !ok {
			return nil, fmt.Errorf("requirement context source node does not match the specification tree")
		}
	}
	if proof, ok := projections["proofBinding"].(map[string]any); ok {
		for _, key := range []string{"requirements", "bindings"} {
			for _, rawValue := range proof[key].([]any) {
				requirementID := rawValue.(map[string]any)["requirementId"].(string)
				if _, exists := requirementIDs[requirementID]; !exists {
					return nil, fmt.Errorf("requirement context proof binding references a requirement outside the context")
				}
			}
		}
	}
	if coverage, ok := projections["coverage"].(map[string]any); ok {
		for _, rawValue := range coverage["requirementCoverage"].([]any) {
			requirementID := rawValue.(map[string]any)["requirementId"].(string)
			if _, exists := requirementIDs[requirementID]; !exists {
				return nil, fmt.Errorf("requirement context coverage references a requirement outside the context")
			}
		}
	}
	for sourceID := range treeRequirementSourceIDs {
		if _, ok := requirementSourceIDs[sourceID]; !ok {
			return nil, fmt.Errorf("requirement context specification tree references an unavailable requirement source")
		}
	}
	sort.Slice(requirementSources, func(left, right int) bool {
		return requirementSources[left].(map[string]any)["sourceId"].(string) < requirementSources[right].(map[string]any)["sourceId"].(string)
	})
	sort.Slice(sources, func(left, right int) bool { return sources[left].SourceRef < sources[right].SourceRef })
	projections["requirementSources"] = requirementSources
	verification := baselineVerification(sources)
	snapshot := Snapshot{BaselineVerification: verification, CatalogID: catalogID, Projections: projections, Sources: sources}
	identityValue := map[string]any{"catalogId": catalogID, "projections": projections, "sources": sourceIdentityValues(sources)}
	encoded, err := stablejson.Marshal(identityValue)
	if err != nil {
		return nil, err
	}
	snapshot.SnapshotID = digest.SHA256TextRef(string(encoded))
	output := SnapshotValue(snapshot)
	admitted, err := AdmitSnapshot(output)
	if err != nil {
		return nil, fmt.Errorf("self-admit composed requirement context: %w", err)
	}
	output = SnapshotValue(admitted)
	encoded, err = stablejson.Marshal(output)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxSnapshotBytes {
		return nil, fmt.Errorf("requirement context snapshot exceeds byte limit")
	}
	return output, nil
}

func admitCatalog(raw any) (string, []catalogSource, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("requirement context catalog must be an object")
	}
	if err := admit.KnownKeys(record, []string{"catalogId", "coverage", "proofBinding", "requirementSources", "schemaVersion", "specTree"}, "requirement context catalog"); err != nil {
		return "", nil, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return "", nil, fmt.Errorf("requirement context catalog schemaVersion must be 1")
	}
	catalogID, err := admit.RuleID(record["catalogId"], "requirement context catalogId")
	if err != nil {
		return "", nil, err
	}
	entries := []catalogSource{}
	specTree, err := admitCatalogEntry(record["specTree"], "spec_tree", "spec-tree")
	if err != nil {
		return "", nil, err
	}
	entries = append(entries, specTree)
	values, ok := record["requirementSources"].([]any)
	if !ok || len(values) == 0 {
		return "", nil, fmt.Errorf("requirement context catalog requirementSources must be a non-empty array")
	}
	for index, value := range values {
		entry, err := admitCatalogEntry(value, "requirement_source", fmt.Sprintf("requirement-source-%d", index+1))
		if err != nil {
			return "", nil, err
		}
		entries = append(entries, entry)
	}
	for _, optional := range []struct{ key, kind, ref string }{{"proofBinding", "proof_binding", "proof-binding"}, {"coverage", "coverage", "coverage"}} {
		if record[optional.key] != nil {
			entry, err := admitCatalogEntry(record[optional.key], optional.kind, optional.ref)
			if err != nil {
				return "", nil, err
			}
			entries = append(entries, entry)
		}
	}
	seenPaths := map[string]struct{}{}
	seenRefs := map[string]struct{}{}
	for _, entry := range entries {
		if _, exists := seenPaths[entry.Path]; exists {
			return "", nil, fmt.Errorf("requirement context catalog paths must be unique")
		}
		if _, exists := seenRefs[entry.SourceRef]; exists {
			return "", nil, fmt.Errorf("requirement context catalog source refs must be unique")
		}
		seenPaths[entry.Path] = struct{}{}
		seenRefs[entry.SourceRef] = struct{}{}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].SourceRef < entries[right].SourceRef })
	return catalogID, entries, nil
}

func admitCatalogEntry(raw any, kind, defaultRef string) (catalogSource, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return catalogSource{}, fmt.Errorf("requirement context catalog entry must be an object")
	}
	if err := admit.KnownKeys(record, []string{"expectedSourceDigest", "nodeId", "path", "sourceRef"}, "requirement context catalog entry"); err != nil {
		return catalogSource{}, err
	}
	pathText, err := admit.NonEmptyText(record["path"], "requirement context catalog entry path")
	if err != nil {
		return catalogSource{}, err
	}
	path, err := admit.SafeRepoRelativePath(pathText, "requirement context catalog entry path")
	if err != nil {
		return catalogSource{}, err
	}
	sourceRef := defaultRef
	if record["sourceRef"] != nil {
		sourceRef, err = admit.RuleID(record["sourceRef"], "requirement context catalog entry sourceRef")
		if err != nil {
			return catalogSource{}, err
		}
	}
	expected := ""
	if record["expectedSourceDigest"] != nil {
		expected, err = admitDigestRef(record["expectedSourceDigest"], "requirement context catalog entry expectedSourceDigest")
		if err != nil {
			return catalogSource{}, err
		}
	}
	nodeID := ""
	if kind == "requirement_source" {
		nodeID, err = admit.RuleID(record["nodeId"], "requirement context catalog entry nodeId")
		if err != nil {
			return catalogSource{}, err
		}
	} else if record["nodeId"] != nil {
		return catalogSource{}, fmt.Errorf("requirement context non-requirement catalog entries must not declare nodeId")
	}
	return catalogSource{ExpectedDigest: expected, Kind: kind, NodeID: nodeID, Path: path, SourceRef: sourceRef}, nil
}

func readCatalogSource(root *os.Root, path string) (any, []byte, string, error) {
	info, err := root.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, nil, "", fmt.Errorf("requirement context source must be a regular non-symlink file")
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, nil, "", fmt.Errorf("open requirement context source")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, nil, "", fmt.Errorf("requirement context source changed between path and handle admission")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil || len(content) > maxSourceBytes {
		return nil, nil, "", fmt.Errorf("read requirement context source within byte limit")
	}
	finalInfo, err := file.Stat()
	if err != nil || !os.SameFile(openedInfo, finalInfo) || finalInfo.Size() != int64(len(content)) {
		return nil, nil, "", fmt.Errorf("requirement context source changed while reading")
	}
	value, err := admission.DecodeJSON(bytes.NewReader(content), maxSourceBytes)
	if err != nil {
		return nil, nil, "", err
	}
	return value, content, digest.SHA256TextRef(string(content)), nil
}

func baselineVerification(sources []Source) string {
	verified := 0
	for _, source := range sources {
		if source.ExpectedDigest != "" {
			verified++
		}
	}
	if verified == 0 {
		return "unverified"
	}
	if verified == len(sources) {
		return "verified"
	}
	return "partially_verified"
}

func sourceIdentityValues(sources []Source) []any {
	values := make([]any, 0, len(sources))
	for _, source := range sources {
		value := map[string]any{
			"currentDigest":  source.CurrentDigest,
			"expectedDigest": source.ExpectedDigest,
			"kind":           source.Kind,
			"path":           source.Path,
			"sourceRef":      source.SourceRef,
		}
		if source.NodeID != "" {
			value["nodeId"] = source.NodeID
		}
		if source.SourceRole != "" {
			value["sourceRole"] = source.SourceRole
		}
		values = append(values, value)
	}
	return values
}
