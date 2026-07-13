package requirementcontext

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const (
	ContextKind      = "proofkit.requirement-context"
	maxSnapshotBytes = 8 << 20
)

var boundaryNonClaims = []string{
	"Requirement context is a derived projection and is not requirement, proof, coverage, merge, release, rollout, or readiness authority.",
	"Requirement context does not execute native witnesses or prove source freshness after composition.",
}

type Source struct {
	CurrentDigest  string
	ExpectedDigest string
	Kind           string
	NodeID         string
	Path           string
	SourceRef      string
	SourceRole     string
}

type Snapshot struct {
	BaselineVerification string
	CatalogID            string
	Coverage             map[string]any
	ProofBinding         *requirementbinding.Input
	Projections          map[string]any
	RequirementSources   []requirementsourceadmission.Source
	SnapshotID           string
	Sources              []Source
	Tree                 requirementspectree.Tree
}

func SnapshotValue(snapshot Snapshot) map[string]any {
	sources := make([]any, 0, len(snapshot.Sources))
	for _, source := range snapshot.Sources {
		record := map[string]any{
			"currentDigest": source.CurrentDigest,
			"kind":          source.Kind,
			"path":          source.Path,
			"sourceRef":     source.SourceRef,
		}
		if source.ExpectedDigest != "" {
			record["expectedDigest"] = source.ExpectedDigest
		}
		if source.NodeID != "" {
			record["nodeId"] = source.NodeID
		}
		if source.SourceRole != "" {
			record["sourceRole"] = source.SourceRole
		}
		sources = append(sources, record)
	}
	return map[string]any{
		"baselineVerification": snapshot.BaselineVerification,
		"catalogId":            snapshot.CatalogID,
		"contextKind":          ContextKind,
		"nonClaims":            admit.StringSliceToAny(boundaryNonClaims),
		"projections":          snapshot.Projections,
		"schemaVersion":        json.Number("1"),
		"snapshotId":           snapshot.SnapshotID,
		"sources":              sources,
	}
}

func AdmitSnapshot(raw any) (Snapshot, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("requirement context must be an object")
	}
	if err := admit.KnownKeys(record, []string{"baselineVerification", "catalogId", "contextKind", "nonClaims", "projections", "schemaVersion", "snapshotId", "sources"}, "requirement context"); err != nil {
		return Snapshot{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["contextKind"] != ContextKind {
		return Snapshot{}, fmt.Errorf("requirement context identity is invalid")
	}
	catalogID, err := admit.RuleID(record["catalogId"], "requirement context catalogId")
	if err != nil {
		return Snapshot{}, err
	}
	snapshotID, err := admitDigestRef(record["snapshotId"], "requirement context snapshotId")
	if err != nil {
		return Snapshot{}, err
	}
	verification, err := admit.Enum(record["baselineVerification"], map[string]struct{}{"verified": {}, "partially_verified": {}, "unverified": {}}, "requirement context baselineVerification")
	if err != nil {
		return Snapshot{}, err
	}
	projections, ok := record["projections"].(map[string]any)
	if !ok {
		return Snapshot{}, fmt.Errorf("requirement context projections must be an object")
	}
	if err := admit.KnownKeys(projections, []string{"coverage", "proofBinding", "requirementSources", "specTree"}, "requirement context projections"); err != nil {
		return Snapshot{}, err
	}
	tree, requirementSources, proofBinding, coverage, canonicalProjections, err := admitSnapshotProjections(projections)
	if err != nil {
		return Snapshot{}, err
	}
	sources, err := admitSources(record["sources"])
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateProjectionSources(tree, requirementSources, proofBinding, coverage, sources); err != nil {
		return Snapshot{}, err
	}
	derivedVerification := baselineVerification(sources)
	if verification != derivedVerification {
		return Snapshot{}, fmt.Errorf("requirement context baselineVerification does not match admitted sources")
	}
	if err := admitExactNonClaims(record["nonClaims"]); err != nil {
		return Snapshot{}, err
	}
	identityValue := map[string]any{"catalogId": catalogID, "projections": canonicalProjections, "sources": sourceIdentityValues(sources)}
	encoded, err := stablejson.Marshal(identityValue)
	if err != nil {
		return Snapshot{}, err
	}
	if digest.SHA256TextRef(string(encoded)) != snapshotID {
		return Snapshot{}, fmt.Errorf("requirement context snapshotId does not match admitted content")
	}
	snapshot := Snapshot{
		BaselineVerification: verification,
		CatalogID:            catalogID,
		Coverage:             coverage,
		ProofBinding:         proofBinding,
		Projections:          canonicalProjections,
		RequirementSources:   requirementSources,
		SnapshotID:           snapshotID,
		Sources:              sources,
		Tree:                 tree,
	}
	fullValue, err := stablejson.Marshal(SnapshotValue(snapshot))
	if err != nil {
		return Snapshot{}, err
	}
	if len(fullValue) > maxSnapshotBytes {
		return Snapshot{}, fmt.Errorf("requirement context snapshot exceeds byte limit")
	}
	return snapshot, nil
}

func validateProjectionSources(tree requirementspectree.Tree, requirementSources []requirementsourceadmission.Source, proofBinding *requirementbinding.Input, coverage map[string]any, sources []Source) error {
	expected := map[string]string{"spec_tree": "spec_tree:" + tree.TreeID}
	requirementNodes := map[string]map[string]struct{}{}
	for _, node := range tree.Nodes {
		for _, ref := range node.SourceRefs {
			if ref.SourceRole != "requirements" || ref.SourceID == "" {
				continue
			}
			if requirementNodes[ref.SourceID] == nil {
				requirementNodes[ref.SourceID] = map[string]struct{}{}
			}
			requirementNodes[ref.SourceID][node.NodeID] = struct{}{}
		}
	}
	for _, source := range requirementSources {
		expected["requirement_source:"+source.SourceID] = source.SourceID
	}
	if len(requirementNodes) != len(requirementSources) {
		return fmt.Errorf("requirement context specification tree requirement refs do not match requirement projections")
	}
	if proofBinding != nil {
		expected["proof_binding"] = "proof_binding:" + proofBinding.BindingID
	}
	if coverage != nil {
		viewInputID, err := admit.RuleID(coverage["viewInputId"], "requirement context coverage viewInputId")
		if err != nil {
			return err
		}
		expected["coverage"] = "coverage:" + viewInputID
	}
	seen := map[string]struct{}{}
	for _, source := range sources {
		key := source.Kind
		if source.Kind == "requirement_source" {
			key += ":" + source.SourceRef
			if _, ok := requirementNodes[source.SourceRef][source.NodeID]; !ok || source.SourceRole != "requirements" {
				return fmt.Errorf("requirement context requirement source node does not match the specification tree")
			}
		}
		ref, ok := expected[key]
		if !ok || ref != source.SourceRef {
			return fmt.Errorf("requirement context source inventory does not match projections")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("requirement context source inventory contains duplicate projection owners")
		}
		seen[key] = struct{}{}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("requirement context source inventory does not match requirement projections")
	}
	knownRequirements := map[string]struct{}{}
	for _, source := range requirementSources {
		if _, ok := requirementNodes[source.SourceID]; !ok {
			return fmt.Errorf("requirement context requirement projection is not referenced by the specification tree")
		}
		for _, requirement := range source.Requirements {
			knownRequirements[requirement.RequirementID] = struct{}{}
		}
	}
	if proofBinding != nil {
		for _, requirement := range proofBinding.Requirements {
			if _, ok := knownRequirements[requirement.RequirementID]; !ok {
				return fmt.Errorf("requirement context proof binding references a requirement outside the context")
			}
		}
		for _, binding := range proofBinding.Bindings {
			if _, ok := knownRequirements[binding.RequirementID]; !ok {
				return fmt.Errorf("requirement context proof binding references a requirement outside the context")
			}
		}
	}
	if coverage != nil {
		for _, raw := range coverage["requirementCoverage"].([]any) {
			if _, ok := knownRequirements[raw.(map[string]any)["requirementId"].(string)]; !ok {
				return fmt.Errorf("requirement context coverage references a requirement outside the context")
			}
		}
	}
	return nil
}

func admitSnapshotProjections(projections map[string]any) (requirementspectree.Tree, []requirementsourceadmission.Source, *requirementbinding.Input, map[string]any, map[string]any, error) {
	treeResult, err := requirementspectree.Evaluate(projections["specTree"])
	if err != nil || treeResult.ExitCode != 0 {
		return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context spec tree projection is invalid")
	}
	rawSources, ok := projections["requirementSources"].([]any)
	if !ok || len(rawSources) == 0 {
		return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context requirementSources must be a non-empty array")
	}
	seen := map[string]struct{}{}
	seenRequirements := map[string]struct{}{}
	requirementSources := make([]requirementsourceadmission.Source, 0, len(rawSources))
	for _, rawSource := range rawSources {
		result, err := requirementsourceadmission.Evaluate(rawSource)
		if err != nil {
			return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context requirement source projection is invalid: %w", err)
		}
		if result.ExitCode != 0 {
			return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context requirement source projection failed admission")
		}
		if _, exists := seen[result.Source.SourceID]; exists {
			return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context requirement source ids must be unique")
		}
		seen[result.Source.SourceID] = struct{}{}
		for _, requirement := range result.Source.Requirements {
			if _, duplicate := seenRequirements[requirement.RequirementID]; duplicate {
				return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context requirement ids must be unique across sources")
			}
			seenRequirements[requirement.RequirementID] = struct{}{}
		}
		requirementSources = append(requirementSources, result.Source)
	}
	sort.Slice(requirementSources, func(left, right int) bool {
		return requirementSources[left].SourceID < requirementSources[right].SourceID
	})
	var proofBinding *requirementbinding.Input
	if rawProof, ok := projections["proofBinding"]; ok {
		result, err := requirementbinding.Build(rawProof)
		if err != nil || result.Record.State != "passed" {
			return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context proof binding projection is invalid")
		}
		proofBinding = &result.Input
	}
	var coverage map[string]any
	if rawCoverage, ok := projections["coverage"]; ok {
		coverage, err = requirementcoverageview.AdmitOutput(rawCoverage)
		if err != nil {
			return requirementspectree.Tree{}, nil, nil, nil, nil, fmt.Errorf("requirement context coverage projection is invalid: %w", err)
		}
	}
	canonical := map[string]any{
		"requirementSources": requirementSourceValues(requirementSources),
		"specTree":           requirementspectree.TreeValue(treeResult.Tree),
	}
	if proofBinding != nil {
		canonical["proofBinding"] = requirementbinding.InputValue(*proofBinding)
	}
	if coverage != nil {
		canonical["coverage"] = coverage
	}
	return treeResult.Tree, requirementSources, proofBinding, coverage, canonical, nil
}

func requirementSourceValues(sources []requirementsourceadmission.Source) []any {
	values := make([]any, 0, len(sources))
	for _, source := range sources {
		values = append(values, requirementsourceadmission.SourceValue(source))
	}
	return values
}

func admitExactNonClaims(raw any) error {
	values, ok := raw.([]any)
	if !ok || len(values) != len(boundaryNonClaims) {
		return fmt.Errorf("requirement context nonClaims must equal the command-owned boundary")
	}
	for index, expected := range boundaryNonClaims {
		if values[index] != expected {
			return fmt.Errorf("requirement context nonClaims must equal the command-owned boundary")
		}
	}
	return nil
}

func admitSources(raw any) ([]Source, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("requirement context sources must be a non-empty array")
	}
	result := make([]Source, 0, len(values))
	seenPaths := map[string]struct{}{}
	seenRefs := map[string]struct{}{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("requirement context sources[%d] must be an object", index)
		}
		if err := admit.KnownKeys(record, []string{"currentDigest", "expectedDigest", "kind", "nodeId", "path", "sourceRef", "sourceRole"}, "requirement context source"); err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], "requirement context source path")
		if err != nil {
			return nil, err
		}
		path, err := admit.SafeRepoRelativePath(pathText, "requirement context source path")
		if err != nil {
			return nil, err
		}
		if _, exists := seenPaths[path]; exists {
			return nil, fmt.Errorf("requirement context source paths must be unique")
		}
		seenPaths[path] = struct{}{}
		currentDigest, err := admitDigestRef(record["currentDigest"], "requirement context source currentDigest")
		if err != nil {
			return nil, err
		}
		expectedDigest := ""
		if record["expectedDigest"] != nil {
			expectedDigest, err = admitDigestRef(record["expectedDigest"], "requirement context source expectedDigest")
			if err != nil {
				return nil, err
			}
		}
		kind, err := admit.Enum(record["kind"], map[string]struct{}{"coverage": {}, "proof_binding": {}, "requirement_source": {}, "spec_tree": {}}, "requirement context source kind")
		if err != nil {
			return nil, err
		}
		sourceRef, err := admit.RuleID(record["sourceRef"], "requirement context source sourceRef")
		if err != nil {
			return nil, err
		}
		if _, exists := seenRefs[sourceRef]; exists {
			return nil, fmt.Errorf("requirement context source refs must be unique")
		}
		seenRefs[sourceRef] = struct{}{}
		if expectedDigest != "" && expectedDigest != currentDigest {
			return nil, fmt.Errorf("requirement context source expectedDigest must equal currentDigest")
		}
		nodeID := ""
		sourceRole := ""
		if kind == "requirement_source" {
			nodeID, err = admit.RuleID(record["nodeId"], "requirement context source nodeId")
			if err != nil {
				return nil, err
			}
			sourceRole, err = admit.Enum(record["sourceRole"], map[string]struct{}{"requirements": {}}, "requirement context source sourceRole")
			if err != nil {
				return nil, err
			}
		} else if record["nodeId"] != nil || record["sourceRole"] != nil {
			return nil, fmt.Errorf("requirement context non-requirement sources must not declare nodeId or sourceRole")
		}
		result = append(result, Source{CurrentDigest: currentDigest, ExpectedDigest: expectedDigest, Kind: kind, NodeID: nodeID, Path: path, SourceRef: sourceRef, SourceRole: sourceRole})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].SourceRef < result[right].SourceRef })
	return result, nil
}

func admitDigestRef(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, "sha256:") {
		return "", fmt.Errorf("%s must be a sha256 digest reference", context)
	}
	if _, err := admit.LowercaseSHA256(strings.TrimPrefix(value, "sha256:"), context); err != nil {
		return "", err
	}
	return value, nil
}
