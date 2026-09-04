package adoptionmaterialization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

const ManifestKind = "proofkit.project-routing-manifest"

var manifestNonClaims = []string{
	"Project routing manifests do not duplicate child semantics or prove child admission, freshness, execution, merge, release, rollout, or production readiness.",
}

type Route struct {
	ArtifactID   string
	ArtifactKind string
	Path         string
}

type Manifest struct {
	ManifestID               string
	MaterializationRequestID string
	ProjectID                string
	Routes                   []Route
	SourcePlanID             string
}

func buildManifest(request Request, childArtifacts []artifact) (Manifest, error) {
	routes := make([]Route, 0, len(childArtifacts))
	for _, child := range childArtifacts {
		routes = append(routes, Route{ArtifactID: child.ID, ArtifactKind: child.Kind, Path: child.Path})
	}
	sort.Slice(routes, func(left, right int) bool { return routes[left].Path < routes[right].Path })
	manifest := Manifest{
		MaterializationRequestID: request.RequestID,
		ProjectID:                request.ProjectID,
		Routes:                   routes,
		SourcePlanID:             request.SourcePlanID,
	}
	id, err := digest.StableJSONSHA256Ref(manifest.identityValue())
	if err != nil {
		return Manifest{}, fmt.Errorf("derive project routing manifest identity")
	}
	manifest.ManifestID = id
	admitted, err := AdmitManifest(manifest.JSONValue())
	if err != nil {
		return Manifest{}, fmt.Errorf("admit generated project routing manifest: %w", err)
	}
	return admitted, nil
}

func (manifest Manifest) JSONValue() map[string]any {
	value := manifest.identityValue()
	value["manifestId"] = manifest.ManifestID
	return value
}

func (manifest Manifest) identityValue() map[string]any {
	routes := make([]any, 0, len(manifest.Routes))
	for _, route := range manifest.Routes {
		routes = append(routes, map[string]any{
			"artifactId":   route.ArtifactID,
			"artifactKind": route.ArtifactKind,
			"path":         route.Path,
		})
	}
	return map[string]any{
		"authority":                "routing_only",
		"manifestKind":             ManifestKind,
		"materializationRequestId": manifest.MaterializationRequestID,
		"nonClaims":                admit.StringSliceToAny(manifestNonClaims),
		"projectId":                manifest.ProjectID,
		"routes":                   routes,
		"schemaVersion":            json.Number("1"),
		"sourcePlanId":             manifest.SourcePlanID,
	}
}

func AdmitManifest(raw any) (Manifest, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Manifest{}, fmt.Errorf("project routing manifest must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authority", "manifestId", "manifestKind", "materializationRequestId", "nonClaims", "projectId", "routes", "schemaVersion", "sourcePlanId"}, "project routing manifest"); err != nil {
		return Manifest{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["manifestKind"] != ManifestKind || record["authority"] != "routing_only" {
		return Manifest{}, fmt.Errorf("project routing manifest identity is invalid")
	}
	manifestID, err := admit.SHA256Ref(record["manifestId"], "project routing manifest manifestId")
	if err != nil {
		return Manifest{}, err
	}
	requestID, err := admit.RuleID(record["materializationRequestId"], "project routing manifest materializationRequestId")
	if err != nil {
		return Manifest{}, err
	}
	projectID, err := admit.RuleID(record["projectId"], "project routing manifest projectId")
	if err != nil {
		return Manifest{}, err
	}
	sourcePlanID, err := admit.SHA256Ref(record["sourcePlanId"], "project routing manifest sourcePlanId")
	if err != nil {
		return Manifest{}, err
	}
	routes, err := admitRoutes(record["routes"])
	if err != nil {
		return Manifest{}, err
	}
	nonClaims, err := admit.PreserveSortedTextArray(record["nonClaims"], "project routing manifest nonClaims", false)
	if err != nil || !equalStrings(nonClaims, manifestNonClaims) {
		return Manifest{}, fmt.Errorf("project routing manifest nonClaims are invalid")
	}
	manifest := Manifest{ManifestID: manifestID, MaterializationRequestID: requestID, ProjectID: projectID, Routes: routes, SourcePlanID: sourcePlanID}
	wantID, err := digest.StableJSONSHA256Ref(manifest.identityValue())
	if err != nil || wantID != manifestID {
		return Manifest{}, fmt.Errorf("project routing manifest identity does not match its content")
	}
	actual, err := stablejson.Marshal(record)
	if err != nil {
		return Manifest{}, fmt.Errorf("encode project routing manifest")
	}
	expected, err := stablejson.Marshal(manifest.JSONValue())
	if err != nil || !bytes.Equal(actual, expected) {
		return Manifest{}, fmt.Errorf("project routing manifest is not canonical")
	}
	return manifest, nil
}

func admitRoutes(raw any) ([]Route, error) {
	values, ok := raw.([]any)
	if !ok || len(values) < 3 || len(values) > repositoryRouteLimit() {
		return nil, fmt.Errorf("project routing manifest route count is invalid")
	}
	routes := make([]Route, 0, len(values))
	artifactIDs := map[string]struct{}{}
	kindCounts := map[string]int{}
	pathUses := []pathUse{{Path: ProjectManifestPath, Role: roleManifestTarget, Target: true}}
	previous := ""
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("project routing manifest route must be an object")
		}
		if err := admit.KnownKeys(record, []string{"artifactId", "artifactKind", "path"}, "project routing manifest route"); err != nil {
			return nil, err
		}
		artifactID, err := admit.RuleID(record["artifactId"], "project routing manifest artifactId")
		if err != nil {
			return nil, err
		}
		kind, err := admit.Enum(record["artifactKind"], artifactKindSet, "project routing manifest artifactKind")
		if err != nil {
			return nil, err
		}
		pathText, err := admit.NonEmptyText(record["path"], "project routing manifest path")
		if err != nil {
			return nil, err
		}
		targetPath, err := admit.SafeRepoRelativePath(pathText, "project routing manifest path")
		if err != nil {
			return nil, err
		}
		if previous != "" && previous >= targetPath {
			return nil, fmt.Errorf("project routing manifest routes must be sorted and path-unique")
		}
		if _, duplicate := artifactIDs[artifactID]; duplicate {
			return nil, fmt.Errorf("project routing manifest artifactIds must be unique")
		}
		artifactIDs[artifactID] = struct{}{}
		kindCounts[kind]++
		if kind == ArtifactRequirementSource && !strings.HasSuffix(targetPath, "/requirements.v1.json") {
			return nil, fmt.Errorf("project routing manifest requirement-source path is outside the producer language")
		}
		role := roleRequirementSource
		switch kind {
		case ArtifactRequirementBinding:
			role = roleBindingTarget
		case ArtifactTestInventory:
			role = roleInventoryTarget
		}
		pathUses = append(pathUses, pathUse{Path: targetPath, Role: role, Target: true})
		previous = targetPath
		routes = append(routes, Route{ArtifactID: artifactID, ArtifactKind: kind, Path: targetPath})
	}
	if kindCounts[ArtifactRequirementSource] < 1 || kindCounts[ArtifactRequirementBinding] != 1 || kindCounts[ArtifactTestInventory] != 1 {
		return nil, fmt.Errorf("project routing manifest route kinds do not match the producer contract")
	}
	if err := validatePathRoles(pathUses); err != nil {
		return nil, err
	}
	return routes, nil
}

var artifactKindSet = map[string]struct{}{
	ArtifactRequirementSource:  {},
	ArtifactRequirementBinding: {},
	ArtifactTestInventory:      {},
}

func repositoryRouteLimit() int {
	return MaximumRequirementSources + 2
}

func equalStrings(left, right []string) bool {
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
