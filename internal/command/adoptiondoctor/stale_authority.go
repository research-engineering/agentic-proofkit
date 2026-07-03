package adoptiondoctor

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
)

var authorityStates = map[string]struct{}{
	"current": {},
	"retired": {},
}

type staleAuthority struct {
	AuthoritySurfaces   []authoritySurface
	CurrentPackage      packageIdentity
	ForbiddenVocabulary []forbiddenVocabulary
	RetiredScopes       []retiredScope
}

type packageIdentity struct {
	Name    string
	Version string
}

type forbiddenVocabulary struct {
	ReplacementText string
	Text            string
	VocabularyID    string
}

type authoritySurface struct {
	AuthorityState       string
	EvidenceRefs         []string
	MatchedVocabularyIDs []string
	NonClaims            []string
	Owner                string
	Path                 string
	RetiredScopeID       string
	SurfaceID            string
	TouchedRuleIDs       []string
}

type retiredScope struct {
	AllowedVocabularyIDs []string
	NonClaim             string
	PathPrefixes         []string
	ScopeID              string
}

func staleAuthorityFromAny(raw any) (staleAuthority, error) {
	if raw == nil {
		return staleAuthority{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return staleAuthority{}, fmt.Errorf("adoption doctor staleAuthority must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authoritySurfaces", "currentPackage", "forbiddenVocabulary", "retiredScopes"}, "adoption doctor staleAuthority"); err != nil {
		return staleAuthority{}, err
	}
	currentPackage, err := packageIdentityFromAny(optional(record, "currentPackage", nil))
	if err != nil {
		return staleAuthority{}, err
	}
	forbidden, err := forbiddenVocabularyList(optional(record, "forbiddenVocabulary", []any{}))
	if err != nil {
		return staleAuthority{}, err
	}
	forbiddenIDs := forbiddenVocabularyIDSet(forbidden)
	scopes, err := retiredScopes(optional(record, "retiredScopes", []any{}), forbiddenIDs)
	if err != nil {
		return staleAuthority{}, err
	}
	surfaces, err := authoritySurfaces(optional(record, "authoritySurfaces", []any{}), forbiddenIDs, retiredScopeIDSet(scopes))
	if err != nil {
		return staleAuthority{}, err
	}
	return staleAuthority{
		AuthoritySurfaces:   surfaces,
		CurrentPackage:      currentPackage,
		ForbiddenVocabulary: forbidden,
		RetiredScopes:       scopes,
	}, nil
}

func packageIdentityFromAny(raw any) (packageIdentity, error) {
	if raw == nil {
		return packageIdentity{}, nil
	}
	record, ok := raw.(map[string]any)
	if !ok {
		return packageIdentity{}, fmt.Errorf("adoption doctor staleAuthority currentPackage must be an object")
	}
	if err := admit.KnownKeys(record, []string{"name", "version"}, "adoption doctor staleAuthority currentPackage"); err != nil {
		return packageIdentity{}, err
	}
	name, err := admit.NonEmptyText(record["name"], "adoption doctor staleAuthority currentPackage name")
	if err != nil {
		return packageIdentity{}, err
	}
	version, err := admit.NonEmptyText(record["version"], "adoption doctor staleAuthority currentPackage version")
	if err != nil {
		return packageIdentity{}, err
	}
	return packageIdentity{Name: name, Version: version}, nil
}

func forbiddenVocabularyList(raw any) ([]forbiddenVocabulary, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor staleAuthority forbiddenVocabulary must be an array")
	}
	items := make([]forbiddenVocabulary, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption doctor staleAuthority forbiddenVocabulary[%d] must be an object", index)
		}
		context := fmt.Sprintf("adoption doctor staleAuthority forbiddenVocabulary[%d]", index)
		if err := admit.KnownKeys(record, []string{"replacementText", "text", "vocabularyId"}, context); err != nil {
			return nil, err
		}
		vocabularyID, err := admit.RuleID(record["vocabularyId"], context+" vocabularyId")
		if err != nil {
			return nil, err
		}
		text, err := admit.NonEmptyText(record["text"], context+" text")
		if err != nil {
			return nil, err
		}
		replacementText := ""
		if value, ok := record["replacementText"]; ok && value != nil {
			replacementText, err = admit.NonEmptyText(value, context+" replacementText")
			if err != nil {
				return nil, err
			}
		}
		items = append(items, forbiddenVocabulary{ReplacementText: replacementText, Text: text, VocabularyID: vocabularyID})
		ids = append(ids, vocabularyID)
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor staleAuthority forbidden vocabulary ids", true); err != nil {
		return nil, err
	}
	return items, nil
}

func authoritySurfaces(raw any, forbiddenIDs map[string]struct{}, scopeIDs map[string]struct{}) ([]authoritySurface, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor staleAuthority authoritySurfaces must be an array")
	}
	surfaces := make([]authoritySurface, 0, len(values))
	ids := []string{}
	for index, value := range values {
		surface, err := authoritySurfaceFromAny(value, index, forbiddenIDs, scopeIDs)
		if err != nil {
			return nil, err
		}
		surfaces = append(surfaces, surface)
		ids = append(ids, surface.SurfaceID)
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor staleAuthority authority surface ids", true); err != nil {
		return nil, err
	}
	return surfaces, nil
}

func authoritySurfaceFromAny(raw any, index int, forbiddenIDs map[string]struct{}, scopeIDs map[string]struct{}) (authoritySurface, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return authoritySurface{}, fmt.Errorf("adoption doctor staleAuthority authoritySurfaces[%d] must be an object", index)
	}
	context := fmt.Sprintf("adoption doctor staleAuthority authoritySurfaces[%d]", index)
	if err := admit.KnownKeys(record, []string{"authorityState", "evidenceRefs", "matchedVocabularyIds", "nonClaims", "owner", "path", "retiredScopeId", "surfaceId", "touchedRuleIds"}, context); err != nil {
		return authoritySurface{}, err
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], context+" surfaceId")
	if err != nil {
		return authoritySurface{}, err
	}
	rawPath, ok := record["path"].(string)
	if !ok {
		return authoritySurface{}, fmt.Errorf("%s path must be a repository-relative POSIX path", context)
	}
	pathValue, err := admit.SafeRepoRelativePath(rawPath, context+" path")
	if err != nil {
		return authoritySurface{}, err
	}
	owner, err := admit.NonEmptyText(record["owner"], context+" owner")
	if err != nil {
		return authoritySurface{}, err
	}
	authorityState, err := admit.Enum(record["authorityState"], authorityStates, context+" authorityState")
	if err != nil {
		return authoritySurface{}, err
	}
	matchedVocabularyIDs, err := sortedRuleIDs(optional(record, "matchedVocabularyIds", []any{}), context+" matchedVocabularyIds")
	if err != nil {
		return authoritySurface{}, err
	}
	if err := requireKnownIDs(matchedVocabularyIDs, forbiddenIDs, context+" matchedVocabularyIds"); err != nil {
		return authoritySurface{}, err
	}
	retiredScopeID := ""
	if rawScopeID, ok := record["retiredScopeId"]; ok && rawScopeID != nil {
		retiredScopeID, err = admit.RuleID(rawScopeID, context+" retiredScopeId")
		if err != nil {
			return authoritySurface{}, err
		}
		if _, ok := scopeIDs[retiredScopeID]; !ok {
			return authoritySurface{}, fmt.Errorf("%s retiredScopeId must reference a declared retired scope", context)
		}
	}
	evidenceRefs, err := sortedPaths(optional(record, "evidenceRefs", []any{}), context+" evidenceRefs")
	if err != nil {
		return authoritySurface{}, err
	}
	touchedRuleIDs, err := sortedRuleIDs(optional(record, "touchedRuleIds", []any{}), context+" touchedRuleIds")
	if err != nil {
		return authoritySurface{}, err
	}
	nonClaims, err := admit.SortedTextArray(optional(record, "nonClaims", []any{}), context+" nonClaims", true)
	if err != nil {
		return authoritySurface{}, err
	}
	return authoritySurface{
		AuthorityState:       authorityState,
		EvidenceRefs:         evidenceRefs,
		MatchedVocabularyIDs: matchedVocabularyIDs,
		NonClaims:            nonClaims,
		Owner:                owner,
		Path:                 pathValue,
		RetiredScopeID:       retiredScopeID,
		SurfaceID:            surfaceID,
		TouchedRuleIDs:       touchedRuleIDs,
	}, nil
}

func retiredScopes(raw any, forbiddenIDs map[string]struct{}) ([]retiredScope, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("adoption doctor staleAuthority retiredScopes must be an array")
	}
	scopes := make([]retiredScope, 0, len(values))
	ids := []string{}
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("adoption doctor staleAuthority retiredScopes[%d] must be an object", index)
		}
		context := fmt.Sprintf("adoption doctor staleAuthority retiredScopes[%d]", index)
		if err := admit.KnownKeys(record, []string{"allowedVocabularyIds", "nonClaim", "pathPrefixes", "scopeId"}, context); err != nil {
			return nil, err
		}
		scopeID, err := admit.RuleID(record["scopeId"], context+" scopeId")
		if err != nil {
			return nil, err
		}
		allowedVocabularyIDs, err := sortedRuleIDs(record["allowedVocabularyIds"], context+" allowedVocabularyIds")
		if err != nil {
			return nil, err
		}
		if err := requireKnownIDs(allowedVocabularyIDs, forbiddenIDs, context+" allowedVocabularyIds"); err != nil {
			return nil, err
		}
		pathPrefixes, err := sortedPaths(record["pathPrefixes"], context+" pathPrefixes")
		if err != nil {
			return nil, err
		}
		if len(pathPrefixes) == 0 {
			return nil, fmt.Errorf("%s pathPrefixes must be non-empty", context)
		}
		nonClaim, err := admit.NonEmptyText(record["nonClaim"], context+" nonClaim")
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, retiredScope{AllowedVocabularyIDs: allowedVocabularyIDs, NonClaim: nonClaim, PathPrefixes: pathPrefixes, ScopeID: scopeID})
		ids = append(ids, scopeID)
	}
	if _, err := admit.PreserveSortedText(ids, "adoption doctor staleAuthority retired scope ids", true); err != nil {
		return nil, err
	}
	return scopes, nil
}

func staleAuthorityGaps(policy staleAuthority, touched map[string]struct{}, checkedScope string) []gap {
	if len(policy.AuthoritySurfaces) == 0 {
		return []gap{}
	}
	scopes := retiredScopeByID(policy.RetiredScopes)
	gaps := []gap{}
	for _, surface := range policy.AuthoritySurfaces {
		if len(surface.MatchedVocabularyIDs) == 0 {
			continue
		}
		touchedSurface := hasTouched(surface.TouchedRuleIDs, touched) || checkedScope == adoptionmode.ScopeAll
		evidenceRefs := sortedUnique(append([]string{surface.Path}, surface.EvidenceRefs...))
		if surface.AuthorityState == "current" {
			gaps = append(gaps, gap{
				EvidenceRefs: evidenceRefs,
				GapID:        surface.SurfaceID + ".stale-authority-current-vocabulary",
				Kind:         "stale_authority_current_vocabulary",
				Message:      "Current authority surface contains caller-reported obsolete package or proof-owner vocabulary.",
				Owner:        surface.Owner,
				Phase:        "retire-stale-authority",
				RuleRefs:     surface.TouchedRuleIDs,
				Touched:      touchedSurface,
			})
			continue
		}
		if !retiredSurfaceAllowed(surface, scopes) {
			gaps = append(gaps, gap{
				EvidenceRefs: evidenceRefs,
				GapID:        surface.SurfaceID + ".stale-authority-retired-scope",
				Kind:         "stale_authority_retired_scope",
				Message:      "Retired authority vocabulary is present outside an admitted historical scope.",
				Owner:        surface.Owner,
				Phase:        "retire-stale-authority",
				RuleRefs:     surface.TouchedRuleIDs,
				Touched:      touchedSurface,
			})
		}
	}
	return gaps
}

func retiredSurfaceAllowed(surface authoritySurface, scopes map[string]retiredScope) bool {
	scope, ok := scopes[surface.RetiredScopeID]
	if !ok {
		return false
	}
	allowedVocabularyIDs := stringSet(scope.AllowedVocabularyIDs)
	for _, vocabularyID := range surface.MatchedVocabularyIDs {
		if _, ok := allowedVocabularyIDs[vocabularyID]; !ok {
			return false
		}
	}
	for _, prefix := range scope.PathPrefixes {
		if surface.Path == prefix || strings.HasPrefix(surface.Path, prefix+"/") {
			return true
		}
	}
	return false
}

func staleAuthorityJSON(policy staleAuthority) map[string]any {
	return map[string]any{
		"authoritySurfaces":   authoritySurfacesJSON(policy.AuthoritySurfaces),
		"currentPackage":      packageIdentityJSON(policy.CurrentPackage),
		"forbiddenVocabulary": forbiddenVocabularyJSON(policy.ForbiddenVocabulary),
		"retiredScopes":       retiredScopesJSON(policy.RetiredScopes),
	}
}

func packageIdentityJSON(identity packageIdentity) map[string]any {
	return map[string]any{
		"name":    identity.Name,
		"version": identity.Version,
	}
}

func forbiddenVocabularyJSON(items []forbiddenVocabulary) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]any{
			"replacementText": item.ReplacementText,
			"text":            item.Text,
			"vocabularyId":    item.VocabularyID,
		})
	}
	return out
}

func authoritySurfacesJSON(surfaces []authoritySurface) []any {
	out := make([]any, 0, len(surfaces))
	for _, surface := range surfaces {
		out = append(out, map[string]any{
			"authorityState":       surface.AuthorityState,
			"evidenceRefs":         admit.StringSliceToAny(surface.EvidenceRefs),
			"matchedVocabularyIds": admit.StringSliceToAny(surface.MatchedVocabularyIDs),
			"nonClaims":            admit.StringSliceToAny(surface.NonClaims),
			"owner":                surface.Owner,
			"path":                 surface.Path,
			"retiredScopeId":       surface.RetiredScopeID,
			"surfaceId":            surface.SurfaceID,
			"touchedRuleIds":       admit.StringSliceToAny(surface.TouchedRuleIDs),
		})
	}
	return out
}

func retiredScopesJSON(scopes []retiredScope) []any {
	out := make([]any, 0, len(scopes))
	for _, scope := range scopes {
		out = append(out, map[string]any{
			"allowedVocabularyIds": admit.StringSliceToAny(scope.AllowedVocabularyIDs),
			"nonClaim":             scope.NonClaim,
			"pathPrefixes":         admit.StringSliceToAny(scope.PathPrefixes),
			"scopeId":              scope.ScopeID,
		})
	}
	return out
}

func forbiddenVocabularyIDSet(items []forbiddenVocabulary) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		out[item.VocabularyID] = struct{}{}
	}
	return out
}

func retiredScopeIDSet(items []retiredScope) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		out[item.ScopeID] = struct{}{}
	}
	return out
}

func retiredScopeByID(items []retiredScope) map[string]retiredScope {
	out := map[string]retiredScope{}
	for _, item := range items {
		out[item.ScopeID] = item
	}
	return out
}

func requireKnownIDs(values []string, known map[string]struct{}, context string) error {
	for _, value := range values {
		if _, ok := known[value]; !ok {
			return fmt.Errorf("%s must reference declared forbidden vocabulary ids", context)
		}
	}
	return nil
}
