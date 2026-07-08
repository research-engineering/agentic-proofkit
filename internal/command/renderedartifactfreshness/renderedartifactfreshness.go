package renderedartifactfreshness

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.rendered-artifact-freshness"

var artifactKinds = map[string]struct{}{
	"generated_lookup": {},
	"rendered_view":    {},
}

var artifactFormats = map[string]struct{}{
	"html":     {},
	"json":     {},
	"markdown": {},
	"text":     {},
}

var artifactAuthorities = map[string]struct{}{
	"canonical_source":  {},
	"durable_meaning":   {},
	"lookup_only":       {},
	"presentation_only": {},
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

var boundaryNonClaims = []string{
	"Rendered artifact freshness reports do not approve merge, release, rollout, or production readiness.",
	"Rendered artifact freshness reports do not execute renderers or generators.",
	"Rendered artifact freshness reports do not own requirement meaning or proof routes.",
	"Rendered artifact freshness reports do not prove native witness execution.",
	"Rendered artifact freshness reports do not read rendered artifacts or source files.",
}

type artifactInput struct {
	ArtifactFormat                string
	ArtifactID                    string
	ArtifactKind                  string
	ArtifactPath                  string
	Authority                     string
	CurrentArtifactDigest         string
	CurrentGenerationScopeDigest  string
	CurrentRendererDigest         string
	CurrentRendererVersion        string
	CurrentSourceDigest           string
	FreshnessCheckRefs            []string
	GenerationScopeID             string
	NonClaims                     []string
	RecordedArtifactDigest        string
	RecordedGenerationScopeDigest string
	RecordedRendererDigest        string
	RecordedRendererVersion       string
	RecordedSourceDigest          string
	RendererID                    string
	SourceRefs                    []string
}

type admittedInput struct {
	Artifacts      []artifactInput
	FreshnessSetID string
	NonClaims      []string
}

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	failures := []string{}
	staleArtifactIDs := []string{}
	for _, artifact := range input.Artifacts {
		artifactFailures := artifactFailures(artifact)
		failures = append(failures, artifactFailures...)
		if len(artifactFailures) > 0 {
			staleArtifactIDs = append(staleArtifactIDs, artifact.ArtifactID)
		}
	}
	sort.Strings(failures)
	sort.Strings(staleArtifactIDs)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      input.FreshnessSetID,
		State:         state,
		Summary: map[string]any{
			"artifactCount":        len(input.Artifacts),
			"failureCount":         len(failures),
			"generatedLookupCount": countArtifacts(input.Artifacts, "generated_lookup"),
			"renderedViewCount":    countArtifacts(input.Artifacts, "rendered_view"),
			"staleArtifactCount":   len(staleArtifactIDs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "artifacts", Value: artifactsDiagnostic(input.Artifacts)},
			{Key: "failures", Value: admit.StringSliceToAny(failures)},
		},
		RuleResults: ruleResults(failures),
		NonClaims:   admit.StringSliceToAny(input.NonClaims),
	}
	if state == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}

func admitInput(raw any) (admittedInput, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return admittedInput{}, fmt.Errorf("rendered artifact freshness input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"artifacts", "freshnessSetId", "nonClaims", "schemaVersion"}, "rendered artifact freshness input"); err != nil {
		return admittedInput{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return admittedInput{}, fmt.Errorf("rendered artifact freshness schemaVersion must be 1")
	}
	artifacts, err := artifactArray(record["artifacts"])
	if err != nil {
		return admittedInput{}, err
	}
	paths := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		paths = append(paths, artifact.ArtifactPath)
	}
	if _, err := sortedUnique(append([]string{}, paths...), "rendered artifact freshness artifact paths", false); err != nil {
		return admittedInput{}, err
	}
	freshnessSetID, err := admit.RuleID(record["freshnessSetId"], "rendered artifact freshness freshnessSetId")
	if err != nil {
		return admittedInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], "rendered artifact freshness nonClaims", false)
	if err != nil {
		return admittedInput{}, err
	}
	allNonClaims := append(append([]string{}, boundaryNonClaims...), nonClaims...)
	sort.Strings(allNonClaims)
	if _, err := preserveSortedUnique(allNonClaims, "rendered artifact freshness report nonClaims", true); err != nil {
		return admittedInput{}, err
	}
	return admittedInput{
		Artifacts:      artifacts,
		FreshnessSetID: freshnessSetID,
		NonClaims:      allNonClaims,
	}, nil
}

func artifactArray(raw any) ([]artifactInput, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("rendered artifact freshness artifacts must be a non-empty array")
	}
	artifacts := make([]artifactInput, 0, len(values))
	for index, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rendered artifact freshness artifacts[%d] must be an object", index)
		}
		artifact, err := admitArtifact(record)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(left int, right int) bool {
		return artifacts[left].ArtifactID < artifacts[right].ArtifactID
	})
	ids := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		ids = append(ids, artifact.ArtifactID)
	}
	if _, err := preserveSortedUnique(ids, "rendered artifact freshness artifact ids", false); err != nil {
		return nil, err
	}
	return artifacts, nil
}

func admitArtifact(record map[string]any) (artifactInput, error) {
	if err := admit.KnownKeys(record, []string{"artifactFormat", "artifactId", "artifactKind", "artifactPath", "authority", "currentArtifactDigest", "currentGenerationScopeDigest", "currentRendererDigest", "currentRendererVersion", "currentSourceDigest", "freshnessCheckRefs", "generationScopeId", "nonClaims", "recordedArtifactDigest", "recordedGenerationScopeDigest", "recordedRendererDigest", "recordedRendererVersion", "recordedSourceDigest", "rendererId", "sourceRefs"}, "rendered artifact freshness artifact"); err != nil {
		return artifactInput{}, err
	}
	artifactID, err := admit.RuleID(record["artifactId"], "rendered artifact freshness artifactId")
	if err != nil {
		return artifactInput{}, err
	}
	artifactPathText, err := text(record["artifactPath"], fmt.Sprintf("rendered artifact freshness %s artifactPath", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	artifactPath, err := admit.SafeRepoRelativePath(artifactPathText, fmt.Sprintf("rendered artifact freshness %s artifactPath", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	artifactKind, err := enum(record["artifactKind"], artifactKinds, fmt.Sprintf("rendered artifact freshness %s artifactKind", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	artifactFormat, err := enum(record["artifactFormat"], artifactFormats, fmt.Sprintf("rendered artifact freshness %s artifactFormat", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	authority, err := enum(record["authority"], artifactAuthorities, fmt.Sprintf("rendered artifact freshness %s authority", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	sourceRefs, err := sortedPaths(record["sourceRefs"], fmt.Sprintf("rendered artifact freshness %s sourceRefs", artifactID), false)
	if err != nil {
		return artifactInput{}, err
	}
	recordedSourceDigest, err := digest(record["recordedSourceDigest"], fmt.Sprintf("rendered artifact freshness %s recordedSourceDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	currentSourceDigest, err := digest(record["currentSourceDigest"], fmt.Sprintf("rendered artifact freshness %s currentSourceDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	rendererID, err := admit.RuleID(record["rendererId"], fmt.Sprintf("rendered artifact freshness %s rendererId", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	recordedRendererVersion, err := text(record["recordedRendererVersion"], fmt.Sprintf("rendered artifact freshness %s recordedRendererVersion", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	currentRendererVersion, err := text(record["currentRendererVersion"], fmt.Sprintf("rendered artifact freshness %s currentRendererVersion", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	recordedRendererDigest, err := digest(record["recordedRendererDigest"], fmt.Sprintf("rendered artifact freshness %s recordedRendererDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	currentRendererDigest, err := digest(record["currentRendererDigest"], fmt.Sprintf("rendered artifact freshness %s currentRendererDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	generationScopeID, err := admit.RuleID(record["generationScopeId"], fmt.Sprintf("rendered artifact freshness %s generationScopeId", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	recordedGenerationScopeDigest, err := digest(record["recordedGenerationScopeDigest"], fmt.Sprintf("rendered artifact freshness %s recordedGenerationScopeDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	currentGenerationScopeDigest, err := digest(record["currentGenerationScopeDigest"], fmt.Sprintf("rendered artifact freshness %s currentGenerationScopeDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	recordedArtifactDigest, err := digest(record["recordedArtifactDigest"], fmt.Sprintf("rendered artifact freshness %s recordedArtifactDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	currentArtifactDigest, err := digest(record["currentArtifactDigest"], fmt.Sprintf("rendered artifact freshness %s currentArtifactDigest", artifactID))
	if err != nil {
		return artifactInput{}, err
	}
	freshnessCheckRefs, err := sortedPaths(record["freshnessCheckRefs"], fmt.Sprintf("rendered artifact freshness %s freshnessCheckRefs", artifactID), false)
	if err != nil {
		return artifactInput{}, err
	}
	nonClaims, err := sortedText(record["nonClaims"], fmt.Sprintf("rendered artifact freshness %s nonClaims", artifactID), false)
	if err != nil {
		return artifactInput{}, err
	}
	return artifactInput{
		ArtifactFormat:                artifactFormat,
		ArtifactID:                    artifactID,
		ArtifactKind:                  artifactKind,
		ArtifactPath:                  artifactPath,
		Authority:                     authority,
		CurrentArtifactDigest:         currentArtifactDigest,
		CurrentGenerationScopeDigest:  currentGenerationScopeDigest,
		CurrentRendererDigest:         currentRendererDigest,
		CurrentRendererVersion:        currentRendererVersion,
		CurrentSourceDigest:           currentSourceDigest,
		FreshnessCheckRefs:            freshnessCheckRefs,
		GenerationScopeID:             generationScopeID,
		NonClaims:                     nonClaims,
		RecordedArtifactDigest:        recordedArtifactDigest,
		RecordedGenerationScopeDigest: recordedGenerationScopeDigest,
		RecordedRendererDigest:        recordedRendererDigest,
		RecordedRendererVersion:       recordedRendererVersion,
		RecordedSourceDigest:          recordedSourceDigest,
		RendererID:                    rendererID,
		SourceRefs:                    sourceRefs,
	}, nil
}

func artifactFailures(artifact artifactInput) []string {
	failures := []string{}
	expectedAuthority := expectedArtifactAuthority(artifact.ArtifactKind)
	if artifact.Authority != expectedAuthority {
		failures = append(failures, fmt.Sprintf("rendered or generated artifact must use %s authority: %s", expectedAuthority, artifact.ArtifactID))
	}
	if artifact.RecordedSourceDigest != artifact.CurrentSourceDigest {
		failures = append(failures, fmt.Sprintf("rendered artifact source digest drifted: %s", artifact.ArtifactID))
	}
	if artifact.RecordedRendererVersion != artifact.CurrentRendererVersion {
		failures = append(failures, fmt.Sprintf("rendered artifact renderer version drifted: %s", artifact.ArtifactID))
	}
	if artifact.RecordedRendererDigest != artifact.CurrentRendererDigest {
		failures = append(failures, fmt.Sprintf("rendered artifact renderer digest drifted: %s", artifact.ArtifactID))
	}
	if artifact.RecordedGenerationScopeDigest != artifact.CurrentGenerationScopeDigest {
		failures = append(failures, fmt.Sprintf("rendered artifact generation scope digest drifted: %s", artifact.ArtifactID))
	}
	if artifact.RecordedArtifactDigest != artifact.CurrentArtifactDigest {
		failures = append(failures, fmt.Sprintf("rendered artifact digest drifted: %s", artifact.ArtifactID))
	}
	return failures
}

func expectedArtifactAuthority(kind string) string {
	if kind == "generated_lookup" {
		return "lookup_only"
	}
	return "presentation_only"
}

func artifactsDiagnostic(artifacts []artifactInput) []any {
	result := make([]any, 0, len(artifacts))
	for _, artifact := range artifacts {
		result = append(result, map[string]any{
			"artifactFormat":    artifact.ArtifactFormat,
			"artifactId":        artifact.ArtifactID,
			"artifactKind":      artifact.ArtifactKind,
			"artifactPath":      artifact.ArtifactPath,
			"authority":         artifact.Authority,
			"generationScopeId": artifact.GenerationScopeID,
			"rendererId":        artifact.RendererID,
		})
	}
	return result
}

func ruleResults(failures []string) []report.RuleResult {
	failureDiagnostics := make([]report.Diagnostic, 0, len(failures))
	for index, failure := range failures {
		failureDiagnostics = append(failureDiagnostics, report.Diagnostic{
			Key:   fmt.Sprintf("failure.%03d", index+1),
			Value: failure,
		})
	}
	return []report.RuleResult{
		{
			RuleID:      "proofkit.rendered-artifact-freshness.artifacts",
			Status:      statusFromFailures(failures),
			Message:     "generated artifacts must be lookup-only, rendered artifacts must be presentation-only, and recorded/current source, renderer, scope, and artifact digests must match",
			Diagnostics: failureDiagnostics,
		},
		{
			RuleID:      "proofkit.rendered-artifact-freshness.boundary",
			Status:      "passed",
			Message:     "rendered artifact freshness validates caller-provided digest facts without reading files or running renderers",
			Diagnostics: []report.Diagnostic{},
		},
	}
}

func statusFromFailures(failures []string) string {
	if len(failures) == 0 {
		return "passed"
	}
	return "failed"
}

func countArtifacts(artifacts []artifactInput, kind string) int {
	count := 0
	for _, artifact := range artifacts {
		if artifact.ArtifactKind == kind {
			count++
		}
	}
	return count
}

func sortedPaths(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique path array", context)
	}
	paths := make([]string, 0, len(values))
	for _, value := range values {
		textValue, err := text(value, context)
		if err != nil {
			return nil, err
		}
		pathValue, err := admit.SafeRepoRelativePath(textValue, context)
		if err != nil {
			return nil, err
		}
		paths = append(paths, pathValue)
	}
	return preserveSortedUnique(paths, context, allowEmpty)
}

func sortedText(raw any, context string, allowEmpty bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a sorted unique string array", context)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		textValue, err := text(value, context)
		if err != nil {
			return nil, err
		}
		result = append(result, textValue)
	}
	return preserveSortedUnique(result, context, allowEmpty)
}

func sortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	sort.Strings(values)
	return preserveSortedUnique(values, context, allowEmpty)
}

func preserveSortedUnique(values []string, context string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, fmt.Errorf("%s must be non-empty", context)
	}
	for index := 0; index < len(values); index++ {
		if index > 0 && values[index-1] >= values[index] {
			return nil, fmt.Errorf("%s must be sorted and unique", context)
		}
	}
	return values, nil
}

func text(raw any, context string) (string, error) {
	return admit.NonEmptyText(raw, context)
}

func digest(raw any, context string) (string, error) {
	value, ok := raw.(string)
	if !ok || !digestPattern.MatchString(value) {
		return "", fmt.Errorf("%s must be sha256:<64 lowercase hex>", context)
	}
	return value, nil
}

func enum(raw any, values map[string]struct{}, context string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, admit.SortedEnum(values))
	}
	if _, ok := values[value]; !ok {
		return "", fmt.Errorf("%s must be one of: %s", context, admit.SortedEnum(values))
	}
	return value, nil
}
