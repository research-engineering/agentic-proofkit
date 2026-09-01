package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type codecSelection struct {
	SchemaVersion      int                 `json:"schemaVersion"`
	Kind               string              `json:"kind"`
	ScreenEvidence     screenEvidence      `json:"screenEvidence"`
	Roles              selectionRoles      `json:"roles"`
	JSONLayoutOrder    []string            `json:"jsonLayoutOrder"`
	MetricRegistry     []selectionMetric   `json:"metricRegistry"`
	ReplacementPolicy  replacementPolicy   `json:"replacementPolicy"`
	ScreenObservations []screenObservation `json:"screenObservations"`
	Decision           selectionDecision   `json:"decision"`
	HardGateSelectors  []string            `json:"hardGateSelectors"`
	NonClaims          []string            `json:"nonClaims"`
}

type screenEvidence struct {
	ArchiveFormat       string           `json:"archiveFormat"`
	ArchivePath         string           `json:"archivePath"`
	ArchiveSHA256       string           `json:"archiveSha256"`
	RootPath            string           `json:"rootPath"`
	TreeDigestAlgorithm string           `json:"treeDigestAlgorithm"`
	TreeSHA256          string           `json:"treeSha256"`
	ArtifactCount       int              `json:"artifactCount"`
	Artifacts           []screenArtifact `json:"artifacts"`
}

type screenArtifact struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type selectionRoles struct {
	StatusQuoComparators      []string `json:"statusQuoComparators"`
	ModelAblations            []string `json:"modelAblations"`
	ScreenOnlyComparators     []string `json:"screenOnlyComparators"`
	JSONLayouts               []string `json:"jsonLayouts"`
	RestrictedTextChallengers []string `json:"restrictedTextChallengers"`
	CodecCandidates           []string `json:"codecCandidates"`
}

type selectionMetric struct {
	MetricID          string `json:"metricId"`
	Stage             string `json:"stage"`
	Role              string `json:"role"`
	Direction         string `json:"direction"`
	Baseline          string `json:"baseline"`
	Aggregation       string `json:"aggregation"`
	Requirement       string `json:"requirement"`
	Missing           string `json:"missing"`
	MaterialThreshold int    `json:"materialThreshold"`
}

type replacementPolicy struct {
	MinimumByteImprovementBasisPoints         int `json:"minimumByteImprovementBasisPoints"`
	MinimumTokenImprovementBasisPoints        int `json:"minimumTokenImprovementBasisPoints"`
	MaximumAggregateDiffRegressionBasisPoints int `json:"maximumAggregateDiffRegressionBasisPoints"`
	MaximumPerEditDiffRegressionBasisPoints   int `json:"maximumPerEditDiffRegressionBasisPoints"`
	MinimumReviewAccuracyBasisPoints          int `json:"minimumReviewAccuracyBasisPoints"`
	MaximumInvalidMutationFalseAccepts        int `json:"maximumInvalidMutationFalseAccepts"`
	MaximumProjectedProductionCostBasisPoints int `json:"maximumProjectedProductionCostBasisPoints"`
}

type screenObservation struct {
	CandidateID                        string `json:"candidateId"`
	FieldClosure                       string `json:"fieldClosure"`
	ReviewAccuracyBasisPoints          *int   `json:"reviewAccuracyBasisPoints"`
	InvalidMutationFalseAccepts        *int   `json:"invalidMutationFalseAccepts"`
	EditLocality                       bool   `json:"editLocality"`
	WeightedCanonicalBytes             int    `json:"weightedCanonicalBytes"`
	WeightedTokensO200kBase            int    `json:"weightedTokensO200kBase"`
	ChangedLines                       int    `json:"changedLines"`
	ChangedBytes                       int    `json:"changedBytes"`
	ProjectedProductionLOC             int    `json:"projectedProductionLoc"`
	ProjectedProductionBranches        int    `json:"projectedProductionBranches"`
	AggregateDiffRegressionBasisPoints *int   `json:"aggregateDiffRegressionBasisPoints"`
	PerEditDiffRegressionBasisPoints   *int   `json:"perEditDiffRegressionBasisPoints"`
	ParseTimeState                     string `json:"parseTimeState"`
	FormatTimeState                    string `json:"formatTimeState"`
	LowerCostDominanceState            string `json:"lowerCostDominanceState"`
}

type selectionDecision struct {
	State                  string  `json:"state"`
	SelectedJSONLayout     string  `json:"selectedJsonLayout"`
	SelectedChallenger     *string `json:"selectedChallenger"`
	SelectedCodec          string  `json:"selectedCodec"`
	ProductionGrammarCount int     `json:"productionGrammarCount"`
}

func TestSelectionRecordIsClosedAndDecisionIsReproducible(t *testing.T) {
	record := readCodecSelection(t)
	if record.SchemaVersion != 1 || record.Kind != "proofkit.requirement-source-codec-selection" {
		t.Fatalf("selection identity = %#v", record)
	}
	assertScreenEvidenceMetadata(t, record.ScreenEvidence)
	assertJSONLayoutOrder(t, record.JSONLayoutOrder)
	assertSortedUniqueMetricRegistry(t, record.MetricRegistry)
	assertReplacementPolicy(t, record.ReplacementPolicy)
	assertDisjointRoles(t, record.Roles)
	assertExactRoles(t, record.Roles)
	assertObservationClosure(t, record)
	selectedJSON := selectJSONLayout(record)
	if selectedJSON != record.Decision.SelectedJSONLayout || selectedJSON != "json-hybrid-v1" {
		t.Fatalf("selected JSON = %q, record = %q", selectedJSON, record.Decision.SelectedJSONLayout)
	}
	if challengerEligible(record) || record.Decision.SelectedChallenger != nil {
		t.Fatal("restricted-text challenger was admitted without passing its screen")
	}
	if record.Decision.State != "grouped_json_only" || record.Decision.SelectedCodec != "grouped-json-v1" || record.Decision.ProductionGrammarCount != 1 {
		t.Fatalf("selection decision = %#v", record.Decision)
	}
	if !reflect.DeepEqual(record.Roles.CodecCandidates, []string{"grouped-json-v1"}) {
		t.Fatalf("production codec candidates = %v", record.Roles.CodecCandidates)
	}
	assertHardGateSelectorsExact(t, record.HardGateSelectors)
	assertTestSelectorsExist(t, record.HardGateSelectors)
}

func readCodecSelection(t *testing.T) codecSelection {
	t.Helper()
	payload, err := os.ReadFile("testdata/codec-selection.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	record, err := admission.DecodeTypedJSON[codecSelection](bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var strict codecSelection
	if err := decoder.Decode(&strict); err != nil {
		t.Fatal(err)
	}
	return record
}

func assertScreenEvidenceMetadata(t *testing.T, value screenEvidence) {
	t.Helper()
	if value.ArchiveFormat != "tar+gzip" || value.ArchivePath != "testdata/screen-v3.tgz" || value.RootPath != "." || value.TreeDigestAlgorithm != "sha256(sorted(relative-path NUL file-sha256 LF))" || value.ArtifactCount != 197 {
		t.Fatalf("screen evidence root = %#v", value)
	}
	pathClean := filepath.ToSlash(filepath.Clean(value.ArchivePath))
	if filepath.IsAbs(value.ArchivePath) || pathClean != value.ArchivePath || strings.HasPrefix(pathClean, "../") {
		t.Fatalf("unsafe screen archive path %q", value.ArchivePath)
	}
	if _, err := admit.LowercaseSHA256(value.ArchiveSHA256, "archiveSha256"); err != nil {
		t.Fatalf("invalid screen archive digest %q", value.ArchiveSHA256)
	}
	if _, err := admit.LowercaseSHA256(value.TreeSHA256, "treeSha256"); err != nil {
		t.Fatalf("invalid screen tree digest %q", value.TreeSHA256)
	}
	wantRoles := []string{"fixture-index", "independent-validation", "observations", "review-results", "screen-decision", "screen-manifest", "selection-opening", "token-go", "token-python"}
	roles := make([]string, len(value.Artifacts))
	for index, artifact := range value.Artifacts {
		roles[index] = artifact.Role
		if artifact.Path == "" || filepath.IsAbs(artifact.Path) || strings.Contains(artifact.Path, "..") {
			t.Fatalf("unsafe screen artifact path %q", artifact.Path)
		}
		if _, err := admit.LowercaseSHA256(artifact.SHA256, artifact.Role); err != nil {
			t.Fatalf("invalid screen artifact digest %q", artifact.SHA256)
		}
	}
	if !reflect.DeepEqual(roles, wantRoles) {
		t.Fatalf("screen artifact roles = %v, want %v", roles, wantRoles)
	}
}

func assertJSONLayoutOrder(t *testing.T, order []string) {
	t.Helper()
	want := []string{"weighted_tokens_o200k_base", "weighted_canonical_bytes", "changed_bytes", "changed_lines", "candidate_id"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("JSON layout order = %v, want %v", order, want)
	}
}

func assertSortedUniqueMetricRegistry(t *testing.T, metrics []selectionMetric) {
	t.Helper()
	ids := make([]string, len(metrics))
	for index, metric := range metrics {
		ids[index] = metric.MetricID
		if metric.MetricID == "" || metric.Stage == "" || metric.Role == "" || metric.Direction == "" || metric.Baseline == "" || metric.Aggregation == "" || metric.Requirement == "" || metric.Missing == "" || metric.MaterialThreshold < 0 {
			t.Fatalf("incomplete metric row %#v", metric)
		}
	}
	want := append([]string(nil), ids...)
	sort.Strings(want)
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("metric IDs = %v, want sorted unique %v", ids, want)
	}
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			t.Fatalf("duplicate metric %q", ids[index])
		}
	}
	wantIDs := []string{
		"aggregate_diff_regression_basis_points", "changed_bytes", "changed_lines", "edit_locality", "field_closure", "format_time_state",
		"invalid_mutation_false_accepts", "lower_cost_dominance_state", "parse_time_state", "per_edit_diff_regression_basis_points",
		"projected_production_branches", "projected_production_loc", "review_accuracy_basis_points",
		"weighted_canonical_bytes", "weighted_tokens_o200k_base",
	}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("metric IDs = %v, want exact registry %v", ids, wantIDs)
	}
	for _, metric := range metrics {
		if metric.Stage == "replacement" {
			if metric.Role != "hard" || metric.Missing != "reject" {
				t.Fatalf("replacement performance metric = %#v", metric)
			}
		} else if metric.Stage != "screen" {
			t.Fatalf("screen metric %q has stage %q", metric.MetricID, metric.Stage)
		}
	}
}

func assertReplacementPolicy(t *testing.T, policy replacementPolicy) {
	t.Helper()
	want := replacementPolicy{
		MinimumByteImprovementBasisPoints:         1000,
		MinimumTokenImprovementBasisPoints:        1000,
		MaximumAggregateDiffRegressionBasisPoints: 500,
		MaximumPerEditDiffRegressionBasisPoints:   1500,
		MinimumReviewAccuracyBasisPoints:          10000,
		MaximumInvalidMutationFalseAccepts:        0,
		MaximumProjectedProductionCostBasisPoints: 15000,
	}
	if policy != want {
		t.Fatalf("replacement policy = %#v, want %#v", policy, want)
	}
}

func assertDisjointRoles(t *testing.T, roles selectionRoles) {
	t.Helper()
	sets := [][]string{
		roles.StatusQuoComparators, roles.ModelAblations, roles.ScreenOnlyComparators,
		roles.JSONLayouts, roles.RestrictedTextChallengers, roles.CodecCandidates,
	}
	seen := map[string]struct{}{}
	for _, values := range sets {
		if len(values) == 0 || !sort.StringsAreSorted(values) {
			t.Fatalf("role set is empty or unsorted: %v", values)
		}
		for _, value := range values {
			if _, exists := seen[value]; exists {
				t.Fatalf("candidate %q has multiple roles", value)
			}
			seen[value] = struct{}{}
		}
	}
}

func assertExactRoles(t *testing.T, roles selectionRoles) {
	t.Helper()
	want := selectionRoles{
		StatusQuoComparators: []string{"flat-v1"},
		ModelAblations: []string{
			"grouped-profile-off-stem-off", "grouped-profile-off-stem-on",
			"grouped-profile-on-stem-off", "grouped-profile-on-stem-on",
		},
		ScreenOnlyComparators:     []string{"toml-tristate-v1", "yaml-strict-v1"},
		JSONLayouts:               []string{"json-compact-v1", "json-hybrid-v1", "json-pretty-v1"},
		RestrictedTextChallengers: []string{"proofkit-source-text-v1"},
		CodecCandidates:           []string{"grouped-json-v1"},
	}
	if !reflect.DeepEqual(roles, want) {
		t.Fatalf("selection roles = %#v, want %#v", roles, want)
	}
}

func assertObservationClosure(t *testing.T, record codecSelection) {
	t.Helper()
	want := append([]string(nil), record.Roles.JSONLayouts...)
	want = append(want, record.Roles.ScreenOnlyComparators...)
	want = append(want, record.Roles.RestrictedTextChallengers...)
	sort.Strings(want)
	actual := make([]string, len(record.ScreenObservations))
	allowedState := map[string]bool{"failed": true, "missing": true, "not_applicable": true, "passed": true}
	challengers := stringSet(record.Roles.RestrictedTextChallengers)
	for index, observation := range record.ScreenObservations {
		actual[index] = observation.CandidateID
		if observation.CandidateID == "" || observation.WeightedCanonicalBytes <= 0 || observation.WeightedTokensO200kBase <= 0 ||
			observation.ChangedLines < 0 || observation.ChangedBytes < 0 || observation.ProjectedProductionLOC <= 0 || observation.ProjectedProductionBranches <= 0 {
			t.Fatalf("candidate %q has invalid quantitative observation", observation.CandidateID)
		}
		if observation.ReviewAccuracyBasisPoints != nil && (*observation.ReviewAccuracyBasisPoints < 0 || *observation.ReviewAccuracyBasisPoints > 10000) {
			t.Fatalf("candidate %q has invalid review accuracy", observation.CandidateID)
		}
		if observation.InvalidMutationFalseAccepts != nil && *observation.InvalidMutationFalseAccepts < 0 {
			t.Fatalf("candidate %q has invalid false-accept count", observation.CandidateID)
		}
		states := []string{observation.ParseTimeState, observation.FormatTimeState, observation.LowerCostDominanceState}
		for _, state := range states {
			if !allowedState[state] {
				t.Fatalf("candidate %q has invalid replacement state %q", observation.CandidateID, state)
			}
		}
		if _, isChallenger := challengers[observation.CandidateID]; !isChallenger {
			if observation.AggregateDiffRegressionBasisPoints != nil || observation.PerEditDiffRegressionBasisPoints != nil {
				t.Fatalf("non-challenger %q has replacement diff observations", observation.CandidateID)
			}
			for _, state := range states {
				if state != "not_applicable" {
					t.Fatalf("non-challenger %q has replacement state %q", observation.CandidateID, state)
				}
			}
		} else if observation.AggregateDiffRegressionBasisPoints == nil || observation.PerEditDiffRegressionBasisPoints == nil || *observation.AggregateDiffRegressionBasisPoints < 0 || *observation.PerEditDiffRegressionBasisPoints < 0 {
			t.Fatalf("challenger %q lacks bounded diff observations", observation.CandidateID)
		}
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("screen observations = %v, want %v", actual, want)
	}
}

func (value *screenObservation) UnmarshalJSON(payload []byte) error {
	type alias screenObservation
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded alias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	required := []string{
		"candidateId", "fieldClosure", "reviewAccuracyBasisPoints", "invalidMutationFalseAccepts", "editLocality",
		"weightedCanonicalBytes", "weightedTokensO200kBase", "changedLines", "changedBytes", "projectedProductionLoc",
		"projectedProductionBranches", "aggregateDiffRegressionBasisPoints", "perEditDiffRegressionBasisPoints",
		"parseTimeState", "formatTimeState", "lowerCostDominanceState",
	}
	if len(fields) != len(required) {
		return fmt.Errorf("screen observation must contain exactly %d fields", len(required))
	}
	for _, field := range required {
		if _, exists := fields[field]; !exists {
			return fmt.Errorf("screen observation is missing %s", field)
		}
	}
	*value = screenObservation(decoded)
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func assertHardGateSelectorsExact(t *testing.T, selectors []string) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "proofkit", "requirement-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bindings struct {
		Bindings []struct {
			RequirementID    string `json:"requirementId"`
			WitnessSelectors []struct {
				Selector string `json:"selector"`
			} `json:"witnessSelectors"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(payload, &bindings); err != nil {
		t.Fatal(err)
	}
	want := []string{}
	for _, binding := range bindings.Bindings {
		if binding.RequirementID != "REQ-PROOFKIT-SPEC-025" {
			continue
		}
		for _, witness := range binding.WitnessSelectors {
			want = append(want, witness.Selector)
		}
	}
	if !reflect.DeepEqual(selectors, want) {
		t.Fatalf("hard-gate selectors = %v, want %v", selectors, want)
	}
}

func assertTestSelectorsExist(t *testing.T, selectors []string) {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]struct{}{}
	for _, path := range files {
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil {
				found[function.Name.Name] = struct{}{}
			}
		}
	}
	for _, selector := range selectors {
		if _, exists := found[selector]; !exists {
			t.Fatalf("hard-gate selector %q does not exist", selector)
		}
	}
}
