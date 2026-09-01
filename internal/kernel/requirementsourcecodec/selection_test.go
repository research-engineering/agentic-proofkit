package requirementsourcecodec

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

type codecSelection struct {
	SchemaVersion      int                 `json:"schemaVersion"`
	Kind               string              `json:"kind"`
	ScreenEvidence     screenEvidence      `json:"screenEvidence"`
	Roles              selectionRoles      `json:"roles"`
	MetricRegistry     []selectionMetric   `json:"metricRegistry"`
	ReplacementPolicy  replacementPolicy   `json:"replacementPolicy"`
	ScreenObservations []screenObservation `json:"screenObservations"`
	Decision           selectionDecision   `json:"decision"`
	HardGateSelectors  []string            `json:"hardGateSelectors"`
	NonClaims          []string            `json:"nonClaims"`
}

type screenEvidence struct {
	ScreenManifestVersion       int               `json:"screenManifestVersion"`
	ScreenManifestSHA256        string            `json:"screenManifestSha256"`
	SelectionOpeningSHA256      string            `json:"selectionOpeningSha256"`
	FixtureIndexSHA256          string            `json:"fixtureIndexSha256"`
	ObservationsSHA256          string            `json:"observationsSha256"`
	IndependentValidationSHA256 string            `json:"independentValidationSha256"`
	ReviewResultsSHA256         string            `json:"reviewResultsSha256"`
	TokenProducerDigests        map[string]string `json:"tokenProducerDigests"`
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
	CandidateID                 string `json:"candidateId"`
	FieldClosure                string `json:"fieldClosure"`
	ReviewAccuracyBasisPoints   *int   `json:"reviewAccuracyBasisPoints"`
	InvalidMutationFalseAccepts *int   `json:"invalidMutationFalseAccepts"`
	EditLocality                bool   `json:"editLocality"`
	WeightedCanonicalBytes      int    `json:"weightedCanonicalBytes"`
	WeightedTokensO200kBase     int    `json:"weightedTokensO200kBase"`
	ChangedLines                int    `json:"changedLines"`
	ChangedBytes                int    `json:"changedBytes"`
	ProjectedProductionLOC      int    `json:"projectedProductionLoc"`
	ProjectedProductionBranches int    `json:"projectedProductionBranches"`
	AggregateDiffState          string `json:"aggregateDiffState"`
	PerEditDiffState            string `json:"perEditDiffState"`
	ParseTimeState              string `json:"parseTimeState"`
	FormatTimeState             string `json:"formatTimeState"`
	LowerCostDominanceState     string `json:"lowerCostDominanceState"`
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
	if record.SchemaVersion != 1 || record.Kind != "proofkit.requirement-source-codec-selection" || record.ScreenEvidence.ScreenManifestVersion != 3 {
		t.Fatalf("selection identity = %#v", record)
	}
	assertScreenDigests(t, record.ScreenEvidence)
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

func assertScreenDigests(t *testing.T, value screenEvidence) {
	t.Helper()
	digests := []string{
		value.ScreenManifestSHA256, value.SelectionOpeningSHA256, value.FixtureIndexSHA256,
		value.ObservationsSHA256, value.IndependentValidationSHA256, value.ReviewResultsSHA256,
	}
	for _, digest := range value.TokenProducerDigests {
		digests = append(digests, digest)
	}
	for _, digest := range digests {
		if _, err := admit.LowercaseSHA256(digest, "digest"); err != nil {
			t.Fatalf("invalid screen digest %q", digest)
		}
	}
	wantProducers := []string{"openai-tiktoken-0.14.0", "tiktoken-go-0.8.1"}
	actualProducers := make([]string, 0, len(value.TokenProducerDigests))
	for producer := range value.TokenProducerDigests {
		actualProducers = append(actualProducers, producer)
	}
	sort.Strings(actualProducers)
	if !reflect.DeepEqual(actualProducers, wantProducers) {
		t.Fatalf("token producers = %v, want %v", actualProducers, wantProducers)
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
		"changed_bytes", "changed_lines", "edit_locality", "field_closure", "format_time",
		"invalid_mutation_false_accepts", "parse_time", "projected_production_branches",
		"projected_production_loc", "review_accuracy_basis_points", "weighted_canonical_bytes",
		"weighted_tokens_o200k_base",
	}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("metric IDs = %v, want exact registry %v", ids, wantIDs)
	}
	for _, metric := range metrics {
		if metric.MetricID == "parse_time" || metric.MetricID == "format_time" {
			if metric.Stage != "replacement" || metric.Role != "primary" || metric.Direction != "minimize" || metric.Missing != "reject" || metric.Requirement != "noninferior" {
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
		states := []string{observation.AggregateDiffState, observation.PerEditDiffState, observation.ParseTimeState, observation.FormatTimeState, observation.LowerCostDominanceState}
		for _, state := range states {
			if !allowedState[state] {
				t.Fatalf("candidate %q has invalid replacement state %q", observation.CandidateID, state)
			}
		}
		if _, isChallenger := challengers[observation.CandidateID]; !isChallenger {
			for _, state := range states {
				if state != "not_applicable" {
					t.Fatalf("non-challenger %q has replacement state %q", observation.CandidateID, state)
				}
			}
		}
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("screen observations = %v, want %v", actual, want)
	}
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
	want := []string{
		"TestFieldManifestMatchesWireDTOAndClosedShape",
		"TestFormatParseRoundTripPreservesEveryProjection",
		"TestCanonicalFormatIsIdempotent",
		"TestChallengerEligibilityRequiresEveryReplacementPredicate",
		"TestCodecMutantManifestClosesRepresentationFailures",
		"TestParseDiagnosticsDoNotDiscloseCallerTextOrDynamicKeys",
		"TestRawByteBoundaryIsExactAndDominatesUTF8",
		"TestHybridLayoutKeepsStableSiblingEntityLinesUnchanged",
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
