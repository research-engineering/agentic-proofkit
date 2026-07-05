package conformanceprofile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/markdownfmt"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.conformance-profile"

type Input struct {
	Manifest      Manifest
	Policy        Policy
	ProfileID     string
	ProofContract ProofContract
}

type Manifest struct {
	AuthorityState       string
	ContractID           string
	ContractKind         string
	NonClaims            []string
	NormalizationProfile string
	Profiles             []Profile
	SourceContract       string
}

type Profile struct {
	AllowedEnvironmentClasses []string
	NonClaims                 []string
	OptionalSurfaceIDs        []string
	PreconditionPolicy        string
	ProfileID                 string
	Purpose                   string
	RequiredSurfaceIDs        []string
}

type ProofContract struct {
	Bindings   []Binding
	ContractID string
	Surfaces   []Surface
}

type Surface struct {
	PreconditionedEnvironmentClasses []string
	RequiredEnvironmentClasses       []string
	SurfaceID                        string
}

type Binding struct {
	BlockingStatus             string
	ProofContractState         string
	RequiredEnvironmentClasses []string
	RequirementID              string
	ScenarioID                 string
	SurfaceID                  string
	VerifyCommands             []string
	WitnessRefs                []WitnessRef
}

type WitnessRef struct {
	Role     string
	Selector string
}

type Policy struct {
	AllowedProofContractStates     map[string]struct{}
	BlockingStatuses               map[string]struct{}
	ExpectedManifest               ExpectedManifest
	FailOnUnusedAllowedEnvironment bool
	KnownEnvironmentClasses        map[string]struct{}
	LocalEnvironmentClasses        map[string]struct{}
}

type ExpectedManifest struct {
	AuthorityState       string
	ContractID           string
	ContractKind         string
	NonClaims            []string
	NormalizationProfile string
	SourceContract       string
}

type ProfileReport struct {
	CommandCount                   int
	CommandExecutionState          string
	EnvironmentClasses             []string
	Failures                       []string
	NonClaims                      []string
	OptionalSurfaceCount           int
	PreconditionedRequirementCount int
	ProfileID                      string
	ProfileResolutionState         string
	Purpose                        string
	RequirementCount               int
	RequiredSurfaceCount           int
	ScenarioCount                  int
	SurfaceCount                   int
	Surfaces                       []string
	VerifyCommands                 []string
	WitnessMappingCount            int
}

type Result struct {
	ExitCode      int
	ProfileReport ProfileReport
	Report        report.Record
}

func BuildVerification(raw any) (report.Record, int, error) {
	result := Verify(raw)
	record := report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "proofkit.conformance-profile.all",
		State:         stateForFailures(result.Failures),
		Summary: map[string]any{
			"profileCount": result.ProfileCount,
		},
		Diagnostics: []report.Diagnostic{},
		RuleResults: ruleResults(result.Failures),
		NonClaims:   admit.StringSliceToAny(result.NonClaims),
	}
	return record, exitCode(record.State), nil
}

func BuildProfile(raw any, profileID string) (Result, error) {
	input, err := admitInput(raw)
	if err != nil {
		return Result{}, err
	}
	selectedProfileID := profileID
	if selectedProfileID == "" {
		selectedProfileID = input.ProfileID
	}
	var selected *Profile
	for index := range input.Manifest.Profiles {
		if input.Manifest.Profiles[index].ProfileID == selectedProfileID {
			selected = &input.Manifest.Profiles[index]
			break
		}
	}
	if selected == nil {
		return Result{}, fmt.Errorf("unknown conformance profile %s", selectedProfileID)
	}
	profileReport := buildProfileReport(*selected, input.ProofContract, input.Policy)
	record := standardReportForProfile(profileReport)
	return Result{ExitCode: exitCode(record.State), ProfileReport: profileReport, Report: record}, nil
}

func List(raw any) ([]string, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(input.Manifest.Profiles))
	for _, profile := range input.Manifest.Profiles {
		ids = append(ids, profile.ProfileID)
	}
	sort.Strings(ids)
	return ids, nil
}

type VerificationResult struct {
	Failures     []string
	NonClaims    []string
	ProfileCount int
}

func Verify(raw any) VerificationResult {
	input, err := admitInput(raw)
	if err != nil {
		return VerificationResult{Failures: []string{err.Error()}, NonClaims: []string{}, ProfileCount: 0}
	}
	failures := []string{}
	seen := map[string]struct{}{}
	for _, profile := range input.Manifest.Profiles {
		if _, ok := seen[profile.ProfileID]; ok {
			failures = append(failures, "duplicate profileId="+profile.ProfileID)
		}
		seen[profile.ProfileID] = struct{}{}
		failures = append(failures, validateProfile(profile, input.ProofContract, input.Policy)...)
	}
	failures = uniqueSorted(failures)
	return VerificationResult{
		Failures:     failures,
		NonClaims:    input.Policy.ExpectedManifest.NonClaims,
		ProfileCount: len(input.Manifest.Profiles),
	}
}

func Markdown(profile ProfileReport) string {
	lines := []string{
		"# Conformance Profile: " + markdownfmt.Text(profile.ProfileID),
		"",
		"Scope resolution: " + profile.ProfileResolutionState,
		"Command execution: not run by this report.",
		"",
		markdownfmt.Text(profile.Purpose),
		"",
		"## Scope",
		"",
		fmt.Sprintf("- Surfaces: %d", profile.SurfaceCount),
		fmt.Sprintf("- Requirements: %d", profile.RequirementCount),
		fmt.Sprintf("- Scenarios: %d", profile.ScenarioCount),
		fmt.Sprintf("- Witness mappings: %d", profile.WitnessMappingCount),
		fmt.Sprintf("- Commands: %d", profile.CommandCount),
		fmt.Sprintf("- Preconditioned requirements: %d", profile.PreconditionedRequirementCount),
		"- Environment classes: " + strings.Join(profile.EnvironmentClasses, ", "),
		"",
		"## Verify Commands",
		"",
	}
	for _, command := range profile.VerifyCommands {
		lines = append(lines, "- "+markdownfmt.CodeSpan(command))
	}
	lines = append(lines, "", "## Non-Claims", "")
	for _, claim := range profile.NonClaims {
		lines = append(lines, "- "+markdownfmt.Text(claim))
	}
	lines = append(lines, "", "")
	return strings.Join(lines, "\n")
}

func admitInput(raw any) (Input, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Input{}, fmt.Errorf("proofkit conformance profile input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"manifest", "policy", "profileId", "proofContract", "schemaVersion"}, "proofkit conformance profile input"); err != nil {
		return Input{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Input{}, fmt.Errorf("proofkit conformance profile input schemaVersion must be 1")
	}
	policy, err := admitPolicy(record["policy"])
	if err != nil {
		return Input{}, err
	}
	manifest, err := admitManifest(record["manifest"], policy)
	if err != nil {
		return Input{}, err
	}
	proofContract, err := admitProofContract(record["proofContract"])
	if err != nil {
		return Input{}, err
	}
	profileID := ""
	if rawProfileID, ok := record["profileId"]; ok {
		profileID, err = nonEmptyText(rawProfileID, "conformance profile input profileId")
		if err != nil {
			return Input{}, err
		}
	}
	return Input{Manifest: manifest, Policy: policy, ProfileID: profileID, ProofContract: proofContract}, nil
}

func admitPolicy(raw any) (Policy, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Policy{}, fmt.Errorf("conformance profile policy must be an object")
	}
	if err := admit.KnownKeys(record, []string{"allowedProofContractStates", "blockingStatuses", "expectedManifest", "failOnUnusedAllowedEnvironmentClass", "knownEnvironmentClasses", "localEnvironmentClasses"}, "conformance profile policy"); err != nil {
		return Policy{}, err
	}
	known, err := stringArray(record["knownEnvironmentClasses"], "conformance profile policy knownEnvironmentClasses", false, true)
	if err != nil {
		return Policy{}, err
	}
	local, err := stringArray(record["localEnvironmentClasses"], "conformance profile policy localEnvironmentClasses", false, true)
	if err != nil {
		return Policy{}, err
	}
	for _, environmentClass := range local {
		if !contains(known, environmentClass) {
			return Policy{}, fmt.Errorf("local environment class %s is not in knownEnvironmentClasses", environmentClass)
		}
	}
	allowedStates, err := stringArray(record["allowedProofContractStates"], "conformance profile policy allowedProofContractStates", false, true)
	if err != nil {
		return Policy{}, err
	}
	blockingStatuses, err := stringArray(record["blockingStatuses"], "conformance profile policy blockingStatuses", false, true)
	if err != nil {
		return Policy{}, err
	}
	expected, err := expectedManifest(record["expectedManifest"])
	if err != nil {
		return Policy{}, err
	}
	failOnUnused := true
	if value, ok := record["failOnUnusedAllowedEnvironmentClass"]; ok {
		boolean, ok := value.(bool)
		if !ok {
			return Policy{}, fmt.Errorf("conformance profile policy failOnUnusedAllowedEnvironmentClass must be boolean")
		}
		failOnUnused = boolean
	}
	return Policy{
		AllowedProofContractStates:     set(allowedStates),
		BlockingStatuses:               set(blockingStatuses),
		ExpectedManifest:               expected,
		FailOnUnusedAllowedEnvironment: failOnUnused,
		KnownEnvironmentClasses:        set(known),
		LocalEnvironmentClasses:        set(local),
	}, nil
}

func expectedManifest(raw any) (ExpectedManifest, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return ExpectedManifest{}, fmt.Errorf("conformance profile expectedManifest must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authorityState", "contractId", "contractKind", "nonClaims", "normalizationProfile", "sourceContract"}, "conformance profile expectedManifest"); err != nil {
		return ExpectedManifest{}, err
	}
	nonClaims, err := stringArray(record["nonClaims"], "expectedManifest nonClaims", false, true)
	if err != nil {
		return ExpectedManifest{}, err
	}
	contractID, err := nonEmptyText(record["contractId"], "expectedManifest contractId")
	if err != nil {
		return ExpectedManifest{}, err
	}
	contractKind, err := nonEmptyText(record["contractKind"], "expectedManifest contractKind")
	if err != nil {
		return ExpectedManifest{}, err
	}
	authorityState, err := nonEmptyText(record["authorityState"], "expectedManifest authorityState")
	if err != nil {
		return ExpectedManifest{}, err
	}
	normalizationProfile, err := nonEmptyText(record["normalizationProfile"], "expectedManifest normalizationProfile")
	if err != nil {
		return ExpectedManifest{}, err
	}
	sourceContract, err := nonEmptyText(record["sourceContract"], "expectedManifest sourceContract")
	if err != nil {
		return ExpectedManifest{}, err
	}
	return ExpectedManifest{
		AuthorityState:       authorityState,
		ContractID:           contractID,
		ContractKind:         contractKind,
		NonClaims:            nonClaims,
		NormalizationProfile: normalizationProfile,
		SourceContract:       sourceContract,
	}, nil
}

func admitManifest(raw any, policy Policy) (Manifest, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Manifest{}, fmt.Errorf("conformance profile manifest must be an object")
	}
	if err := admit.KnownKeys(record, []string{"authorityState", "contractId", "contractKind", "nonClaims", "normalizationProfile", "profiles", "schemaVersion", "sourceContract"}, "conformance profile manifest"); err != nil {
		return Manifest{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return Manifest{}, fmt.Errorf("conformance profile manifest schemaVersion must be 1")
	}
	nonClaims, err := stringArray(record["nonClaims"], "conformance profile manifest nonClaims", false, true)
	if err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{NonClaims: nonClaims}
	if manifest.ContractID, err = nonEmptyText(record["contractId"], "conformance profile manifest contractId"); err != nil {
		return Manifest{}, err
	}
	if manifest.ContractKind, err = nonEmptyText(record["contractKind"], "conformance profile manifest contractKind"); err != nil {
		return Manifest{}, err
	}
	if manifest.AuthorityState, err = nonEmptyText(record["authorityState"], "conformance profile manifest authorityState"); err != nil {
		return Manifest{}, err
	}
	if manifest.NormalizationProfile, err = nonEmptyText(record["normalizationProfile"], "conformance profile manifest normalizationProfile"); err != nil {
		return Manifest{}, err
	}
	if manifest.SourceContract, err = nonEmptyText(record["sourceContract"], "conformance profile manifest sourceContract"); err != nil {
		return Manifest{}, err
	}
	if manifest.ContractID != policy.ExpectedManifest.ContractID {
		return Manifest{}, fmt.Errorf("conformance profile manifest contractId drift")
	}
	if manifest.ContractKind != policy.ExpectedManifest.ContractKind {
		return Manifest{}, fmt.Errorf("conformance profile manifest contractKind drift")
	}
	if manifest.AuthorityState != policy.ExpectedManifest.AuthorityState {
		return Manifest{}, fmt.Errorf("conformance profile manifest authorityState drift")
	}
	if manifest.NormalizationProfile != policy.ExpectedManifest.NormalizationProfile {
		return Manifest{}, fmt.Errorf("conformance profile manifest normalizationProfile drift")
	}
	if manifest.SourceContract != policy.ExpectedManifest.SourceContract {
		return Manifest{}, fmt.Errorf("conformance profile manifest sourceContract drift")
	}
	if strings.Join(manifest.NonClaims, "\n") != strings.Join(policy.ExpectedManifest.NonClaims, "\n") {
		return Manifest{}, fmt.Errorf("conformance profile manifest nonClaims drift")
	}
	profileValues, ok := record["profiles"].([]any)
	if !ok {
		return Manifest{}, fmt.Errorf("conformance profile manifest profiles must be an array")
	}
	profiles := make([]Profile, 0, len(profileValues))
	for index, value := range profileValues {
		profile, err := profileFrom(value, index)
		if err != nil {
			return Manifest{}, err
		}
		profiles = append(profiles, profile)
	}
	manifest.Profiles = profiles
	return manifest, nil
}

func admitProofContract(raw any) (ProofContract, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return ProofContract{}, fmt.Errorf("conformance proof contract must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bindings", "contractId", "surfaces"}, "conformance proof contract"); err != nil {
		return ProofContract{}, err
	}
	contractID, err := nonEmptyText(record["contractId"], "conformance proof contract contractId")
	if err != nil {
		return ProofContract{}, err
	}
	surfaceValues, ok := record["surfaces"].([]any)
	if !ok {
		return ProofContract{}, fmt.Errorf("conformance proof contract must declare surfaces and bindings arrays")
	}
	bindingValues, ok := record["bindings"].([]any)
	if !ok {
		return ProofContract{}, fmt.Errorf("conformance proof contract must declare surfaces and bindings arrays")
	}
	surfaces := make([]Surface, 0, len(surfaceValues))
	for _, value := range surfaceValues {
		surface, err := surfaceFrom(value)
		if err != nil {
			return ProofContract{}, err
		}
		surfaces = append(surfaces, surface)
	}
	if err := assertSortedUnique(ids(surfaces), "conformance proof contract surfaceIds"); err != nil {
		return ProofContract{}, err
	}
	bindings := make([]Binding, 0, len(bindingValues))
	for _, value := range bindingValues {
		binding, err := bindingFrom(value)
		if err != nil {
			return ProofContract{}, err
		}
		bindings = append(bindings, binding)
	}
	if err := assertSortedUnique(bindingIDs(bindings), "conformance proof contract requirementIds"); err != nil {
		return ProofContract{}, err
	}
	return ProofContract{Bindings: bindings, ContractID: contractID, Surfaces: surfaces}, nil
}

func surfaceFrom(raw any) (Surface, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Surface{}, fmt.Errorf("conformance proof surface must be an object")
	}
	if err := admit.KnownKeys(record, []string{"preconditionedEnvironmentClasses", "requiredEnvironmentClasses", "surfaceId"}, "conformance proof surface"); err != nil {
		return Surface{}, err
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], "conformance proof surfaceId")
	if err != nil {
		return Surface{}, err
	}
	required, err := stringArray(record["requiredEnvironmentClasses"], "surface "+fmt.Sprint(record["surfaceId"])+" requiredEnvironmentClasses", false, false)
	if err != nil {
		return Surface{}, err
	}
	preconditioned, err := stringArray(record["preconditionedEnvironmentClasses"], "surface "+fmt.Sprint(record["surfaceId"])+" preconditionedEnvironmentClasses", true, false)
	if err != nil {
		return Surface{}, err
	}
	return Surface{PreconditionedEnvironmentClasses: preconditioned, RequiredEnvironmentClasses: required, SurfaceID: surfaceID}, nil
}

func bindingFrom(raw any) (Binding, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Binding{}, fmt.Errorf("conformance proof binding must be an object")
	}
	if err := admit.KnownKeys(record, []string{"blockingStatus", "proofContractState", "requiredEnvironmentClasses", "requirementId", "scenarioId", "surfaceId", "verifyCommands", "witnessRefs"}, "conformance proof binding"); err != nil {
		return Binding{}, err
	}
	requirementID, err := admit.RuleID(record["requirementId"], "conformance proof binding requirementId")
	if err != nil {
		return Binding{}, err
	}
	witnessRefs, err := witnessRefs(record["witnessRefs"], requirementID)
	if err != nil {
		return Binding{}, err
	}
	if len(witnessRefs) == 0 {
		return Binding{}, fmt.Errorf("conformance proof binding %s must declare witnessRefs", requirementID)
	}
	surfaceID, err := admit.RuleID(record["surfaceId"], "conformance proof binding "+requirementID+" surfaceId")
	if err != nil {
		return Binding{}, err
	}
	scenarioID, err := nonEmptyText(record["scenarioId"], "conformance proof binding "+requirementID+" scenarioId")
	if err != nil {
		return Binding{}, err
	}
	proofState, err := admit.RuleID(record["proofContractState"], "conformance proof binding "+requirementID+" proofContractState")
	if err != nil {
		return Binding{}, err
	}
	blockingStatus, err := admit.RuleID(record["blockingStatus"], "conformance proof binding "+requirementID+" blockingStatus")
	if err != nil {
		return Binding{}, err
	}
	required, err := stringArray(record["requiredEnvironmentClasses"], "conformance proof binding "+requirementID+" requiredEnvironmentClasses", false, false)
	if err != nil {
		return Binding{}, err
	}
	commands, err := displayCommandArray(record["verifyCommands"], "conformance proof binding "+requirementID+" verifyCommands", false, false)
	if err != nil {
		return Binding{}, err
	}
	return Binding{BlockingStatus: blockingStatus, ProofContractState: proofState, RequiredEnvironmentClasses: required, RequirementID: requirementID, ScenarioID: scenarioID, SurfaceID: surfaceID, VerifyCommands: commands, WitnessRefs: witnessRefs}, nil
}

func witnessRefs(raw any, requirementID string) ([]WitnessRef, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("conformance proof binding %s witnessRefs must be an array", requirementID)
	}
	refs := make([]WitnessRef, 0, len(values))
	for _, value := range values {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("conformance proof binding %s witnessRef must be an object", requirementID)
		}
		if err := admit.KnownKeys(record, []string{"role", "selector"}, "conformance proof binding "+requirementID+" witnessRef"); err != nil {
			return nil, err
		}
		role, err := admit.RuleID(record["role"], "conformance proof binding "+requirementID+" witnessRef role")
		if err != nil {
			return nil, err
		}
		selector, err := nonEmptyText(record["selector"], "conformance proof binding "+requirementID+" witnessRef selector")
		if err != nil {
			return nil, err
		}
		refs = append(refs, WitnessRef{Role: role, Selector: selector})
	}
	sort.Slice(refs, func(left int, right int) bool {
		return refs[left].Role < refs[right].Role || refs[left].Role == refs[right].Role && refs[left].Selector < refs[right].Selector
	})
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		keys = append(keys, ref.Role+"\x00"+ref.Selector)
	}
	if err := assertSortedUnique(keys, "conformance proof binding "+requirementID+" witnessRefs"); err != nil {
		return nil, err
	}
	return refs, nil
}

func profileFrom(raw any, index int) (Profile, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return Profile{}, fmt.Errorf("conformance profile #%d must be an object", index)
	}
	if err := admit.KnownKeys(record, []string{"allowedEnvironmentClasses", "nonClaims", "optionalSurfaceIds", "preconditionPolicy", "profileId", "purpose", "requiredSurfaceIds"}, fmt.Sprintf("conformance profile #%d", index)); err != nil {
		return Profile{}, err
	}
	profileID, err := admit.RuleID(record["profileId"], fmt.Sprintf("conformance profile #%d profileId", index))
	if err != nil {
		return Profile{}, err
	}
	if !lowerDashID(profileID) {
		return Profile{}, fmt.Errorf("profile %s must use a lowercase stable id", profileID)
	}
	preconditionPolicy, err := nonEmptyText(record["preconditionPolicy"], fmt.Sprintf("conformance profile #%d preconditionPolicy", index))
	if err != nil {
		return Profile{}, err
	}
	if preconditionPolicy != "allow_preconditioned" && preconditionPolicy != "local_only" {
		return Profile{}, fmt.Errorf("conformance profile #%d has unsupported preconditionPolicy", index)
	}
	required, err := stringArray(record["requiredSurfaceIds"], fmt.Sprintf("conformance profile #%d requiredSurfaceIds", index), false, true)
	if err != nil {
		return Profile{}, err
	}
	optional, err := stringArray(record["optionalSurfaceIds"], fmt.Sprintf("conformance profile #%d optionalSurfaceIds", index), true, true)
	if err != nil {
		return Profile{}, err
	}
	overlap := []string{}
	for _, surfaceID := range required {
		if contains(optional, surfaceID) {
			overlap = append(overlap, surfaceID)
		}
	}
	if len(overlap) > 0 {
		return Profile{}, fmt.Errorf("profile %s required and optional surfaces overlap: %s", profileID, strings.Join(overlap, ", "))
	}
	allowed, err := stringArray(record["allowedEnvironmentClasses"], fmt.Sprintf("conformance profile #%d allowedEnvironmentClasses", index), false, true)
	if err != nil {
		return Profile{}, err
	}
	nonClaims, err := stringArray(record["nonClaims"], fmt.Sprintf("conformance profile #%d nonClaims", index), false, true)
	if err != nil {
		return Profile{}, err
	}
	purpose, err := nonEmptyText(record["purpose"], fmt.Sprintf("conformance profile #%d purpose", index))
	if err != nil {
		return Profile{}, err
	}
	return Profile{AllowedEnvironmentClasses: allowed, NonClaims: nonClaims, OptionalSurfaceIDs: optional, PreconditionPolicy: preconditionPolicy, ProfileID: profileID, Purpose: purpose, RequiredSurfaceIDs: required}, nil
}

func validateProfile(profile Profile, proofContract ProofContract, policy Policy) []string {
	failures := []string{}
	required := set(profile.RequiredSurfaceIDs)
	surfacesByID := map[string]Surface{}
	for _, surface := range proofContract.Surfaces {
		surfacesByID[surface.SurfaceID] = surface
	}
	for _, surfaceID := range append(append([]string{}, profile.RequiredSurfaceIDs...), profile.OptionalSurfaceIDs...) {
		if _, ok := surfacesByID[surfaceID]; !ok {
			failures = append(failures, fmt.Sprintf("profile %s references unknown surface %s", profile.ProfileID, surfaceID))
		}
	}
	requiredSurfaceBindings := map[string]int{}
	for _, surfaceID := range profile.RequiredSurfaceIDs {
		requiredSurfaceBindings[surfaceID] = 0
	}
	allowedEnvironments := set(profile.AllowedEnvironmentClasses)
	for _, environmentClass := range profile.AllowedEnvironmentClasses {
		if _, ok := policy.KnownEnvironmentClasses[environmentClass]; !ok {
			failures = append(failures, fmt.Sprintf("profile %s declares unknown environment class %s", profile.ProfileID, environmentClass))
		}
	}
	selectedBindings := profileBindings(profile, proofContract)
	selectedEnvironments := set(flatMapEnvironments(selectedBindings))
	if policy.FailOnUnusedAllowedEnvironment {
		for _, environmentClass := range profile.AllowedEnvironmentClasses {
			if _, ok := selectedEnvironments[environmentClass]; !ok {
				failures = append(failures, fmt.Sprintf("profile %s declares unused environment class %s", profile.ProfileID, environmentClass))
			}
		}
	}
	for _, binding := range selectedBindings {
		if _, ok := required[binding.SurfaceID]; ok {
			requiredSurfaceBindings[binding.SurfaceID]++
		}
		if _, ok := policy.AllowedProofContractStates[binding.ProofContractState]; !ok {
			failures = append(failures, fmt.Sprintf("profile %s binding %s has unallowed proof state %s", profile.ProfileID, binding.RequirementID, binding.ProofContractState))
		}
		if _, ok := policy.BlockingStatuses[binding.BlockingStatus]; !ok {
			failures = append(failures, fmt.Sprintf("profile %s binding %s has unallowed blocking status %s", profile.ProfileID, binding.RequirementID, binding.BlockingStatus))
		}
		for _, environmentClass := range binding.RequiredEnvironmentClasses {
			if _, ok := allowedEnvironments[environmentClass]; !ok {
				failures = append(failures, fmt.Sprintf("profile %s binding %s uses unallowed environment %s", profile.ProfileID, binding.RequirementID, environmentClass))
			}
		}
		if profile.PreconditionPolicy == "local_only" {
			surface := surfacesByID[binding.SurfaceID]
			if len(surface.PreconditionedEnvironmentClasses) > 0 {
				failures = append(failures, fmt.Sprintf("profile %s local-only profile selects preconditioned surface %s", profile.ProfileID, binding.SurfaceID))
			}
			if isPreconditionedBinding(binding, policy) {
				failures = append(failures, fmt.Sprintf("profile %s local-only profile selects preconditioned binding %s", profile.ProfileID, binding.RequirementID))
			}
		}
	}
	for _, surfaceID := range profile.RequiredSurfaceIDs {
		if requiredSurfaceBindings[surfaceID] == 0 {
			failures = append(failures, fmt.Sprintf("profile %s required surface %s has no bindings", profile.ProfileID, surfaceID))
		}
	}
	sort.Strings(failures)
	return failures
}

func buildProfileReport(profile Profile, proofContract ProofContract, policy Policy) ProfileReport {
	failures := validateProfile(profile, proofContract, policy)
	bindings := profileBindings(profile, proofContract)
	environmentClasses := uniqueSorted(flatMapEnvironments(bindings))
	verifyCommands := uniqueSorted(flatMapCommands(bindings))
	preconditioned := 0
	for _, binding := range bindings {
		surface := findSurface(proofContract.Surfaces, binding.SurfaceID)
		if len(surface.PreconditionedEnvironmentClasses) > 0 || isPreconditionedBinding(binding, policy) {
			preconditioned++
		}
	}
	state := "resolved"
	if len(failures) > 0 {
		state = "invalid"
	}
	return ProfileReport{
		CommandCount:                   len(verifyCommands),
		CommandExecutionState:          "not_run",
		EnvironmentClasses:             environmentClasses,
		Failures:                       failures,
		NonClaims:                      profile.NonClaims,
		OptionalSurfaceCount:           len(profile.OptionalSurfaceIDs),
		PreconditionedRequirementCount: preconditioned,
		ProfileID:                      profile.ProfileID,
		ProfileResolutionState:         state,
		Purpose:                        profile.Purpose,
		RequirementCount:               len(bindings),
		RequiredSurfaceCount:           len(profile.RequiredSurfaceIDs),
		ScenarioCount:                  len(uniqueSorted(scenarios(bindings))),
		SurfaceCount:                   len(uniqueSorted(bindingSurfaces(bindings))),
		Surfaces:                       uniqueSorted(bindingSurfaces(bindings)),
		VerifyCommands:                 verifyCommands,
		WitnessMappingCount:            witnessMappingCount(bindings),
	}
}

func standardReportForProfile(profile ProfileReport) report.Record {
	state := "passed"
	if len(profile.Failures) > 0 {
		state = "failed"
	}
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "proofkit.conformance-profile." + profile.ProfileID,
		State:         state,
		Summary: map[string]any{
			"commandCount":           profile.CommandCount,
			"profileId":              profile.ProfileID,
			"profileResolutionState": profile.ProfileResolutionState,
			"requirementCount":       profile.RequirementCount,
			"scenarioCount":          profile.ScenarioCount,
			"surfaceCount":           profile.SurfaceCount,
			"witnessMappingCount":    profile.WitnessMappingCount,
		},
		Diagnostics: []report.Diagnostic{
			{Key: "profileReport", Value: profile.JSONValue()},
		},
		RuleResults: ruleResults(profile.Failures),
		NonClaims:   admit.StringSliceToAny(profile.NonClaims),
	}
}

func (profile ProfileReport) JSONValue() map[string]any {
	return map[string]any{
		"commandCount":                   profile.CommandCount,
		"commandExecutionState":          profile.CommandExecutionState,
		"environmentClasses":             admit.StringSliceToAny(profile.EnvironmentClasses),
		"failures":                       admit.StringSliceToAny(profile.Failures),
		"nonClaims":                      admit.StringSliceToAny(profile.NonClaims),
		"optionalSurfaceCount":           profile.OptionalSurfaceCount,
		"preconditionedRequirementCount": profile.PreconditionedRequirementCount,
		"profileId":                      profile.ProfileID,
		"profileResolutionState":         profile.ProfileResolutionState,
		"purpose":                        profile.Purpose,
		"requirementCount":               profile.RequirementCount,
		"requiredSurfaceCount":           profile.RequiredSurfaceCount,
		"scenarioCount":                  profile.ScenarioCount,
		"surfaceCount":                   profile.SurfaceCount,
		"surfaces":                       admit.StringSliceToAny(profile.Surfaces),
		"verifyCommands":                 admit.StringSliceToAny(profile.VerifyCommands),
		"witnessMappingCount":            profile.WitnessMappingCount,
	}
}

func profileBindings(profile Profile, proofContract ProofContract) []Binding {
	surfaceIDs := set(append(append([]string{}, profile.RequiredSurfaceIDs...), profile.OptionalSurfaceIDs...))
	bindings := []Binding{}
	for _, binding := range proofContract.Bindings {
		if _, ok := surfaceIDs[binding.SurfaceID]; ok {
			bindings = append(bindings, binding)
		}
	}
	return bindings
}

func isPreconditionedBinding(binding Binding, policy Policy) bool {
	for _, environmentClass := range binding.RequiredEnvironmentClasses {
		if _, ok := policy.LocalEnvironmentClasses[environmentClass]; !ok {
			return true
		}
	}
	return false
}

func ruleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.conformance-profile.resolved",
			Status:      "passed",
			Message:     "Conformance profile scope resolves to admitted requirement bindings.",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.conformance-profile.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}

func stringArray(raw any, context string, allowEmpty bool, requireSortedUnique bool) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a string array", context)
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		text, err := nonEmptyText(item, context)
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	if !allowEmpty && len(result) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty string array", context)
	}
	normalized := append([]string{}, result...)
	sort.Strings(normalized)
	if !requireSortedUnique {
		return normalized, nil
	}
	if err := assertSortedUnique(result, context); err != nil {
		return nil, err
	}
	return result, nil
}

func displayCommandArray(raw any, context string, allowEmpty bool, requireSortedUnique bool) ([]string, error) {
	values, err := stringArray(raw, context, allowEmpty, requireSortedUnique)
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		command, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		values[index] = command
	}
	return values, nil
}

func nonEmptyText(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s must not contain NUL bytes", context)
	}
	return value, nil
}

func stateForFailures(failures []string) string {
	if len(failures) == 0 {
		return "passed"
	}
	return "failed"
}

func exitCode(state string) int {
	if state == "passed" {
		return 0
	}
	return 1
}

func set(values []string) map[string]struct{} {
	result := map[string]struct{}{}
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func assertSortedUnique(values []string, context string) error {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	if strings.Join(values, "\n") != strings.Join(sorted, "\n") || len(values) != len(set(values)) {
		return fmt.Errorf("%s must be sorted and unique", context)
	}
	return nil
}

func lowerDashID(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			continue
		}
		return false
	}
	return true
}

func ids(surfaces []Surface) []string {
	result := make([]string, 0, len(surfaces))
	for _, surface := range surfaces {
		result = append(result, surface.SurfaceID)
	}
	return result
}

func bindingIDs(bindings []Binding) []string {
	result := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		result = append(result, binding.RequirementID)
	}
	return result
}

func flatMapEnvironments(bindings []Binding) []string {
	result := []string{}
	for _, binding := range bindings {
		result = append(result, binding.RequiredEnvironmentClasses...)
	}
	return result
}

func flatMapCommands(bindings []Binding) []string {
	result := []string{}
	for _, binding := range bindings {
		result = append(result, binding.VerifyCommands...)
	}
	return result
}

func scenarios(bindings []Binding) []string {
	result := []string{}
	for _, binding := range bindings {
		result = append(result, binding.ScenarioID)
	}
	return result
}

func bindingSurfaces(bindings []Binding) []string {
	result := []string{}
	for _, binding := range bindings {
		result = append(result, binding.SurfaceID)
	}
	return result
}

func witnessMappingCount(bindings []Binding) int {
	count := 0
	for _, binding := range bindings {
		count += len(binding.WitnessRefs)
	}
	return count
}

func findSurface(surfaces []Surface, surfaceID string) Surface {
	for _, surface := range surfaces {
		if surface.SurfaceID == surfaceID {
			return surface
		}
	}
	return Surface{}
}
