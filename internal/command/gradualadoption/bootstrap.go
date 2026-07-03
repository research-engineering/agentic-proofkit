package gradualadoption

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/adoptionmode"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/contractenv"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

var bootstrapNonClaims = []string{
	"Bootstrap reports do not execute native witnesses.",
	"Bootstrap reports do not own repository proof truth.",
	"Bootstrap reports do not prove rollout readiness.",
	"Bootstrap reports do not write caller repository files.",
}

type BootstrapResult struct {
	AgentActionPlan []any
	ExitCode        int
	NextCommands    []string
	Payloads        map[string]any
	PlannedFiles    []any
	Record          report.Record
	WitnessPlan     map[string]any
}

func BuildBootstrap(raw any) (map[string]any, int, error) {
	result, err := BuildBootstrapResult(raw)
	if err != nil {
		return nil, 1, err
	}
	return result.JSONValue(), result.ExitCode, nil
}

func BuildBootstrapResult(raw any) (BootstrapResult, error) {
	return buildBootstrap(raw)
}

func BuildBootstrapFromContractEnvelope(raw any) (map[string]any, int, error) {
	input, err := BootstrapInputFromContractEnvelope(raw)
	if err != nil {
		return nil, 1, err
	}
	return BuildBootstrap(input)
}

func BootstrapInputFromContractEnvelope(raw any) (map[string]any, error) {
	envelope, err := contractenv.Object(raw, "proofkit.gradual-adoption-profile.v1", "gradual adoption", "bootstrap", "guidance", "input")
	if err != nil {
		return nil, err
	}
	adoption, err := contractenv.ObjectField(envelope, "input", "gradual adoption contract envelope")
	if err != nil {
		return nil, err
	}
	proofBinding, err := contractenv.ObjectField(adoption, "proofBinding", "gradual adoption contract envelope input")
	if err != nil {
		return nil, err
	}
	guidance, err := contractenv.ObjectField(envelope, "guidance", "gradual adoption contract envelope")
	if err != nil {
		return nil, err
	}
	bootstrap, err := contractenv.ObjectField(envelope, "bootstrap", "gradual adoption contract envelope")
	if err != nil {
		return nil, err
	}
	scopeEvidence, err := contractenv.ObjectField(bootstrap, "scopeEvidence", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	bootstrapID, err := contractenv.StringField(bootstrap, "bootstrapId", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	proofBindingPath, err := contractenv.StringField(proofBinding, "bindingPath", "gradual adoption contract envelope input proofBinding")
	if err != nil {
		return nil, err
	}
	ownerRoute, err := contractenv.ObjectField(guidance, "ownerRoute", "gradual adoption guidance contract")
	if err != nil {
		return nil, err
	}
	paths, err := contractenv.ObjectField(bootstrap, "paths", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	guidanceMode, err := contractenv.StringField(bootstrap, "defaultMode", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	checkedScope, err := contractenv.StringField(scopeEvidence, "checkedScope", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	touchedRuleIDs, err := contractenv.StringArrayField(scopeEvidence, "touchedRuleIds", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	commands, err := contractenv.StringArrayField(bootstrap, "commands", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	commands, err = displayCommandsFromStrings(commands, "gradual adoption bootstrap contract commands")
	if err != nil {
		return nil, err
	}
	nonClaims, err := contractenv.StringArrayField(bootstrap, "nonClaims", "gradual adoption bootstrap contract")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"bootstrapId":       bootstrapID,
		"budget":            adoption["budget"],
		"checkedScope":      checkedScope,
		"commands":          admit.StringSliceToAny(commands),
		"guidanceMode":      guidanceMode,
		"module":            adoption["module"],
		"nativeWitnesses":   adoption["nativeWitnesses"],
		"nonClaims":         admit.StringSliceToAny(nonClaims),
		"ownerRoute":        ownerRoute,
		"packageVersionRef": adoption["packageVersionRef"],
		"paths":             paths,
		"proofBindingPath":  proofBindingPath,
		"repository":        adoption["repository"],
		"rollback":          adoption["rollback"],
		"schemaVersion":     json.Number("1"),
		"touchedRuleIds":    admit.StringSliceToAny(touchedRuleIDs),
	}, nil
}

func (result BootstrapResult) JSONValue() map[string]any {
	return map[string]any{
		"agentActionPlan": result.AgentActionPlan,
		"exitCode":        result.ExitCode,
		"nextCommands":    admit.StringSliceToAny(result.NextCommands),
		"payloads":        result.Payloads,
		"plannedFiles":    result.PlannedFiles,
		"report":          result.Record.JSONValue(),
		"witnessPlan":     result.WitnessPlan,
	}
}

func buildBootstrap(raw any) (BootstrapResult, error) {
	record, ok := raw.(map[string]any)
	if !ok {
		return BootstrapResult{}, fmt.Errorf("proofkit gradual adoption bootstrap input must be an object")
	}
	if err := admit.KnownKeys(record, []string{"bootstrapId", "budget", "checkedScope", "commands", "guidanceMode", "module", "nativeWitnesses", "nonClaims", "ownerRoute", "packageVersionRef", "paths", "proofBindingPath", "repository", "rollback", "schemaVersion", "touchedRuleIds"}, "proofkit gradual adoption bootstrap input"); err != nil {
		return BootstrapResult{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) {
		return BootstrapResult{}, fmt.Errorf("proofkit gradual adoption bootstrap schemaVersion must be 1")
	}
	failures := []string{}
	bootstrapID, err := admit.RuleID(record["bootstrapId"], "gradual adoption bootstrapId")
	if err != nil {
		return BootstrapResult{}, err
	}
	paths := admitBootstrapPaths(object(record["paths"]), &failures)
	module := admitBootstrapModule(object(record["module"]), &failures)
	ownerRoute := admitBootstrapOwnerRoute(object(record["ownerRoute"]), &failures)
	proofBindingPath, err := safePath(record["proofBindingPath"], "bootstrap proofBindingPath")
	addErr(&failures, err)
	witnessCommands, witnessPlan, err := bootstrapWitnessCommands(object(record["nativeWitnesses"]), &failures)
	if err != nil {
		return BootstrapResult{}, err
	}
	witnessCommandIDs := witnessIDs(witnessCommands)
	if len(witnessCommandIDs) == 0 {
		failures = append(failures, "bootstrap must declare at least one native witness command")
	}
	guidanceMode, _ := record["guidanceMode"].(string)
	if guidanceMode != adoptionmode.Observe {
		failures = append(failures, "bootstrap guidanceMode must be observe for the first non-blocking adoption step")
	}
	checkedScope, _ := record["checkedScope"].(string)
	if checkedScope != adoptionmode.ScopeNone {
		failures = append(failures, "bootstrap checkedScope must be none for the first non-blocking adoption step")
	}
	touchedRuleIDs, err := sortedRuleIDArray(record["touchedRuleIds"], "bootstrap touchedRuleIds")
	addErr(&failures, err)
	if len(touchedRuleIDs) > 0 {
		failures = append(failures, "bootstrap touchedRuleIds must be empty when checkedScope is none")
	}
	commands, err := preserveDisplayCommands(record["commands"], "bootstrap commands", true)
	addErr(&failures, err)
	callerNonClaims, err := admit.SortedTextArray(record["nonClaims"], "bootstrap nonClaims", true)
	addErr(&failures, err)
	nonClaims, err := admit.SortedText(append(append([]string{}, bootstrapNonClaims...), callerNonClaims...), "bootstrap merged nonClaims", false)
	addErr(&failures, err)
	nextCommands := []string{
		cliexec.DisplayCommand("gradual-adoption", "--input", stringFromMap(paths, "adoptionProfilePath")),
		cliexec.DisplayCommand("gradual-adoption-guidance", "--input", stringFromMap(paths, "adoptionGuidancePath")),
		cliexec.DisplayCommand("witness-scheduler-plan", "--input", stringFromMap(paths, "witnessPlanInputPath")),
	}
	adoptionProfile := map[string]any{
		"adoptionId":      bootstrapID,
		"adoptionMode":    "non_blocking",
		"agentReport":     bootstrapAgentReport(paths),
		"budget":          record["budget"],
		"module":          module,
		"nativeWitnesses": record["nativeWitnesses"],
		"nonClaims": admit.StringSliceToAny([]string{
			"Gradual adoption does not execute native witnesses.",
			"Gradual adoption does not replace repository-local proof authority.",
			"Gradual adoption does not prove organization rollout readiness.",
		}),
		"packageVersionRef": record["packageVersionRef"],
		"proofBinding": map[string]any{
			"bindingFormat":     "requirement_to_witness",
			"bindingPath":       proofBindingPath,
			"requirementIds":    anyStringArrayFromMap(module, "requirementIds"),
			"witnessCommandIds": admit.StringSliceToAny(witnessCommandIDs),
		},
		"repository":    record["repository"],
		"rollback":      record["rollback"],
		"rolloutClaim":  false,
		"schemaVersion": json.Number("1"),
	}
	source, err := BuildReport(adoptionProfile)
	if err != nil {
		return BootstrapResult{}, err
	}
	if source.Record.State != "passed" {
		failures = append(failures, "generated adoptionProfile must be accepted before bootstrap can pass")
	}
	adoptionGuidance := map[string]any{
		"agentGuidance": bootstrapAgentGuidance(paths, commands, nextCommands),
		"guidanceId":    bootstrapID + ".guidance",
		"guidanceMode":  guidanceMode,
		"nonClaims": admit.StringSliceToAny([]string{
			"Guidance reports do not execute native witnesses.",
			"Guidance reports do not own repository proof truth.",
			"Guidance reports do not prove rollout readiness.",
		}),
		"ownerRoute":    ownerRoute,
		"schemaVersion": json.Number("1"),
		"scopeEvidence": map[string]any{
			"basis":          "caller_provided_touched_rule_ids",
			"checkedScope":   checkedScope,
			"touchedRuleIds": admit.StringSliceToAny(touchedRuleIDs),
		},
		"sourceReport": source.Record.JSONValue(),
	}
	guidance, err := buildGuidance(adoptionGuidance, GuidanceOptions{})
	if err != nil {
		return BootstrapResult{}, err
	}
	if guidance.Record.State != "passed" {
		failures = append(failures, "generated adoptionGuidance must be accepted before bootstrap can pass")
	}
	proofBindingPayload := map[string]any{
		"bindingFormat": "requirement_to_witness",
		"moduleId":      module["moduleId"],
		"nonClaims": admit.StringSliceToAny([]string{
			"Bootstrap proof binding payloads are starter inputs only.",
			"Bootstrap proof binding payloads do not prove native witness execution.",
			"Bootstrap proof binding payloads do not replace caller-owned proof authority.",
		}),
		"requirementIds":    anyStringArrayFromMap(module, "requirementIds"),
		"schemaVersion":     json.Number("1"),
		"witnessCommandIds": admit.StringSliceToAny(witnessCommandIDs),
	}
	plannedFiles := plannedBootstrapFiles(map[string]any{
		"moduleSpecPath":   module["specPath"],
		"paths":            paths,
		"profilePath":      object(record["repository"])["profilePath"],
		"proofBindingPath": proofBindingPath,
	})
	agentActionPlan := bootstrapAgentActionPlan(nextCommands, plannedFiles)
	state := "passed"
	if len(failures) > 0 {
		state = "failed"
	}
	rec := report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.gradual-adoption-bootstrap",
		ReportID:      bootstrapID,
		State:         state,
		Summary: map[string]any{
			"adoptionMode":        "non_blocking",
			"checkedScope":        checkedScope,
			"guidanceMode":        guidanceMode,
			"moduleId":            module["moduleId"],
			"plannedFileCount":    len(plannedFiles),
			"payloadCount":        4,
			"requirementCount":    len(stringArrayFromMap(module, "requirementIds")),
			"rolloutClaim":        false,
			"witnessCommandCount": len(witnessCommandIDs),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "agentActionPlan", Value: agentActionPlan},
			{Key: "nextCommands", Value: admit.StringSliceToAny(nextCommands)},
			{Key: "plannedFiles", Value: plannedFiles},
			{Key: "sourceReports", Value: map[string]any{
				"adoptionGuidanceState": guidance.Record.State,
				"adoptionProfileState":  source.Record.State,
			}},
		},
		RuleResults: bootstrapRuleResults(failures),
		NonClaims:   admit.StringSliceToAny(nonClaims),
	}
	exit := exitCode(rec)
	return BootstrapResult{
		AgentActionPlan: agentActionPlan,
		ExitCode:        exit,
		NextCommands:    nextCommands,
		Payloads: map[string]any{
			"adoptionGuidance": adoptionGuidance,
			"adoptionProfile":  adoptionProfile,
			"proofBinding":     proofBindingPayload,
			"witnessPlanInput": record["nativeWitnesses"],
		},
		PlannedFiles: plannedFiles,
		Record:       rec,
		WitnessPlan:  witnessPlan,
	}, nil
}

func admitBootstrapPaths(raw map[string]any, failures *[]string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"adoptionGuidancePath", "adoptionProfilePath", "adoptionReportArtifactPath", "guidanceReportArtifactPath", "witnessPlanInputPath"}, "bootstrap paths"); err != nil {
		addErr(failures, err)
	}
	paths := map[string]any{}
	for _, key := range []string{"adoptionProfilePath", "adoptionGuidancePath", "witnessPlanInputPath", "adoptionReportArtifactPath", "guidanceReportArtifactPath"} {
		path, err := safePath(raw[key], "bootstrap "+key)
		addErr(failures, err)
		paths[key] = path
	}
	return paths
}

func admitBootstrapModule(raw map[string]any, failures *[]string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"moduleId", "requirementIds", "specPath"}, "bootstrap module"); err != nil {
		addErr(failures, err)
	}
	requirementIDs, err := sortedRuleIDArray(raw["requirementIds"], "bootstrap module requirementIds")
	addErr(failures, err)
	if len(requirementIDs) == 0 {
		*failures = append(*failures, "bootstrap module must declare at least one requirement")
	}
	if len(requirementIDs) > 15 {
		*failures = append(*failures, "bootstrap module must stay bounded to at most 15 requirements")
	}
	moduleID, err := admit.RuleID(raw["moduleId"], "bootstrap moduleId")
	addErr(failures, err)
	specPath, err := safePath(raw["specPath"], "bootstrap module specPath")
	addErr(failures, err)
	return map[string]any{
		"moduleId":       moduleID,
		"requirementIds": admit.StringSliceToAny(requirementIDs),
		"specPath":       specPath,
	}
}

func admitBootstrapOwnerRoute(raw map[string]any, failures *[]string) map[string]any {
	if err := admit.KnownKeys(raw, []string{"evidencePaths", "primaryOwner", "proofBindingPaths", "specPaths"}, "bootstrap ownerRoute"); err != nil {
		addErr(failures, err)
	}
	specPaths, err := sortedPaths(raw["specPaths"], "bootstrap ownerRoute specPaths")
	addErr(failures, err)
	proofBindingPaths, err := sortedPaths(raw["proofBindingPaths"], "bootstrap ownerRoute proofBindingPaths")
	addErr(failures, err)
	if len(specPaths) == 0 {
		*failures = append(*failures, "bootstrap ownerRoute must declare at least one spec path")
	}
	if len(proofBindingPaths) == 0 {
		*failures = append(*failures, "bootstrap ownerRoute must declare at least one proof binding path")
	}
	evidencePaths, err := sortedPaths(raw["evidencePaths"], "bootstrap ownerRoute evidencePaths")
	addErr(failures, err)
	primaryOwner, err := text(raw["primaryOwner"], "bootstrap ownerRoute primaryOwner")
	addErr(failures, err)
	return map[string]any{
		"evidencePaths":     admit.StringSliceToAny(evidencePaths),
		"primaryOwner":      primaryOwner,
		"proofBindingPaths": admit.StringSliceToAny(proofBindingPaths),
		"specPaths":         admit.StringSliceToAny(specPaths),
	}
}

func bootstrapWitnessCommands(raw map[string]any, failures *[]string) ([]witnesscommand.Command, map[string]any, error) {
	commands, plan, err := admitWitnessCommands(raw, failures)
	if err != nil {
		return nil, nil, err
	}
	if len(commands) == 0 {
		*failures = append(*failures, "bootstrap must declare at least one native witness command")
	}
	return commands, plan, nil
}

func bootstrapAgentReport(paths map[string]any) map[string]any {
	return map[string]any{
		"artifactPath":   paths["adoptionReportArtifactPath"],
		"outputMode":     "non_blocking",
		"reportKind":     "proofkit.gradual-adoption",
		"routeQuestions": admit.StringSliceToAny(standardQuestions),
		"schemaId":       "proofkit.gradual-adoption-profile.v1",
	}
}

func bootstrapAgentGuidance(paths map[string]any, commands []string, nextCommands []string) map[string]any {
	return map[string]any{
		"artifactPath":                     paths["guidanceReportArtifactPath"],
		"blockedPreconditions":             []any{},
		"callerSuggestedAutofixCandidates": []any{},
		"commands":                         admit.StringSliceToAny(append(append([]string{}, commands...), nextCommands...)),
		"minimalAdoptionPath": admit.StringSliceToAny([]string{
			"Start with one bounded module and observe-mode guidance.",
			"Bind every declared requirement to caller-owned native witnesses.",
			"Promote to warn or enforce-touched only after the first route stays stable.",
		}),
		"proofBindingsMissing": []any{},
		"reportKind":           "proofkit.gradual-adoption-guidance",
		"requiredNextActions": admit.StringSliceToAny([]string{
			"Create or update the caller-owned starter files listed by the bootstrap report.",
			"Run the generated gradual-adoption and gradual-adoption-guidance commands before enabling enforcement.",
		}),
		"routeQuestions": admit.StringSliceToAny(standardQuestions),
		"schemaId":       "proofkit.gradual-adoption-guidance.v1",
	}
}

func displayCommandsFromStrings(values []string, context string) ([]string, error) {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		command, err := admit.DisplayOnlyCommandText(value, context)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[command]; ok {
			return nil, fmt.Errorf("%s must be unique", context)
		}
		seen[command] = struct{}{}
		result = append(result, command)
	}
	return result, nil
}

func plannedBootstrapFiles(input map[string]any) []any {
	paths := input["paths"].(map[string]any)
	files := []map[string]any{
		{"path": input["moduleSpecPath"], "payloadKey": nil, "purpose": "caller-owned module specification"},
		{"path": paths["adoptionGuidancePath"], "payloadKey": "adoptionGuidance", "purpose": "caller-owned gradual adoption guidance input"},
		{"path": paths["adoptionProfilePath"], "payloadKey": "adoptionProfile", "purpose": "caller-owned gradual adoption profile input"},
		{"path": input["proofBindingPath"], "payloadKey": "proofBinding", "purpose": "caller-owned requirement-to-witness binding starter payload"},
		{"path": input["profilePath"], "payloadKey": nil, "purpose": "caller-owned proofkit profile"},
		{"path": paths["witnessPlanInputPath"], "payloadKey": "witnessPlanInput", "purpose": "caller-owned witness plan input"},
	}
	sort.Slice(files, func(left int, right int) bool {
		return files[left]["path"].(string) < files[right]["path"].(string)
	})
	result := make([]any, 0, len(files))
	for _, file := range files {
		result = append(result, file)
	}
	return result
}

func bootstrapAgentActionPlan(nextCommands []string, plannedFiles []any) []any {
	fileRefs := make([]string, 0, len(plannedFiles))
	for _, rawFile := range plannedFiles {
		fileRefs = append(fileRefs, rawFile.(map[string]any)["path"].(string))
	}
	return []any{
		map[string]any{
			"commands":     []any{},
			"evidenceRefs": admit.StringSliceToAny(fileRefs),
			"instruction":  "Create or update the caller-owned starter files from the bootstrap payloads and preserve any existing repository-specific policy.",
			"nonClaims":    []any{"Bootstrap reports do not write files or replace caller-owned specifications."},
			"owner":        "consumer_repository",
			"phase":        "bind",
			"stepId":       "proofkit.agent.materialize-starter-files",
		},
		map[string]any{
			"commands":     admit.StringSliceToAny(nextCommands),
			"evidenceRefs": []any{},
			"instruction":  "Run the emitted observe-mode reports and native witness plan before promoting any enforcement mode.",
			"nonClaims":    []any{"Bootstrap reports do not execute native witnesses or prove rollout readiness."},
			"owner":        "consumer_repository",
			"phase":        "verify",
			"stepId":       "proofkit.agent.run-observe-reports",
		},
		map[string]any{
			"commands":     []any{},
			"evidenceRefs": []any{},
			"instruction":  "Promote observe to warn, enforce-touched, and enforce-all only after caller-owned proof bindings and native witnesses stay green.",
			"nonClaims":    []any{"Promotion remains a caller repository decision."},
			"owner":        "consumer_repository",
			"phase":        "promote",
			"stepId":       "proofkit.agent.promote-module-gradually",
		},
	}
}

func bootstrapRuleResults(failures []string) []report.RuleResult {
	if len(failures) == 0 {
		return []report.RuleResult{{
			RuleID:      "proofkit.gradual-adoption-bootstrap.accepted",
			Status:      "passed",
			Message:     "gradual adoption bootstrap is deterministic and non-blocking",
			Diagnostics: []report.Diagnostic{},
		}}
	}
	results := make([]report.RuleResult, 0, len(failures))
	for index, failure := range failures {
		results = append(results, report.RuleResult{
			RuleID:      fmt.Sprintf("proofkit.gradual-adoption-bootstrap.failure.%03d", index+1),
			Status:      "failed",
			Message:     failure,
			Diagnostics: []report.Diagnostic{},
		})
	}
	return results
}
