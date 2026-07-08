package app

import "sort"

type commandInputMode string

const (
	commandInputNone     commandInputMode = "none"
	commandInputRequired commandInputMode = "required"
)

type commandRunner string

const (
	commandRunnerGenericInput                commandRunner = "generic_input"
	commandRunnerAdoptionContractEnvelope    commandRunner = "adoption_contract_envelope"
	commandRunnerAdoptionDoctor              commandRunner = "adoption_doctor"
	commandRunnerAdoptionWorkflow            commandRunner = "adoption_workflow"
	commandRunnerAgentRoute                  commandRunner = "agent_route"
	commandRunnerConformanceProfile          commandRunner = "conformance_profile"
	commandRunnerContractEnvelope            commandRunner = "contract_envelope"
	commandRunnerGradualAdoptionBootstrap    commandRunner = "gradual_adoption_bootstrap"
	commandRunnerGradualAdoptionGuidance     commandRunner = "gradual_adoption_guidance"
	commandRunnerHelp                        commandRunner = "help"
	commandRunnerInit                        commandRunner = "init"
	commandRunnerJSONReportCLIAdapterSource  commandRunner = "json_report_cli_adapter_source"
	commandRunnerPilotAdmission              commandRunner = "pilot_admission"
	commandRunnerPlanning                    commandRunner = "planning"
	commandRunnerProjectStructure            commandRunner = "project_structure"
	commandRunnerRequirementBrowserServer    commandRunner = "requirement_browser_server"
	commandRunnerRequirementProofResolver    commandRunner = "requirement_proof_resolver"
	commandRunnerRequirementView             commandRunner = "requirement_view"
	commandRunnerStackPreset                 commandRunner = "stack_preset"
	commandRunnerTestEvidenceInventory       commandRunner = "test_evidence_inventory"
	commandRunnerTypeScriptPublicAPISurfaces commandRunner = "typescript_public_api_surfaces"
)

type commandScopeClass string

const (
	commandScopeBuiltInPackageCatalog  commandScopeClass = "built_in_package_catalog"
	commandScopeExplicitCallerInput    commandScopeClass = "explicit_caller_input"
	commandScopeExplicitFileSystemScan commandScopeClass = "explicit_filesystem_scan"
)

type commandDescriptor struct {
	name               string
	input              commandInputMode
	runner             commandRunner
	scopeClass         commandScopeClass
	allowedFlags       []string
	inputSchemaSummary []string
	outputModes        []string
	agentEnvelope      bool
	contractEnvelope   bool
	semanticAppTests   []string
	semanticOwnerDirs  []string
}

var commandDescriptors = []commandDescriptor{
	command("adoption-checklist", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("adoptionchecklist")),
	command("adoption-contract-envelope", commandInputRequired, flags("--agent-envelope", "--checked-scope", "--guidance-mode", "--input", "--materialization-manifest", "--mode", "--pilot", "--touched-rule-id"), modes("json"), ownerDirs("adoptioncontract"), withRunner(commandRunnerAdoptionContractEnvelope), withAgentEnvelope()),
	command("adoption-doctor", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("adoptiondoctor"), withRunner(commandRunnerAdoptionDoctor), withSemanticAppTests("TestAdoptionDoctorCLIABI"), withAgentEnvelope()),
	command("adoption-workflow-plan", commandInputRequired, flags("--agent-envelope", "--contract-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("adoptionworkflow"), withRunner(commandRunnerAdoptionWorkflow), withAgentEnvelope(), withContractEnvelope()),
	command("agent-route", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("agentroute"), withRunner(commandRunnerAgentRoute), withAgentEnvelope()),
	command("binding-partition", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("bindingpartition")),
	command("branch-authority", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("branchauthority")),
	command("capability-map-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("capabilitymapadmission")),
	command("changed-path-set", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("changedpathset"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("completion-criteria", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("completioncriteria")),
	command("conformance-profile", commandInputRequired, flags("--format", "--input", "--input-pointer", "--list", "--profile", "--verify"), modes("json", "markdown"), ownerDirs("conformanceprofile"), withRunner(commandRunnerConformanceProfile)),
	command("custom-rule-boundary", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("customruleboundary")),
	command("deployment-evidence-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("deploymentevidenceadmission")),
	command("document-lifecycle-boundary", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("documentlifecycle")),
	command("evidence-graph", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementbinding")),
	command("external-consumer", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("externalconsumer")),
	command("gradual-adoption", commandInputRequired, flags("--contract-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("gradualadoption"), withRunner(commandRunnerContractEnvelope), withContractEnvelope()),
	command("gradual-adoption-bootstrap", commandInputRequired, flags("--agent-envelope", "--contract-envelope", "--input", "--input-pointer", "--materialization-manifest"), modes("json"), ownerDirs("gradualadoption"), withRunner(commandRunnerGradualAdoptionBootstrap), withAgentEnvelope(), withContractEnvelope()),
	command("gradual-adoption-guidance", commandInputRequired, flags("--agent-envelope", "--checked-scope", "--contract-envelope", "--guidance-mode", "--input", "--input-pointer", "--touched-rule-id"), modes("json"), ownerDirs("gradualadoption"), withRunner(commandRunnerGradualAdoptionGuidance), withAgentEnvelope(), withContractEnvelope()),
	command("help", commandInputNone, flags("--help", "-h"), modes("text"), ownerDirs("help"), withRunner(commandRunnerHelp), withSemanticAppTests("TestHelpCommandContractForms")),
	command("impact", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("impact")),
	command("init", commandInputNone, flags("--preset"), modes("json"), ownerDirs("initplan"), withRunner(commandRunnerInit), withSemanticAppTests("TestCLIABIGoldenCorpus")),
	command("json-report-cli-adapter-source", commandInputNone, flags("--format", "--language"), modes("json"), ownerDirs("jsonreportcliadaptersource"), withRunner(commandRunnerJSONReportCLIAdapterSource)),
	command("migration-parity-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("migrationparityadmission"), withInputSchemaSummary("schemaVersion=1", "paritySetId", "sourceProofOwners[]", "targetProofkitRefs[]", "parityRecords[]", "nonClaims[]")),
	command("migration-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("migrationplan"), withInputSchemaSummary("schemaVersion=1", "migrationId", "sourceProofOwners[]", "targetProofkitRefs[]", "parityEvidenceRefs[]", "retainedOwners[]", "retirementCandidates[]", "followUpCommands[]", "nonClaims[]")),
	command("obligation-decision", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("obligationdecision"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("package-runtime-dependency-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("packageruntimedependency"), withInputSchemaSummary("schemaVersion=1", "reportId", "expectedDependencySpec", "expectedLockfileIntegrity", "expectedPackageName", "expectedPackageVersion", "admissibleLocations{}", "packageResolution{}", "nonClaims[]")),
	command("pilot-admission", commandInputRequired, flags("--contract-envelope", "--input", "--input-pointer", "--pilot", "--stack-diverse"), modes("json"), ownerDirs("pilotadmission"), withRunner(commandRunnerPilotAdmission), withContractEnvelope()),
	command("producer-policy-self-proof", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("producerpolicyselfproof")),
	command("proof-obligation-algebra", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("proofobligationalgebra")),
	command("proof-receipt-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("proofreceiptadmission")),
	command("proof-slice", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementbinding")),
	command("readiness-closeout", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("readinesscloseout")),
	command("receipt-currentness-scope", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("receiptcurrentnessscope")),
	command("receipt-producer-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("receiptproduceradmission")),
	command("receipt-trust-class", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("receipttrustclass")),
	command("registry-consumer", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("registryconsumer")),
	command("registry-consumer-proof-input-compose", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("registryconsumerinputcompose")),
	command("release-authority", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("releaseauthority")),
	command("rendered-artifact-freshness", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("renderedartifactfreshness")),
	command("repo-profile-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("repoprofileadmission")),
	command("requirement-authoring-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementauthoringplan")),
	command("requirement-bindings", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementbinding")),
	command("requirement-browser-server", commandInputRequired, flags("--empty-local-environment-policy", "--host", "--input", "--input-pointer", "--local-environment-class", "--open", "--port", "--scope", "--serve", "--view"), modes("json", "server"), ownerDirs("requirementbrowser"), withRunner(commandRunnerRequirementBrowserServer), withSemanticAppTests("TestRequirementBrowserServerSpecTreeCLIABI")),
	command("requirement-coverage-input-compose", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementcoverageinput")),
	command("requirement-coverage-view", commandInputRequired, flags("--agent-envelope", "--format", "--input", "--input-pointer"), modes("html", "json", "markdown"), ownerDirs("requirementcoverageview"), withRunner(commandRunnerRequirementView), withAgentEnvelope()),
	command("requirement-impact-input-compose", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementimpactinput")),
	command("requirement-proof-resolver", commandInputRequired, flags("--empty-local-environment-policy", "--input", "--input-pointer", "--local-environment-class"), modes("json"), ownerDirs("requirementbinding"), withRunner(commandRunnerRequirementProofResolver)),
	command("requirement-proof-source-set", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementproofsourceset")),
	command("requirement-proof-view", commandInputRequired, flags("--empty-local-environment-policy", "--format", "--input", "--input-pointer", "--local-environment-class", "--scope"), modes("html", "json", "markdown"), ownerDirs("requirementproofview"), withRunner(commandRunnerRequirementView)),
	command("requirement-source-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementsourceadmission")),
	command("requirement-source-transition", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementsourcetransition")),
	command("requirement-source-view", commandInputRequired, flags("--format", "--input", "--input-pointer"), modes("html", "json", "markdown"), ownerDirs("requirementsourceview"), withRunner(commandRunnerRequirementView)),
	command("requirement-spec-tree", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementspectree")),
	command("requirement-spec-tree-view", commandInputRequired, flags("--format", "--input", "--input-pointer", "--output"), modes("html", "json", "markdown"), ownerDirs("requirementspectree"), withRunner(commandRunnerRequirementView)),
	command("scaffold-profile-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("scaffoldprofileplan")),
	command("scaffold-project-structure", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("projectstructure"), withRunner(commandRunnerProjectStructure), withAgentEnvelope()),
	command("selective-gate-evidence", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateevidence"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("selective-gate-obligation-decision-input", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateevidence"), withRunner(commandRunnerPlanning)),
	command("selective-gate-plan", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateplan"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("secret-scan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("secretscan")),
	command("self-check", commandInputRequired, flags("--input"), modes("json"), ownerDirs("selfcheck"), withSemanticAppTests("TestSelfCheckRejectsDuplicateKeys")),
	command("spec-overview-claims", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("specoverviewclaims")),
	command("spec-proof-bundle-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("specproofbundleadmission")),
	command("stack-preset", commandInputNone, flags("--preset"), modes("json"), ownerDirs("stackpreset"), withRunner(commandRunnerStackPreset), withSemanticAppTests("TestNoInputCommandsHaveCommandSpecificBehavior")),
	command("test-evidence-inventory", commandInputRequired, flags("--input", "--input-pointer", "--normalized-inventory", "--projection"), modes("json", "normalized-inventory"), ownerDirs("proofbindingtestinventory", "testevidenceinventory"), withRunner(commandRunnerTestEvidenceInventory)),
	command("text-policy", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("textpolicy")),
	command("typescript-public-api-surfaces", commandInputRequired, flags("--input", "--input-pointer", "--repo-root"), modes("json"), ownerDirs("publicapi"), withRunner(commandRunnerTypeScriptPublicAPISurfaces), withScopeClass(commandScopeExplicitFileSystemScan)),
	command("witness-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("witnessplan")),
	command("witness-scheduler-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("witnessschedulerplan")),
	command("workspace-changed-package-plan", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("workspaceplanning"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("workspace-manifest-facts", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("workspacemanifestfacts")),
	command("workspace-registry", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("workspaceregistry")),
	command("workspace-shard-partition", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("workspaceplanning"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
}

var knownCommandRunners = map[commandRunner]struct{}{
	commandRunnerGenericInput:                {},
	commandRunnerAdoptionContractEnvelope:    {},
	commandRunnerAdoptionDoctor:              {},
	commandRunnerAdoptionWorkflow:            {},
	commandRunnerAgentRoute:                  {},
	commandRunnerConformanceProfile:          {},
	commandRunnerContractEnvelope:            {},
	commandRunnerGradualAdoptionBootstrap:    {},
	commandRunnerGradualAdoptionGuidance:     {},
	commandRunnerHelp:                        {},
	commandRunnerInit:                        {},
	commandRunnerJSONReportCLIAdapterSource:  {},
	commandRunnerPilotAdmission:              {},
	commandRunnerPlanning:                    {},
	commandRunnerProjectStructure:            {},
	commandRunnerRequirementBrowserServer:    {},
	commandRunnerRequirementProofResolver:    {},
	commandRunnerRequirementView:             {},
	commandRunnerStackPreset:                 {},
	commandRunnerTestEvidenceInventory:       {},
	commandRunnerTypeScriptPublicAPISurfaces: {},
}

var knownCommandScopeClasses = map[commandScopeClass]struct{}{
	commandScopeBuiltInPackageCatalog:  {},
	commandScopeExplicitCallerInput:    {},
	commandScopeExplicitFileSystemScan: {},
}

var commandDescriptorByName = buildCommandDescriptorIndex(commandDescriptors)
var supportedCommands = buildSupportedCommandSet(commandDescriptors)

type commandDescriptorOption func(*commandDescriptor)

func command(name string, input commandInputMode, allowedFlags []string, outputModes []string, semanticOwnerDirs []string, options ...commandDescriptorOption) commandDescriptor {
	descriptor := commandDescriptor{
		name:              name,
		input:             input,
		runner:            commandRunnerGenericInput,
		scopeClass:        defaultCommandScopeClass(input),
		allowedFlags:      cloneStrings(allowedFlags),
		outputModes:       cloneStrings(outputModes),
		semanticOwnerDirs: cloneStrings(semanticOwnerDirs),
	}
	for _, option := range options {
		option(&descriptor)
	}
	return descriptor
}

func defaultCommandScopeClass(input commandInputMode) commandScopeClass {
	if input == commandInputNone {
		return commandScopeBuiltInPackageCatalog
	}
	return commandScopeExplicitCallerInput
}

func withRunner(runner commandRunner) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.runner = runner
	}
}

func withScopeClass(scopeClass commandScopeClass) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.scopeClass = scopeClass
	}
}

func withAgentEnvelope() commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.agentEnvelope = true
	}
}

func withContractEnvelope() commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.contractEnvelope = true
	}
}

func withSemanticAppTests(testNames ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.semanticAppTests = cloneStrings(testNames)
	}
}

func withInputSchemaSummary(fields ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.inputSchemaSummary = cloneStrings(fields)
	}
}

func flags(values ...string) []string {
	return cloneStrings(values)
}

func modes(values ...string) []string {
	return cloneStrings(values)
}

func ownerDirs(values ...string) []string {
	return cloneStrings(values)
}

func buildCommandDescriptorIndex(descriptors []commandDescriptor) map[string]commandDescriptor {
	index := make(map[string]commandDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.name == "" {
			panic("command descriptor name is empty")
		}
		if _, exists := index[descriptor.name]; exists {
			panic("duplicate command descriptor: " + descriptor.name)
		}
		if !isKnownCommandRunner(descriptor.runner) {
			panic("unknown runner for command descriptor: " + descriptor.name)
		}
		if !isKnownCommandScopeClass(descriptor.scopeClass) {
			panic("unknown scope class for command descriptor: " + descriptor.name)
		}
		if len(descriptor.allowedFlags) == 0 || len(descriptor.outputModes) == 0 || len(descriptor.semanticOwnerDirs) == 0 {
			panic("incomplete command descriptor: " + descriptor.name)
		}
		if !isSortedUnique(descriptor.allowedFlags) || !isSortedUnique(descriptor.outputModes) || !isSortedUnique(descriptor.semanticOwnerDirs) || !isSortedUnique(descriptor.semanticAppTests) {
			panic("command descriptor lists must be sorted and unique: " + descriptor.name)
		}
		index[descriptor.name] = descriptor.clone()
	}
	return index
}

func buildSupportedCommandSet(descriptors []commandDescriptor) map[string]struct{} {
	commands := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		commands[descriptor.name] = struct{}{}
	}
	return commands
}

func commandDescriptorFor(name string) (commandDescriptor, bool) {
	descriptor, ok := commandDescriptorByName[name]
	if !ok {
		return commandDescriptor{}, false
	}
	return descriptor.clone(), true
}

func commandNamesMatching(predicate func(commandDescriptor) bool) []string {
	names := []string{}
	for _, descriptor := range commandDescriptors {
		if predicate(descriptor) {
			names = append(names, descriptor.name)
		}
	}
	sort.Strings(names)
	return names
}

func commandSemanticOwnerDirs(name string) []string {
	descriptor, ok := commandDescriptorFor(name)
	if !ok {
		return nil
	}
	return descriptor.semanticOwnerDirs
}

func commandSemanticAppTests(name string) []string {
	descriptor, ok := commandDescriptorFor(name)
	if !ok {
		return nil
	}
	return descriptor.semanticAppTests
}

func isKnownCommandRunner(runner commandRunner) bool {
	_, ok := knownCommandRunners[runner]
	return ok
}

func isKnownCommandScopeClass(scopeClass commandScopeClass) bool {
	_, ok := knownCommandScopeClasses[scopeClass]
	return ok
}

func isSortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" {
			return false
		}
		if index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func (descriptor commandDescriptor) clone() commandDescriptor {
	descriptor.allowedFlags = cloneStrings(descriptor.allowedFlags)
	descriptor.inputSchemaSummary = cloneStrings(descriptor.inputSchemaSummary)
	descriptor.outputModes = cloneStrings(descriptor.outputModes)
	descriptor.semanticAppTests = cloneStrings(descriptor.semanticAppTests)
	descriptor.semanticOwnerDirs = cloneStrings(descriptor.semanticOwnerDirs)
	return descriptor
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}
