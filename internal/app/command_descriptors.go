package app

import (
	"slices"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbrowser"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofview"
)

type commandInputMode string

const (
	commandInputNone     commandInputMode = "none"
	commandInputRequired commandInputMode = "required"
)

type commandRunner string

const (
	commandRunnerGenericInput                commandRunner = "generic_input"
	commandRunnerAdoptionFrontDoor           commandRunner = "adoption_front_door"
	commandRunnerAdoptionContractEnvelope    commandRunner = "adoption_contract_envelope"
	commandRunnerAdoptionDoctor              commandRunner = "adoption_doctor"
	commandRunnerAdoptionWorkflow            commandRunner = "adoption_workflow"
	commandRunnerAgentWorkflow               commandRunner = "agent_workflow"
	commandRunnerAgentRoute                  commandRunner = "agent_route"
	commandRunnerConformanceProfile          commandRunner = "conformance_profile"
	commandRunnerContractEnvelope            commandRunner = "contract_envelope"
	commandRunnerGradualAdoptionBootstrap    commandRunner = "gradual_adoption_bootstrap"
	commandRunnerGradualAdoptionGuidance     commandRunner = "gradual_adoption_guidance"
	commandRunnerHelp                        commandRunner = "help"
	commandRunnerJSONReportCLIAdapterSource  commandRunner = "json_report_cli_adapter_source"
	commandRunnerPilotAdmission              commandRunner = "pilot_admission"
	commandRunnerPlanning                    commandRunner = "planning"
	commandRunnerProjectStructure            commandRunner = "project_structure"
	commandRunnerRequirementBrowserServer    commandRunner = "requirement_browser_server"
	commandRunnerRequirementContextCompose   commandRunner = "requirement_context_compose"
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
	name                     string
	routeTokens              []string
	input                    commandInputMode
	runner                   commandRunner
	scopeClass               commandScopeClass
	allowedFlags             []string
	requiredFlags            []string
	exactlyOneOfFlagGroups   [][]string
	atMostOneOfFlagGroups    [][]string
	flagPresenceRequirements []flagPresenceRequirement
	flagValueRequirements    []flagValueRequirement
	singleOccurrenceFlags    []string
	flagValueChoices         map[string][]string
	inputSchemaSummary       []string
	outputModes              []string
	agentEnvelope            bool
	contractEnvelope         bool
	semanticAppTests         []string
	semanticOwnerDirs        []string
}

type flagValueRequirement struct {
	Flag               string              `json:"flag"`
	RequiredFlagValues []requiredFlagValue `json:"requiredFlagValues,omitempty"`
	RequiredFlags      []string            `json:"requiredFlags"`
	Value              string              `json:"value"`
}

type flagPresenceRequirement struct {
	Flag               string              `json:"flag"`
	RequiredFlagValues []requiredFlagValue `json:"requiredFlagValues,omitempty"`
	RequiredFlags      []string            `json:"requiredFlags"`
}

type requiredFlagValue struct {
	Flag  string `json:"flag"`
	Value string `json:"value"`
}

var commandDescriptors = []commandDescriptor{
	command("adopt-plan", commandInputNone, flags("--color", "--format", "--mode", "--repo-root", "--stack"), modes("json", "text"), ownerDirs("adoptionplan", "repositoryinventory"), withRunner(commandRunnerAdoptionFrontDoor), withSemanticAppTests("TestAdoptionFrontDoorCLI"), withScopeClass(commandScopeExplicitFileSystemScan), withRequiredFlags("--mode", "--repo-root"), withFlagPresenceAndRequiredValue("--color", "--format", "text"), withSingleOccurrenceFlags("--color", "--mode", "--repo-root", "--stack")),
	command("adoption-checklist", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("adoptionchecklist")),
	command("adoption-contract-envelope", commandInputRequired, flags("--agent-envelope", "--checked-scope", "--guidance-mode", "--input", "--materialization-manifest", "--mode", "--pilot", "--touched-rule-id"), modes("json"), ownerDirs("adoptioncontract"), withRunner(commandRunnerAdoptionContractEnvelope), withAgentEnvelope(), withRequiredFlags("--mode")),
	command("adoption-doctor", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("adoptiondoctor"), withRunner(commandRunnerAdoptionDoctor), withSemanticAppTests("TestAdoptionDoctorCLIABI"), withAgentEnvelope()),
	command("adoption-workflow-plan", commandInputRequired, flags("--agent-envelope", "--contract-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("adoptionworkflow"), withRunner(commandRunnerAdoptionWorkflow), withAgentEnvelope(), withContractEnvelope()),
	command("agent-route", commandInputRequired, flags("--agent-envelope", "--agent-envelope-mode", "--input", "--input-pointer"), modes("json"), ownerDirs("agentroute"), withRunner(commandRunnerAgentRoute), withAgentEnvelope(), withFlagChoices("--agent-envelope-mode", "brief", "full"), withFlagPresenceRequirement("--agent-envelope-mode", "--agent-envelope"), withSingleOccurrenceFlags("--agent-envelope", "--agent-envelope-mode", "--input", "--input-pointer")),
	command("binding-partition", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("bindingpartition")),
	command("branch-authority", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("branchauthority")),
	command("capability-map-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("capabilitymapadmission")),
	command("change-workflow-plan", commandInputRequired, flags("--agent-envelope", "--color", "--format", "--input", "--input-pointer"), modes("json", "text"), ownerDirs("changeworkflowplan"), withRunner(commandRunnerAgentWorkflow), withSemanticAppTests("TestAgentWorkflowCLITruthTable"), withAgentEnvelope(), withFlagChoices("--color", "auto", "never"), withFlagChoices("--format", "json", "text"), withSingleOccurrenceFlags("--agent-envelope", "--color", "--input", "--input-pointer")),
	command("changed-path-set", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("changedpathset"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("completion-criteria", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("completioncriteria")),
	command("conformance-profile", commandInputRequired, flags("--format", "--input", "--input-pointer", "--list", "--profile", "--verify"), modes("json", "markdown"), ownerDirs("conformanceprofile"), withRunner(commandRunnerConformanceProfile), withExactlyOneOfFlags("--list", "--profile", "--verify"), withFlagValueRequirement("--format", "markdown", "--profile")),
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
	command("json-report-cli-adapter-source", commandInputNone, flags("--format", "--language"), modes("json"), ownerDirs("jsonreportcliadaptersource"), withRunner(commandRunnerJSONReportCLIAdapterSource), withRequiredFlags("--language")),
	command("migration-parity-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("migrationparityadmission")),
	command("migration-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("migrationplan")),
	command("native-evidence-guidance", commandInputNone, flags("--color", "--format"), modes("json", "text"), ownerDirs("nativeevidenceguidance"), withRunner(commandRunnerAgentWorkflow), withSemanticAppTests("TestAgentWorkflowCLITruthTable"), withFlagChoices("--color", "auto", "never"), withFlagChoices("--format", "json", "text"), withSingleOccurrenceFlags("--color")),
	command("obligation-decision", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("obligationdecision"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("package-runtime-dependency-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("packageruntimedependency")),
	command("pilot-admission", commandInputRequired, flags("--contract-envelope", "--input", "--input-pointer", "--pilot", "--stack-diverse"), modes("json"), ownerDirs("pilotadmission"), withRunner(commandRunnerPilotAdmission), withContractEnvelope(), withFlagValueRequirement("--pilot", "all", "--contract-envelope")),
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
	command("repository-inventory", commandInputNone, flags("--repo-root"), modes("json"), ownerDirs("repositoryinventory"), withRunner(commandRunnerAdoptionFrontDoor), withSemanticAppTests("TestAdoptionFrontDoorCLI"), withScopeClass(commandScopeExplicitFileSystemScan), withRequiredFlags("--repo-root"), withSingleOccurrenceFlags("--repo-root")),
	command("requirement-authoring-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementauthoringplan")),
	command("requirement-bindings", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementbinding")),
	command("requirement-browser-server", commandInputRequired, flags("--empty-local-environment-policy", "--host", "--input", "--input-pointer", "--local-environment-class", "--open", "--port", "--scope", "--serve", "--session-mode", "--session-timeout-seconds", "--view"), modes("json", "server"), ownerDirs("requirementbrowser"), withRunner(commandRunnerRequirementBrowserServer), withSemanticAppTests("TestRequirementBrowserServerSpecTreeCLIABI"), withRequiredFlags("--view"), withAtMostOneOfFlags("--empty-local-environment-policy", "--local-environment-class"), withFlagChoices("--host", requirementbrowser.HostChoices()...), withFlagChoices("--scope", requirementproofview.ScopeChoices()...), withFlagChoices("--session-mode", requirementbrowser.SessionModeChoices()...), withFlagChoices("--view", requirementbrowser.ViewChoices()...), withFlagPresenceAndRequiredValue("--empty-local-environment-policy", "--view", "proof"), withFlagPresenceAndRequiredValue("--local-environment-class", "--view", "proof"), withFlagPresenceRequirement("--open", "--serve"), withFlagPresenceAndRequiredValue("--scope", "--view", "proof"), withFlagPresenceAndRequiredValue("--session-timeout-seconds", "--session-mode", "one-shot-question"), withFlagValueAndRequiredValue("--session-mode", "browse", "--view", "workspace", "--serve"), withFlagValueAndRequiredValue("--session-mode", "one-shot-question", "--view", "workspace", "--open", "--serve"), withSingleOccurrenceFlags(requirementBrowserSingleOccurrenceFlags...)),
	command("requirement-context-compose", commandInputRequired, flags("--input", "--input-pointer", "--repo-root"), modes("json"), ownerDirs("requirementcontext"), withRunner(commandRunnerRequirementContextCompose), withSemanticAppTests("TestRequirementContextCommandsComposeThroughWholeCLI"), withScopeClass(commandScopeExplicitFileSystemScan), withRequiredFlags("--repo-root")),
	command("requirement-context-slice", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementcontext"), withSemanticAppTests("TestRequirementContextCommandsComposeThroughWholeCLI")),
	command("requirement-coverage-input-compose", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementcoverageinput")),
	command("requirement-coverage-view", commandInputRequired, flags("--agent-envelope", "--format", "--input", "--input-pointer"), modes("html", "json", "markdown"), ownerDirs("requirementcoverageview"), withRunner(commandRunnerRequirementView), withAgentEnvelope()),
	command("requirement-impact-input-compose", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementimpactinput")),
	command("requirement-proof-resolver", commandInputRequired, flags("--empty-local-environment-policy", "--input", "--input-pointer", "--local-environment-class"), modes("json"), ownerDirs("requirementbinding"), withRunner(commandRunnerRequirementProofResolver), withExactlyOneOfFlags("--empty-local-environment-policy", "--local-environment-class")),
	command("requirement-proof-source-set", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementproofsourceset")),
	command("requirement-proof-view", commandInputRequired, flags("--empty-local-environment-policy", "--format", "--input", "--input-pointer", "--local-environment-class", "--scope"), modes("html", "json", "markdown"), ownerDirs("requirementproofview"), withRunner(commandRunnerRequirementView)),
	command("requirement-semantic-diff", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementdiff"), withSemanticAppTests("TestRequirementContextCommandsComposeThroughWholeCLI")),
	command("requirement-source-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementsourceadmission")),
	command("requirement-source-transition", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementsourcetransition")),
	command("requirement-source-view", commandInputRequired, flags("--format", "--input", "--input-pointer"), modes("html", "json", "markdown"), ownerDirs("requirementsourceview"), withRunner(commandRunnerRequirementView)),
	command("requirement-spec-tree", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementspectree")),
	command("requirement-spec-tree-view", commandInputRequired, flags("--format", "--input", "--input-pointer", "--output"), modes("html", "json", "markdown"), ownerDirs("requirementspectree"), withRunner(commandRunnerRequirementView)),
	command("requirement-traceability-graph", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("requirementgraph"), withSemanticAppTests("TestRequirementContextCommandsComposeThroughWholeCLI")),
	command("scaffold-profile-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("scaffoldprofileplan")),
	command("scaffold-project-structure", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("projectstructure"), withRunner(commandRunnerProjectStructure), withAgentEnvelope()),
	command("selective-gate-evidence", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateevidence"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("selective-gate-obligation-decision-input", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateevidence"), withRunner(commandRunnerPlanning)),
	command("selective-gate-plan", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("selectivegateplan"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("secret-scan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("secretscan")),
	command("self-check", commandInputRequired, flags("--input"), modes("json"), ownerDirs("selfcheck"), withSemanticAppTests("TestSelfCheckRejectsDuplicateKeys")),
	command("spec-overview-claims", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("specoverviewclaims")),
	command("spec-proof-bundle-admission", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("specproofbundleadmission")),
	command("stack-preset", commandInputNone, flags("--preset"), modes("json"), ownerDirs("stackpreset"), withRunner(commandRunnerStackPreset), withSemanticAppTests("TestNoInputCommandsHaveCommandSpecificBehavior"), withRequiredFlags("--preset")),
	command("test-evidence-inventory", commandInputRequired, flags("--input", "--input-pointer", "--normalized-inventory", "--projection"), modes("json", "normalized-inventory"), ownerDirs("proofbindingtestinventory", "testevidenceinventory"), withRunner(commandRunnerTestEvidenceInventory)),
	command("text-policy", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("textpolicy")),
	command("typescript-public-api-surfaces", commandInputRequired, flags("--input", "--input-pointer", "--repo-root"), modes("json"), ownerDirs("publicapi"), withRunner(commandRunnerTypeScriptPublicAPISurfaces), withScopeClass(commandScopeExplicitFileSystemScan), withRequiredFlags("--repo-root")),
	command("witness-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("witnessplan")),
	command("witness-scheduler-plan", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("witnessschedulerplan")),
	command("workspace-changed-package-plan", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("workspaceplanning"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
	command("workspace-manifest-facts", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("workspacemanifestfacts")),
	command("workspace-registry", commandInputRequired, flags("--input", "--input-pointer"), modes("json"), ownerDirs("workspaceregistry")),
	command("workspace-shard-partition", commandInputRequired, flags("--agent-envelope", "--input", "--input-pointer"), modes("json"), ownerDirs("workspaceplanning"), withRunner(commandRunnerPlanning), withAgentEnvelope()),
}

var knownCommandRunners = map[commandRunner]struct{}{
	commandRunnerGenericInput:                {},
	commandRunnerAdoptionFrontDoor:           {},
	commandRunnerAdoptionContractEnvelope:    {},
	commandRunnerAdoptionDoctor:              {},
	commandRunnerAdoptionWorkflow:            {},
	commandRunnerAgentWorkflow:               {},
	commandRunnerAgentRoute:                  {},
	commandRunnerConformanceProfile:          {},
	commandRunnerContractEnvelope:            {},
	commandRunnerGradualAdoptionBootstrap:    {},
	commandRunnerGradualAdoptionGuidance:     {},
	commandRunnerHelp:                        {},
	commandRunnerJSONReportCLIAdapterSource:  {},
	commandRunnerPilotAdmission:              {},
	commandRunnerPlanning:                    {},
	commandRunnerProjectStructure:            {},
	commandRunnerRequirementBrowserServer:    {},
	commandRunnerRequirementContextCompose:   {},
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
		routeTokens:       []string{name},
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
	if slices.Contains(descriptor.allowedFlags, "--format") {
		descriptor.singleOccurrenceFlags = sortedUniqueStrings(append(descriptor.singleOccurrenceFlags, "--format"))
	}
	explicitFlagChoices := cloneStringMap(descriptor.flagValueChoices)
	metadata, ok := generatedCommandContractMetadataByName[name]
	if !ok {
		panic("command descriptor is missing generated contract metadata: " + name)
	}
	descriptor.routeTokens = cloneStrings(metadata.RouteTokens)
	descriptor.inputSchemaSummary = cloneStrings(metadata.InputSchemaSummary)
	descriptor.flagValueChoices = cloneStringMap(metadata.FlagChoices)
	for flag, choices := range explicitFlagChoices {
		if generated, exists := descriptor.flagValueChoices[flag]; exists && !slices.Equal(generated, choices) {
			panic("explicit and generated flag choices disagree: " + name + " " + flag)
		}
		descriptor.flagValueChoices[flag] = cloneStrings(choices)
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

func withRequiredFlags(flags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.requiredFlags = cloneStrings(flags)
	}
}

func withExactlyOneOfFlags(flags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.exactlyOneOfFlagGroups = append(descriptor.exactlyOneOfFlagGroups, cloneStrings(flags))
	}
}

func withAtMostOneOfFlags(flags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.atMostOneOfFlagGroups = append(descriptor.atMostOneOfFlagGroups, cloneStrings(flags))
	}
}

func withFlagChoices(flag string, values ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		if descriptor.flagValueChoices == nil {
			descriptor.flagValueChoices = map[string][]string{}
		}
		descriptor.flagValueChoices[flag] = cloneStrings(values)
	}
}

func withFlagPresenceRequirement(flag string, requiredFlags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.flagPresenceRequirements = append(descriptor.flagPresenceRequirements, flagPresenceRequirement{
			Flag: flag, RequiredFlags: append([]string{}, requiredFlags...),
		})
	}
}

func withFlagPresenceAndRequiredValue(flag string, requiredFlag string, requiredValue string, requiredFlags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.flagPresenceRequirements = append(descriptor.flagPresenceRequirements, flagPresenceRequirement{
			Flag: flag,
			RequiredFlagValues: []requiredFlagValue{{
				Flag:  requiredFlag,
				Value: requiredValue,
			}},
			RequiredFlags: append([]string{}, requiredFlags...),
		})
	}
}

func withFlagValueRequirement(flag string, value string, requiredFlags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.flagValueRequirements = append(descriptor.flagValueRequirements, flagValueRequirement{
			Flag: flag, RequiredFlags: cloneStrings(requiredFlags), Value: value,
		})
	}
}

func withFlagValueAndRequiredValue(flag string, value string, requiredFlag string, requiredValue string, requiredFlags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.flagValueRequirements = append(descriptor.flagValueRequirements, flagValueRequirement{
			Flag: flag,
			RequiredFlagValues: []requiredFlagValue{{
				Flag:  requiredFlag,
				Value: requiredValue,
			}},
			RequiredFlags: cloneStrings(requiredFlags),
			Value:         value,
		})
	}
}

func withSingleOccurrenceFlags(flags ...string) commandDescriptorOption {
	return func(descriptor *commandDescriptor) {
		descriptor.singleOccurrenceFlags = append(descriptor.singleOccurrenceFlags, flags...)
	}
}

func sortedUniqueStrings(values []string) []string {
	result := cloneStrings(values)
	sort.Strings(result)
	return slices.Compact(result)
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
		if !validCommandRoute(descriptor.routeTokens) {
			panic("invalid command descriptor route: " + descriptor.name)
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
		if !isSortedUnique(descriptor.allowedFlags) || !isSortedUnique(descriptor.requiredFlags) || !isSortedUnique(descriptor.singleOccurrenceFlags) || !isSortedUnique(descriptor.outputModes) || !isSortedUnique(descriptor.semanticOwnerDirs) || !isSortedUnique(descriptor.semanticAppTests) || !isSortedUniqueFlagPresenceRequirements(descriptor.flagPresenceRequirements) || !isSortedUniqueFlagValueRequirements(descriptor.flagValueRequirements) {
			panic("command descriptor lists must be sorted and unique: " + descriptor.name)
		}
		for _, requiredFlag := range descriptor.requiredFlags {
			if !slices.Contains(descriptor.allowedFlags, requiredFlag) {
				panic("required flag is not allowed: " + descriptor.name + " " + requiredFlag)
			}
		}
		for _, group := range descriptor.exactlyOneOfFlagGroups {
			if len(group) < 2 || !isSortedUnique(group) {
				panic("exactly-one flag group must be sorted, unique, and contain at least two flags: " + descriptor.name)
			}
			for _, flag := range group {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					panic("exactly-one flag is not allowed: " + descriptor.name + " " + flag)
				}
			}
		}
		for _, group := range descriptor.atMostOneOfFlagGroups {
			if len(group) < 2 || !isSortedUnique(group) {
				panic("at-most-one flag group must be sorted, unique, and contain at least two flags: " + descriptor.name)
			}
			for _, flag := range group {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					panic("at-most-one flag is not allowed: " + descriptor.name + " " + flag)
				}
			}
		}
		for _, requirement := range descriptor.flagPresenceRequirements {
			if requirement.Flag == "" || !slices.Contains(descriptor.allowedFlags, requirement.Flag) || !isSortedUnique(requirement.RequiredFlags) || !isSortedUniqueRequiredFlagValues(requirement.RequiredFlagValues) {
				panic("invalid flag presence requirement: " + descriptor.name)
			}
			for _, flag := range requirement.RequiredFlags {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					panic("presence-required flag is not allowed: " + descriptor.name + " " + flag)
				}
			}
			for _, required := range requirement.RequiredFlagValues {
				if !slices.Contains(descriptor.allowedFlags, required.Flag) {
					panic("presence-required flag is not allowed: " + descriptor.name + " " + required.Flag)
				}
			}
		}
		for _, requirement := range descriptor.flagValueRequirements {
			if requirement.Flag == "" || requirement.Value == "" || !slices.Contains(descriptor.allowedFlags, requirement.Flag) || !isSortedUnique(requirement.RequiredFlags) || !isSortedUniqueRequiredFlagValues(requirement.RequiredFlagValues) {
				panic("invalid flag value requirement: " + descriptor.name)
			}
			for _, flag := range requirement.RequiredFlags {
				if !slices.Contains(descriptor.allowedFlags, flag) {
					panic("value-required flag is not allowed: " + descriptor.name + " " + flag)
				}
			}
			for _, required := range requirement.RequiredFlagValues {
				if !slices.Contains(descriptor.allowedFlags, required.Flag) {
					panic("value-required flag is not allowed: " + descriptor.name + " " + required.Flag)
				}
			}
		}
		for flag, choices := range descriptor.flagValueChoices {
			if !slices.Contains(descriptor.allowedFlags, flag) || !isSortedUnique(choices) {
				panic("invalid generated flag choices: " + descriptor.name + " " + flag)
			}
		}
		for _, flag := range descriptor.singleOccurrenceFlags {
			if !slices.Contains(descriptor.allowedFlags, flag) {
				panic("single-occurrence flag is not allowed: " + descriptor.name + " " + flag)
			}
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

func isSortedUniqueRequiredFlagValues(values []requiredFlagValue) bool {
	previous := requiredFlagValue{}
	for index, value := range values {
		if value.Flag == "" || value.Value == "" {
			return false
		}
		if index > 0 && (previous.Flag > value.Flag || previous.Flag == value.Flag && previous.Value >= value.Value) {
			return false
		}
		previous = value
	}
	return true
}

func isSortedUniqueFlagPresenceRequirements(values []flagPresenceRequirement) bool {
	previous := ""
	for index, value := range values {
		if value.Flag == "" || index > 0 && previous >= value.Flag {
			return false
		}
		previous = value.Flag
	}
	return true
}

func isSortedUniqueFlagValueRequirements(values []flagValueRequirement) bool {
	previous := ""
	for index, value := range values {
		key := value.Flag + "\x00" + value.Value
		if value.Flag == "" || value.Value == "" || index > 0 && previous >= key {
			return false
		}
		previous = key
	}
	return true
}

func (descriptor commandDescriptor) clone() commandDescriptor {
	descriptor.routeTokens = cloneStrings(descriptor.routeTokens)
	descriptor.allowedFlags = cloneStrings(descriptor.allowedFlags)
	descriptor.requiredFlags = cloneStrings(descriptor.requiredFlags)
	descriptor.exactlyOneOfFlagGroups = cloneStringMatrix(descriptor.exactlyOneOfFlagGroups)
	descriptor.atMostOneOfFlagGroups = cloneStringMatrix(descriptor.atMostOneOfFlagGroups)
	descriptor.flagPresenceRequirements = cloneFlagPresenceRequirements(descriptor.flagPresenceRequirements)
	descriptor.flagValueRequirements = cloneFlagValueRequirements(descriptor.flagValueRequirements)
	descriptor.singleOccurrenceFlags = cloneStrings(descriptor.singleOccurrenceFlags)
	descriptor.flagValueChoices = cloneStringMap(descriptor.flagValueChoices)
	descriptor.inputSchemaSummary = cloneStrings(descriptor.inputSchemaSummary)
	descriptor.outputModes = cloneStrings(descriptor.outputModes)
	descriptor.semanticAppTests = cloneStrings(descriptor.semanticAppTests)
	descriptor.semanticOwnerDirs = cloneStrings(descriptor.semanticOwnerDirs)
	return descriptor
}

func cloneStringMatrix(values [][]string) [][]string {
	out := make([][]string, 0, len(values))
	for _, value := range values {
		out = append(out, cloneStrings(value))
	}
	return out
}

func cloneFlagValueRequirements(values []flagValueRequirement) []flagValueRequirement {
	out := make([]flagValueRequirement, 0, len(values))
	for _, value := range values {
		value.RequiredFlags = append([]string{}, value.RequiredFlags...)
		value.RequiredFlagValues = append([]requiredFlagValue(nil), value.RequiredFlagValues...)
		out = append(out, value)
	}
	return out
}

func cloneFlagPresenceRequirements(values []flagPresenceRequirement) []flagPresenceRequirement {
	out := make([]flagPresenceRequirement, 0, len(values))
	for _, value := range values {
		value.RequiredFlags = append([]string{}, value.RequiredFlags...)
		value.RequiredFlagValues = append([]requiredFlagValue(nil), value.RequiredFlagValues...)
		out = append(out, value)
	}
	return out
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func cloneStringMap(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = cloneStrings(value)
	}
	return out
}
