package app

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionchecklist"
	"github.com/research-engineering/agentic-proofkit/internal/command/bindingpartition"
	"github.com/research-engineering/agentic-proofkit/internal/command/branchauthority"
	"github.com/research-engineering/agentic-proofkit/internal/command/capabilitymapadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
	"github.com/research-engineering/agentic-proofkit/internal/command/customruleboundary"
	"github.com/research-engineering/agentic-proofkit/internal/command/deploymentevidenceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/documentlifecycle"
	"github.com/research-engineering/agentic-proofkit/internal/command/externalconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/command/initplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/migrationparityadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/migrationplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/packageruntimedependency"
	"github.com/research-engineering/agentic-proofkit/internal/command/producerpolicyselfproof"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofobligationalgebra"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/readinesscloseout"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptcurrentnessscope"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receipttrustclass"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumerinputcompose"
	"github.com/research-engineering/agentic-proofkit/internal/command/releaseauthority"
	"github.com/research-engineering/agentic-proofkit/internal/command/renderedartifactfreshness"
	"github.com/research-engineering/agentic-proofkit/internal/command/repoprofileadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementauthoringplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementimpactinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofsourceset"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/secretscan"
	"github.com/research-engineering/agentic-proofkit/internal/command/specoverviewclaims"
	"github.com/research-engineering/agentic-proofkit/internal/command/specproofbundleadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspacemanifestfacts"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceregistry"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

type genericCommandBuilder func(any) (any, int, error)

var genericCommandBuilders = mustGenericCommandBuilders(map[string]genericCommandBuilder{
	"adoption-checklist":                   reportOutput(adoptionchecklist.Build),
	"binding-partition":                    reportOutput(bindingpartition.Build),
	"branch-authority":                     reportOutputWithoutError(branchauthority.Build),
	"capability-map-admission":             reportOutput(capabilitymapadmission.Build),
	"completion-criteria":                  reportOutput(completioncriteria.Build),
	"custom-rule-boundary":                 reportOutput(customruleboundary.Build),
	"deployment-evidence-admission":        reportOutput(deploymentevidenceadmission.Build),
	"document-lifecycle-boundary":          reportOutput(documentlifecycle.Build),
	"evidence-graph":                       requirementbinding.BuildEvidenceGraph,
	"external-consumer":                    reportOutput(externalconsumer.Build),
	"impact":                               outputWithExit(impact.Build),
	"migration-parity-admission":           reportOutput(migrationparityadmission.Build),
	"migration-plan":                       outputWithExit(migrationplan.Build),
	"package-runtime-dependency-admission": reportOutputWithoutError(packageruntimedependency.Build),
	"producer-policy-self-proof":           reportOutput(producerpolicyselfproof.Build),
	"proof-obligation-algebra":             reportOutput(proofobligationalgebra.Build),
	"proof-receipt-admission":              reportOutput(proofreceiptadmission.Build),
	"proof-slice":                          requirementbinding.BuildProofSlice,
	"readiness-closeout":                   reportOutput(readinesscloseout.Build),
	"receipt-currentness-scope":            reportOutput(receiptcurrentnessscope.Build),
	"receipt-producer-admission":           reportOutput(receiptproduceradmission.Build),
	"receipt-trust-class":                  reportOutput(receipttrustclass.Build),
	"registry-consumer":                    reportOutput(registryconsumer.Build),
	"registry-consumer-proof-input-compose": outputWithExit(
		registryconsumerinputcompose.Build,
	),
	"release-authority":                  reportOutput(releaseauthority.Build),
	"rendered-artifact-freshness":        reportOutput(renderedartifactfreshness.Build),
	"repo-profile-admission":             reportOutput(repoprofileadmission.Build),
	"requirement-authoring-plan":         outputWithExit(requirementauthoringplan.Build),
	"requirement-bindings":               reportOutput(requirementbinding.BuildReport),
	"requirement-coverage-input-compose": outputWithExit(requirementcoverageinput.Build),
	"requirement-context-slice":          zeroExitOutput(requirementcontext.Slice),
	"requirement-semantic-diff":          zeroExitOutput(requirementdiff.Build),
	"requirement-traceability-graph":     zeroExitOutput(requirementgraph.Build),
	"requirement-impact-input-compose":   outputWithExit(requirementimpactinput.Build),
	"requirement-proof-source-set":       requirementproofsourceset.Build,
	"requirement-source-admission":       reportOutput(requirementsourceadmission.Build),
	"requirement-source-transition":      reportOutput(requirementsourcetransition.Build),
	"requirement-spec-tree":              reportOutput(requirementspectree.Build),
	"scaffold-profile-plan":              zeroExitOutput(scaffoldprofileplan.Build),
	"secret-scan":                        reportOutput(secretscan.Build),
	"self-check":                         selfCheckOutput,
	"spec-overview-claims":               reportOutput(specoverviewclaims.Build),
	"spec-proof-bundle-admission":        reportOutput(specproofbundleadmission.Build),
	"text-policy":                        reportOutput(textpolicy.Build),
	"witness-plan":                       zeroExitOutput(witnessplan.Build),
	"witness-scheduler-plan":             reportOutput(witnessschedulerplan.Build),
	"workspace-manifest-facts":           outputWithExit(workspacemanifestfacts.Build),
	"workspace-registry":                 reportOutput(workspaceregistry.Build),
})

func buildOutput(command string, input any) (any, int, error) {
	builder, ok := genericCommandBuilders[command]
	if !ok {
		return nil, 1, fmt.Errorf("unsupported generic command: %s", command)
	}
	return builder(input)
}

func outputWithExit[T any](builder func(any) (T, int, error)) genericCommandBuilder {
	return func(input any) (any, int, error) {
		return builder(input)
	}
}

func zeroExitOutput[T any](builder func(any) (T, error)) genericCommandBuilder {
	return func(input any) (any, int, error) {
		output, err := builder(input)
		return output, 0, err
	}
}

func reportOutput(builder func(any) (report.Record, int, error)) genericCommandBuilder {
	return func(input any) (any, int, error) {
		record, exitCode, err := builder(input)
		if err != nil {
			return nil, exitCode, err
		}
		return record.JSONValue(), exitCode, nil
	}
}

func reportOutputWithoutError(builder func(any) (report.Record, int)) genericCommandBuilder {
	return func(input any) (any, int, error) {
		record, exitCode := builder(input)
		return record.JSONValue(), exitCode, nil
	}
}

func selfCheckOutput(input any) (any, int, error) {
	return report.BuildSelfCheckReport(input).JSONValue(), 0, nil
}

func mustGenericCommandBuilders(builders map[string]genericCommandBuilder) map[string]genericCommandBuilder {
	for _, descriptor := range commandDescriptors {
		_, registered := builders[descriptor.name]
		if descriptor.runner == commandRunnerGenericInput && !registered {
			panic("generic command has no builder: " + descriptor.name)
		}
		if descriptor.runner != commandRunnerGenericInput && registered {
			panic("non-generic command has an unreachable generic builder: " + descriptor.name)
		}
	}
	for command, builder := range builders {
		descriptor, exists := commandDescriptorByName[command]
		if !exists || descriptor.runner != commandRunnerGenericInput {
			panic("generic builder has no generic command descriptor: " + command)
		}
		if builder == nil {
			panic("generic command has a nil builder: " + command)
		}
	}
	return builders
}

func buildInitReport(preset string) (report.Record, error) {
	return initplan.Build(preset)
}
