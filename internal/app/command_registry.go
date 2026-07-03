package app

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionchecklist"
	"github.com/research-engineering/agentic-proofkit/internal/command/agentroute"
	"github.com/research-engineering/agentic-proofkit/internal/command/bindingpartition"
	"github.com/research-engineering/agentic-proofkit/internal/command/branchauthority"
	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
	"github.com/research-engineering/agentic-proofkit/internal/command/customruleboundary"
	"github.com/research-engineering/agentic-proofkit/internal/command/deploymentevidenceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/documentlifecycle"
	"github.com/research-engineering/agentic-proofkit/internal/command/externalconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
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
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementimpactinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementproofsourceset"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/command/scaffoldprofileplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/specoverviewclaims"
	"github.com/research-engineering/agentic-proofkit/internal/command/specproofbundleadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspacemanifestfacts"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceregistry"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

func buildOutput(command string, input any) (any, int, error) {
	if command == "impact" {
		return impact.Build(input)
	}
	if command == "migration-plan" {
		return migrationplan.Build(input)
	}
	if command == "witness-plan" {
		output, err := witnessplan.Build(input)
		return output, 0, err
	}
	if command == "evidence-graph" {
		return requirementbinding.BuildEvidenceGraph(input)
	}
	if command == "proof-slice" {
		return requirementbinding.BuildProofSlice(input)
	}
	if command == "requirement-proof-source-set" {
		return requirementproofsourceset.Build(input)
	}
	if command == "requirement-coverage-view" {
		return requirementcoverageview.BuildJSON(input, requirementcoverageview.Options{})
	}
	if command == "requirement-coverage-input-compose" {
		return requirementcoverageinput.Build(input)
	}
	if command == "requirement-impact-input-compose" {
		return requirementimpactinput.Build(input)
	}
	if command == "requirement-authoring-plan" {
		return requirementauthoringplan.Build(input)
	}
	if command == "registry-consumer-proof-input-compose" {
		return registryconsumerinputcompose.Build(input)
	}
	if command == "workspace-manifest-facts" {
		return workspacemanifestfacts.Build(input)
	}
	if command == "scaffold-profile-plan" {
		output, err := scaffoldprofileplan.Build(input)
		return output, 0, err
	}
	if command == "agent-route" {
		return agentroute.Build(input)
	}
	record, exitCode, err := buildReport(command, input)
	if err != nil {
		return nil, exitCode, err
	}
	return record.JSONValue(), exitCode, nil
}

func buildReport(command string, input any) (report.Record, int, error) {
	if command == "adoption-checklist" {
		return adoptionchecklist.Build(input)
	}
	if command == "binding-partition" {
		return bindingpartition.Build(input)
	}
	if command == "branch-authority" {
		record, exitCode := branchauthority.Build(input)
		return record, exitCode, nil
	}
	if command == "completion-criteria" {
		return completioncriteria.Build(input)
	}
	if command == "custom-rule-boundary" {
		return customruleboundary.Build(input)
	}
	if command == "deployment-evidence-admission" {
		return deploymentevidenceadmission.Build(input)
	}
	if command == "document-lifecycle-boundary" {
		return documentlifecycle.Build(input)
	}
	if command == "external-consumer" {
		return externalconsumer.Build(input)
	}
	if command == "migration-parity-admission" {
		return migrationparityadmission.Build(input)
	}
	if command == "package-runtime-dependency-admission" {
		record, exitCode := packageruntimedependency.Build(input)
		return record, exitCode, nil
	}
	if command == "proof-obligation-algebra" {
		return proofobligationalgebra.Build(input)
	}
	if command == "producer-policy-self-proof" {
		return producerpolicyselfproof.Build(input)
	}
	if command == "proof-receipt-admission" {
		return proofreceiptadmission.Build(input)
	}
	if command == "readiness-closeout" {
		return readinesscloseout.Build(input)
	}
	if command == "receipt-currentness-scope" {
		return receiptcurrentnessscope.Build(input)
	}
	if command == "receipt-producer-admission" {
		return receiptproduceradmission.Build(input)
	}
	if command == "receipt-trust-class" {
		return receipttrustclass.Build(input)
	}
	if command == "registry-consumer" {
		return registryconsumer.Build(input)
	}
	if command == "rendered-artifact-freshness" {
		return renderedartifactfreshness.Build(input)
	}
	if command == "requirement-bindings" {
		return requirementbinding.BuildReport(input)
	}
	if command == "release-authority" {
		return releaseauthority.Build(input)
	}
	if command == "repo-profile-admission" {
		return repoprofileadmission.Build(input)
	}
	if command == "requirement-source-admission" {
		return requirementsourceadmission.Build(input)
	}
	if command == "requirement-spec-tree" {
		return requirementspectree.Build(input)
	}
	if command == "requirement-source-transition" {
		return requirementsourcetransition.Build(input)
	}
	if command == "spec-overview-claims" {
		return specoverviewclaims.Build(input)
	}
	if command == "spec-proof-bundle-admission" {
		return specproofbundleadmission.Build(input)
	}
	if command == "test-evidence-inventory" {
		return testevidenceinventory.Build(input)
	}
	if command == "text-policy" {
		return textpolicy.Build(input)
	}
	if command == "witness-scheduler-plan" {
		return witnessschedulerplan.Build(input)
	}
	if command == "workspace-registry" {
		return workspaceregistry.Build(input)
	}
	if command == "self-check" {
		return report.BuildSelfCheckReport(input), 0, nil
	}
	return report.Record{}, 1, fmt.Errorf("unsupported command: %s", command)
}
