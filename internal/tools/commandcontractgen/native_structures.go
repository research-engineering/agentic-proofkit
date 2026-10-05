package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionchecklist"
	"github.com/research-engineering/agentic-proofkit/internal/command/bindingpartition"
	"github.com/research-engineering/agentic-proofkit/internal/command/branchauthority"
	"github.com/research-engineering/agentic-proofkit/internal/command/changedpathset"
	"github.com/research-engineering/agentic-proofkit/internal/command/completioncriteria"
	"github.com/research-engineering/agentic-proofkit/internal/command/customruleboundary"
	"github.com/research-engineering/agentic-proofkit/internal/command/documentlifecycle"
	"github.com/research-engineering/agentic-proofkit/internal/command/impact"
	"github.com/research-engineering/agentic-proofkit/internal/command/obligationdecision"
	"github.com/research-engineering/agentic-proofkit/internal/command/packageruntimedependency"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofbindingtestinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofobligationalgebra"
	"github.com/research-engineering/agentic-proofkit/internal/command/proofreceiptadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/publicapi"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptcurrentnessscope"
	"github.com/research-engineering/agentic-proofkit/internal/command/receiptproduceradmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/receipttrustclass"
	"github.com/research-engineering/agentic-proofkit/internal/command/renderedartifactfreshness"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementauthoringplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementbinding"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcontext"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementdiff"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementgraph"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementimpactinput"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceadmission"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourcetransition"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementsourceview"
	"github.com/research-engineering/agentic-proofkit/internal/command/requirementspectree"
	"github.com/research-engineering/agentic-proofkit/internal/command/secretscan"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateevidence"
	"github.com/research-engineering/agentic-proofkit/internal/command/selectivegateplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/selfcheck"
	"github.com/research-engineering/agentic-proofkit/internal/command/testevidenceinventory"
	"github.com/research-engineering/agentic-proofkit/internal/command/textpolicy"
	"github.com/research-engineering/agentic-proofkit/internal/command/transactionresidue"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspacemanifestfacts"
	"github.com/research-engineering/agentic-proofkit/internal/command/workspaceplanning"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/agentenvelope"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/compactproofcontract"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcecodec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/requirementsourcemodel"
)

type nativeStructure struct {
	id                   string
	direction            string
	predecessors         []string
	commands             []string
	schema               func() (map[string]any, error)
	variants             []nativeStructureVariant
	wireVersion          json.Number
	versionField         string
	outOfBandVersion     json.Number
	aggregateVersion     json.Number // Contract version for variants with independent wire headers.
	optionalInputVersion bool
	jsonValueInput       bool // Unconstrained JSON input; its contract version is metadata only.
	semanticVersion      uint // Zero follows the wire version; nonzero identifies changed semantics.
}

type nativeStructureVariant struct {
	id     string
	when   string
	schema func() (map[string]any, error)
}

// This registry binds native structure owners to their exact public consumers.
// It is not a second schema interpreter or a replacement for native semantics.
func nativeStructures() []nativeStructure {
	return []nativeStructure{{
		id: "proofkit.requirement-bindings.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-bindings.input.v1.root-shape"}, commands: []string{"evidence-graph", "proof-slice", "requirement-bindings"},
		schema: func() (map[string]any, error) { return requirementbinding.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-bindings.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-bindings.output.v1.root-shape"}, commands: []string{"requirement-bindings"},
		schema: func() (map[string]any, error) { return requirementbinding.ReportOutputStructure(), nil },
	}, {
		id: "proofkit.evidence-graph.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.evidence-graph.output.v1.root-shape"}, commands: []string{"evidence-graph"},
		schema: func() (map[string]any, error) { return requirementbinding.EvidenceGraphOutputStructure(), nil },
	}, {
		id: "proofkit.proof-slice.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.proof-slice.output.v1.root-shape"}, commands: []string{"proof-slice"},
		schema: func() (map[string]any, error) { return requirementbinding.ProofSliceOutputStructure(), nil },
	}, {
		id: "proofkit.requirement-proof-resolver.output.v2.json-schema", direction: "output", wireVersion: json.Number("2"),
		predecessors: []string{"proofkit.requirement-proof-resolver.output.v2.root-shape"}, commands: []string{"requirement-proof-resolver"},
		schema: func() (map[string]any, error) { return compactproofcontract.ResolverOutputStructure(), nil },
	}, {
		id: "proofkit.witness-plan.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.witness-plan.input.v1.root-shape"}, commands: []string{"witness-plan"},
		optionalInputVersion: true,
		variants: []nativeStructureVariant{
			{id: "01-direct", when: "without projection", schema: func() (map[string]any, error) { return witnessplan.DirectInputStructure(), nil }},
			{id: "02-requirement-bindings-projection", when: "projection=requirement-bindings", schema: func() (map[string]any, error) { return witnessplan.ProjectedInputStructure(), nil }},
		},
	}, {
		id: "proofkit.witness-plan.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.witness-plan.output.v1.root-shape"}, commands: []string{"witness-plan"},
		outOfBandVersion: json.Number("1"),
		schema:           func() (map[string]any, error) { return witnessplan.OutputStructure(), nil },
	}, {
		id: "proofkit.witness-scheduler-plan.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.witness-scheduler-plan.input.v1.root-shape"}, commands: []string{"witness-scheduler-plan"},
		schema: func() (map[string]any, error) { return witnessschedulerplan.InputStructure(), nil },
	}, {
		id: "proofkit.witness-scheduler-plan.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.witness-scheduler-plan.output.v1.root-shape"}, commands: []string{"witness-scheduler-plan"},
		schema: func() (map[string]any, error) { return witnessschedulerplan.OutputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source.input.v2.json-schema",
		direction:    "input",
		predecessors: []string{"proofkit.requirement-source-admission.input.v1.root-shape", "proofkit.requirement-source-view.input.v1.root-shape"},
		commands:     []string{"requirement-source-admission", "requirement-source-view"},
		schema: func() (map[string]any, error) {
			return requirementsourcecodec.InputStructure(requirementsourcemodel.DefaultLimits())
		},
	}, {
		id:           "proofkit.requirement-source-admission.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-admission.output.v2.root-shape"},
		commands:     []string{"requirement-source-admission"},
		schema:       func() (map[string]any, error) { return requirementsourceadmission.OutputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-view.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-view.output.v2.root-shape"},
		commands:     []string{"requirement-source-view"},
		schema:       func() (map[string]any, error) { return requirementsourceview.OutputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-transition.input.v2.json-schema",
		direction:    "input",
		predecessors: []string{"proofkit.requirement-source-transition.input.v2.root-shape"},
		commands:     []string{"requirement-source-transition"},
		schema:       func() (map[string]any, error) { return requirementsourcetransition.InputStructure(), nil },
	}, {
		id:           "proofkit.requirement-source-transition.output.v2.json-schema",
		direction:    "output",
		predecessors: []string{"proofkit.requirement-source-transition.output.v2.root-shape"},
		commands:     []string{"requirement-source-transition"},
		schema:       func() (map[string]any, error) { return requirementsourcetransition.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-authoring-plan.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-authoring-plan.input.v2.root-shape"}, commands: []string{"requirement-authoring-plan"},
		schema: func() (map[string]any, error) { return requirementauthoringplan.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-authoring-plan.output.v3.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-authoring-plan.output.v3.root-shape"}, commands: []string{"requirement-authoring-plan"},
		schema: func() (map[string]any, error) { return requirementauthoringplan.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-context-compose.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-context-compose.input.v2.root-shape"}, commands: []string{"requirement-context-compose"},
		schema: func() (map[string]any, error) { return requirementcontext.CatalogInputStructure(), nil },
	}, {
		id: "proofkit.requirement-spec-tree.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-spec-tree.input.v1.root-shape", "proofkit.requirement-spec-tree-view.input.v1.root-shape"},
		commands:     []string{"requirement-spec-tree", "requirement-spec-tree-view"},
		schema:       func() (map[string]any, error) { return requirementspectree.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-spec-tree.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-spec-tree.output.v1.root-shape"}, commands: []string{"requirement-spec-tree"},
		schema: func() (map[string]any, error) { return requirementspectree.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-spec-tree-view.output.v2.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-spec-tree-view.output.v2.root-shape"}, commands: []string{"requirement-spec-tree-view"},
		schema: func() (map[string]any, error) { return requirementspectree.ViewOutputStructure(), nil },
	}, {
		id: "proofkit.requirement-coverage-view.output.v4.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-coverage-view.output.v4.root-shape"}, commands: []string{"requirement-coverage-view"},
		wireVersion: json.Number("4"),
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope", schema: agentEnvelopeRootStructure},
			{id: "02-report", when: "without --agent-envelope", schema: func() (map[string]any, error) { return requirementcoverageview.OutputStructure(), nil }},
		},
	}, {
		id: "proofkit.requirement-context-compose.output.v4.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-context-compose.output.v4.root-shape"}, commands: []string{"requirement-context-compose"},
		schema: func() (map[string]any, error) { return requirementcontext.CatalogSnapshotStructure(), nil },
	}, {
		id: "proofkit.requirement-context-slice.input.v2.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-context-slice.input.v2.root-shape"}, commands: []string{"requirement-context-slice"},
		schema: func() (map[string]any, error) { return requirementcontext.SliceInputStructure(), nil },
	}, {
		id: "proofkit.requirement-semantic-diff.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-semantic-diff.input.v3.root-shape"}, commands: []string{"requirement-semantic-diff"},
		schema: func() (map[string]any, error) { return requirementdiff.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-traceability-graph.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-traceability-graph.input.v3.root-shape"}, commands: []string{"requirement-traceability-graph"},
		schema: func() (map[string]any, error) { return requirementgraph.InputStructure(), nil },
	}, {
		id: "proofkit.requirement-traceability-graph.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-traceability-graph.output.v1.root-shape"}, commands: []string{"requirement-traceability-graph"},
		schema: func() (map[string]any, error) { return requirementgraph.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-context-slice.output.v2.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-context-slice.output.v2.root-shape"}, commands: []string{"requirement-context-slice"},
		schema: func() (map[string]any, error) { return requirementcontext.SliceOutputStructure(), nil },
	}, {
		id: "proofkit.requirement-semantic-diff.output.v3.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-semantic-diff.output.v3.root-shape"}, commands: []string{"requirement-semantic-diff"},
		schema: func() (map[string]any, error) { return requirementdiff.OutputStructure(), nil },
	}, {
		id: "proofkit.transaction-inspect-residue.output.v1.json-schema", direction: "output",
		commands: []string{"transaction-inspect-residue"},
		schema:   func() (map[string]any, error) { return transactionresidue.InspectionOutputStructure(), nil },
	}, {
		id: "proofkit.transaction-quarantine-residue.output.v1.json-schema", direction: "output",
		commands: []string{"transaction-quarantine-residue"},
		schema:   func() (map[string]any, error) { return transactionresidue.RelocationOutputStructure(), nil },
	}, {
		id: "proofkit.branch-authority.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.branch-authority.input.v1.root-shape"}, commands: []string{"branch-authority"},
		schema: func() (map[string]any, error) { return branchauthority.InputStructure(), nil },
	}, {
		id: "proofkit.branch-authority.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.branch-authority.output.v1.root-shape"}, commands: []string{"branch-authority"},
		schema: func() (map[string]any, error) { return branchauthority.OutputStructure(), nil },
	}, {
		id: "proofkit.receipt-currentness-scope.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.receipt-currentness-scope.input.v1.root-shape"}, commands: []string{"receipt-currentness-scope"},
		schema: func() (map[string]any, error) { return receiptcurrentnessscope.InputStructure(), nil },
	}, {
		id: "proofkit.receipt-currentness-scope.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.receipt-currentness-scope.output.v1.root-shape"}, commands: []string{"receipt-currentness-scope"},
		schema: func() (map[string]any, error) { return receiptcurrentnessscope.OutputStructure(), nil },
	}, {
		id: "proofkit.receipt-trust-class.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.receipt-trust-class.input.v1.root-shape"}, commands: []string{"receipt-trust-class"},
		schema: func() (map[string]any, error) { return receipttrustclass.InputStructure(), nil },
	}, {
		id: "proofkit.receipt-trust-class.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.receipt-trust-class.output.v1.root-shape"}, commands: []string{"receipt-trust-class"},
		schema: func() (map[string]any, error) { return receipttrustclass.OutputStructure(), nil },
	}, {
		id: compactV2DefinitionID, direction: "input", versionField: "schema_version",
		predecessors: []string{"proofkit.requirement-proof-resolver.input.v2.root-shape"},
		commands:     []string{"requirement-proof-resolver"},
		variants: []nativeStructureVariant{{id: "01-compact", when: "default JSON mode", schema: func() (map[string]any, error) {
			return compactproofcontract.InputStructure(), nil
		}}},
	}, {
		id: "proofkit.proof-receipt-admission.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.proof-receipt-admission.input.v1.root-shape"}, commands: []string{"proof-receipt-admission"},
		schema: func() (map[string]any, error) { return proofreceiptadmission.InputStructure(), nil },
	}, {
		id: "proofkit.proof-receipt-admission.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.proof-receipt-admission.output.v1.root-shape"}, commands: []string{"proof-receipt-admission"},
		schema: func() (map[string]any, error) { return proofreceiptadmission.OutputStructure(), nil },
	}, {
		id: "proofkit.receipt-producer-admission.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.receipt-producer-admission.input.v1.root-shape"}, commands: []string{"receipt-producer-admission"},
		schema: func() (map[string]any, error) { return receiptproduceradmission.InputStructure(), nil },
	}, {
		id: "proofkit.receipt-producer-admission.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.receipt-producer-admission.output.v1.root-shape"}, commands: []string{"receipt-producer-admission"},
		schema: func() (map[string]any, error) { return receiptproduceradmission.OutputStructure(), nil },
	}, {
		id: "proofkit.custom-rule-boundary.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.custom-rule-boundary.input.v1.root-shape"}, commands: []string{"custom-rule-boundary"},
		schema: func() (map[string]any, error) { return customruleboundary.InputStructure(), nil },
	}, {
		id: "proofkit.custom-rule-boundary.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.custom-rule-boundary.output.v1.root-shape"}, commands: []string{"custom-rule-boundary"},
		schema: func() (map[string]any, error) { return customruleboundary.OutputStructure(), nil },
	}, {
		id: "proofkit.document-lifecycle-boundary.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.document-lifecycle-boundary.input.v1.root-shape"}, commands: []string{"document-lifecycle-boundary"},
		schema: func() (map[string]any, error) { return documentlifecycle.InputStructure(), nil },
	}, {
		id: "proofkit.document-lifecycle-boundary.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.document-lifecycle-boundary.output.v1.root-shape"}, commands: []string{"document-lifecycle-boundary"},
		schema: func() (map[string]any, error) { return documentlifecycle.OutputStructure(), nil },
	}, {
		id: "proofkit.rendered-artifact-freshness.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.rendered-artifact-freshness.input.v1.root-shape"}, commands: []string{"rendered-artifact-freshness"},
		schema: func() (map[string]any, error) { return renderedartifactfreshness.InputStructure(), nil },
	}, {
		id: "proofkit.rendered-artifact-freshness.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.rendered-artifact-freshness.output.v1.root-shape"}, commands: []string{"rendered-artifact-freshness"},
		schema: func() (map[string]any, error) { return renderedartifactfreshness.OutputStructure(), nil },
	}, {
		id: "proofkit.adoption-checklist.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.adoption-checklist.input.v1.root-shape"}, commands: []string{"adoption-checklist"},
		schema: func() (map[string]any, error) { return adoptionchecklist.InputStructure(), nil },
	}, {
		id: "proofkit.adoption-checklist.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.adoption-checklist.output.v1.root-shape"}, commands: []string{"adoption-checklist"},
		schema: func() (map[string]any, error) { return adoptionchecklist.OutputStructure(), nil },
	}, {
		id: "proofkit.binding-partition.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.binding-partition.input.v1.root-shape"}, commands: []string{"binding-partition"},
		schema: func() (map[string]any, error) { return bindingpartition.InputStructure(), nil },
	}, {
		id: "proofkit.binding-partition.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.binding-partition.output.v1.root-shape"}, commands: []string{"binding-partition"},
		schema: func() (map[string]any, error) { return bindingpartition.OutputStructure(), nil },
	}, {
		id: "proofkit.completion-criteria.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.completion-criteria.input.v1.root-shape"}, commands: []string{"completion-criteria"},
		schema: func() (map[string]any, error) { return completioncriteria.InputStructure(), nil },
	}, {
		id: "proofkit.completion-criteria.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.completion-criteria.output.v1.root-shape"}, commands: []string{"completion-criteria"},
		schema: func() (map[string]any, error) { return completioncriteria.OutputStructure(), nil },
	}, {
		id: "proofkit.package-runtime-dependency-admission.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.package-runtime-dependency-admission.input.v1.root-shape"}, commands: []string{"package-runtime-dependency-admission"},
		schema: func() (map[string]any, error) { return packageruntimedependency.InputStructure(), nil },
	}, {
		id: "proofkit.package-runtime-dependency-admission.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.package-runtime-dependency-admission.output.v1.root-shape"}, commands: []string{"package-runtime-dependency-admission"},
		schema: func() (map[string]any, error) { return packageruntimedependency.OutputStructure(), nil },
	}, {
		id: "proofkit.proof-obligation-algebra.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.proof-obligation-algebra.input.v1.root-shape"}, commands: []string{"proof-obligation-algebra"},
		schema: func() (map[string]any, error) { return proofobligationalgebra.InputStructure(), nil },
	}, {
		id: "proofkit.proof-obligation-algebra.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.proof-obligation-algebra.output.v1.root-shape"}, commands: []string{"proof-obligation-algebra"},
		schema: func() (map[string]any, error) { return proofobligationalgebra.OutputStructure(), nil },
	}, {
		id: "proofkit.text-policy.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.text-policy.input.v1.root-shape"}, commands: []string{"text-policy"},
		schema: func() (map[string]any, error) { return textpolicy.InputStructure(), nil },
	}, {
		id: "proofkit.text-policy.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.text-policy.output.v1.root-shape"}, commands: []string{"text-policy"},
		schema: func() (map[string]any, error) { return textpolicy.OutputStructure(), nil },
	}, {
		id: "proofkit.workspace-manifest-facts.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.workspace-manifest-facts.input.v1.root-shape"}, commands: []string{"workspace-manifest-facts"},
		schema: func() (map[string]any, error) { return workspacemanifestfacts.InputStructure(), nil },
	}, {
		id: "proofkit.workspace-manifest-facts.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.workspace-manifest-facts.output.v1.root-shape"}, commands: []string{"workspace-manifest-facts"},
		schema: func() (map[string]any, error) { return workspacemanifestfacts.OutputStructure(), nil },
	}, {
		id: "proofkit.workspace-changed-package-plan.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.workspace-changed-package-plan.input.v1.root-shape"}, commands: []string{"workspace-changed-package-plan"},
		schema: func() (map[string]any, error) { return workspaceplanning.ChangedPlanInputStructure(), nil },
	}, {
		id: "proofkit.workspace-changed-package-plan.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.workspace-changed-package-plan.output.v1.root-shape"}, commands: []string{"workspace-changed-package-plan"},
		wireVersion: json.Number("1"),
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope", schema: agentEnvelopeRootStructure},
			{id: "02-plan", when: "without --agent-envelope", schema: func() (map[string]any, error) { return workspaceplanning.ChangedPlanOutputStructure(), nil }},
		},
	}, {
		id: "proofkit.workspace-shard-partition.input.v2.json-schema", direction: "input", semanticVersion: 2,
		predecessors: []string{"proofkit.workspace-shard-partition.input.v1.root-shape", "proofkit.workspace-shard-partition.input.v1.json-schema"}, commands: []string{"workspace-shard-partition"},
		schema: func() (map[string]any, error) { return workspaceplanning.ShardInputStructure(), nil },
	}, {
		id: "proofkit.workspace-shard-partition.output.v2.json-schema", direction: "output", semanticVersion: 2,
		predecessors: []string{"proofkit.workspace-shard-partition.output.v1.root-shape", "proofkit.workspace-shard-partition.output.v1.json-schema"}, commands: []string{"workspace-shard-partition"},
		wireVersion: json.Number("1"),
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope", schema: agentEnvelopeRootStructure},
			{id: "02-partition", when: "without --agent-envelope", schema: func() (map[string]any, error) { return workspaceplanning.ShardOutputStructure(), nil }},
		},
	}, {
		id: "proofkit.typescript-public-api-surfaces.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.typescript-public-api-surfaces.input.v1.root-shape"}, commands: []string{"typescript-public-api-surfaces"},
		schema: func() (map[string]any, error) { return publicapi.InputStructure(), nil },
	}, {
		id: "proofkit.typescript-public-api-surfaces.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.typescript-public-api-surfaces.output.v1.root-shape"}, commands: []string{"typescript-public-api-surfaces"},
		outOfBandVersion: json.Number("1"),
		schema:           func() (map[string]any, error) { return publicapi.OutputStructure(), nil },
	}, {
		id: "proofkit.selective-gate-plan.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.selective-gate-plan.input.v1.root-shape"}, commands: []string{"selective-gate-plan"},
		schema: func() (map[string]any, error) { return selectivegateplan.InputStructure(), nil },
	}, {
		id: "proofkit.selective-gate-plan.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.selective-gate-plan.output.v1.root-shape"}, commands: []string{"selective-gate-plan"},
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope with admitted input", schema: func() (map[string]any, error) { return selectivegateplan.EnvelopeStructure(), nil }},
			{id: "02-invalid-input-envelope", when: "--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr", schema: func() (map[string]any, error) { return agentenvelope.InvalidInputStructure(), nil }},
			{id: "03-plan", when: "without --agent-envelope", schema: func() (map[string]any, error) { return selectivegateplan.OutputStructure(), nil }},
		},
	}, {
		id: "proofkit.selective-gate-evidence.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.selective-gate-evidence.input.v1.root-shape"}, commands: []string{"selective-gate-evidence"},
		schema: func() (map[string]any, error) { return selectivegateevidence.InputStructure(), nil },
	}, {
		id: "proofkit.selective-gate-evidence.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.selective-gate-evidence.output.v1.root-shape"}, commands: []string{"selective-gate-evidence"},
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope with admitted input", schema: func() (map[string]any, error) { return selectivegateevidence.EnvelopeStructure(), nil }},
			{id: "02-invalid-input-envelope", when: "--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr", schema: func() (map[string]any, error) { return agentenvelope.InvalidInputStructure(), nil }},
			{id: "03-report", when: "without --agent-envelope", schema: func() (map[string]any, error) { return selectivegateevidence.OutputStructure(), nil }},
		},
	}, {
		id: "proofkit.selective-gate-obligation-decision-input.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.selective-gate-obligation-decision-input.input.v1.root-shape"}, commands: []string{"selective-gate-obligation-decision-input"},
		schema: func() (map[string]any, error) { return selectivegateevidence.ProjectionInputStructure(), nil },
	}, {
		id: "proofkit.selective-gate-obligation-decision-input.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.selective-gate-obligation-decision-input.output.v1.root-shape"}, commands: []string{"selective-gate-obligation-decision-input"},
		schema: func() (map[string]any, error) { return obligationdecision.InputStructure(), nil },
	}, {
		id: "proofkit.obligation-decision.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.obligation-decision.input.v1.root-shape"}, commands: []string{"obligation-decision"},
		schema: func() (map[string]any, error) { return obligationdecision.InputStructure(), nil },
	}, {
		id: "proofkit.obligation-decision.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.obligation-decision.output.v1.root-shape"}, commands: []string{"obligation-decision"},
		variants: []nativeStructureVariant{
			{id: "01-agent-envelope", when: "--agent-envelope with admitted input", schema: func() (map[string]any, error) { return obligationdecision.EnvelopeStructure(), nil }},
			{id: "02-invalid-input-envelope", when: "--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr", schema: func() (map[string]any, error) { return agentenvelope.InvalidInputStructure(), nil }},
			{id: "03-report", when: "without --agent-envelope", schema: func() (map[string]any, error) { return obligationdecision.OutputStructure(), nil }},
		},
	}, {
		id: "proofkit.impact.input.v2.json-schema", direction: "input", wireVersion: json.Number("2"),
		predecessors: []string{"proofkit.impact.input.v2.root-shape"}, commands: []string{"impact"},
		schema: func() (map[string]any, error) { return impact.InputStructure(), nil },
	}, {
		id: "proofkit.impact.output.v2.json-schema", direction: "output", wireVersion: json.Number("2"),
		predecessors: []string{"proofkit.impact.output.v2.root-shape"}, commands: []string{"impact"},
		schema: func() (map[string]any, error) { return impact.OutputStructure(), nil },
	}, {
		id: "proofkit.requirement-impact-input-compose.input.v3.json-schema", direction: "input", wireVersion: json.Number("3"),
		predecessors: []string{"proofkit.requirement-impact-input-compose.input.v3.root-shape"}, commands: []string{"requirement-impact-input-compose"},
		schema: requirementimpactinput.InputStructure,
	}, {
		id: "proofkit.requirement-impact-input-compose.output.v2.json-schema", direction: "output", wireVersion: json.Number("2"),
		predecessors: []string{"proofkit.requirement-impact-input-compose.output.v2.root-shape"}, commands: []string{"requirement-impact-input-compose"},
		schema: func() (map[string]any, error) { return requirementimpactinput.OutputStructure(), nil },
	}, {
		id: "proofkit.test-evidence-inventory.input.v3.json-schema", direction: "input", aggregateVersion: "3",
		predecessors: []string{"proofkit.test-evidence-inventory.input.v3.root-shape"}, commands: []string{"test-evidence-inventory"},
		variants: []nativeStructureVariant{
			{id: "01-direct-inventory", when: "without --projection; direct inventory", schema: func() (map[string]any, error) { return testevidenceinventory.DirectInputShape().JSONSchema(), nil }},
			{id: "02-discovery-draft", when: "--projection discovery-draft", schema: func() (map[string]any, error) { return testevidenceinventory.DiscoveryInputShape().JSONSchema(), nil }},
			{id: "03-proof-binding-derived", when: "--projection proof-binding-derived", schema: proofbindingtestinventory.InputStructure},
			{id: "04-source-set", when: "without --projection; source-set inventory", schema: func() (map[string]any, error) { return testevidenceinventory.SourceSetInputShape().JSONSchema(), nil }},
			{id: "05-wrapped-inventory", when: "without --projection; wrapped inventory", schema: func() (map[string]any, error) { return testevidenceinventory.WrappedInputShape().JSONSchema(), nil }},
		},
	}, {
		id: "proofkit.test-evidence-inventory.output.v2.json-schema", direction: "output", aggregateVersion: "2",
		predecessors: []string{"proofkit.test-evidence-inventory.output.v2.root-shape"}, commands: []string{"test-evidence-inventory"},
		variants: []nativeStructureVariant{
			{id: "01-normalized-direct", when: "--normalized-inventory without --projection; passed inventory", schema: func() (map[string]any, error) { return testevidenceinventory.NormalizedOutputStructure(), nil }},
			{id: "02-normalized-proof-binding", when: "--normalized-inventory --projection proof-binding-derived; passed inventory", schema: func() (map[string]any, error) {
				return testevidenceinventory.ProofBindingNormalizedOutputStructure(), nil
			}},
			{id: "03-report", when: "without --normalized-inventory except --projection discovery-draft; or --normalized-inventory failure report", schema: func() (map[string]any, error) { return testevidenceinventory.ReportOutputShape().JSONSchema(), nil }},
			{id: "04-discovery-report", when: "--projection discovery-draft without --normalized-inventory", schema: func() (map[string]any, error) { return testevidenceinventory.DiscoveryOutputShape().JSONSchema(), nil }},
		},
	}, {
		id: "proofkit.requirement-coverage-input-compose.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-coverage-input-compose.input.v3.root-shape"}, commands: []string{"requirement-coverage-input-compose"},
		schema: requirementcoverageinput.InputStructure,
	}, {
		id: "proofkit.requirement-coverage-input-compose.output.v3.json-schema", direction: "output",
		predecessors: []string{"proofkit.requirement-coverage-input-compose.output.v3.root-shape"}, commands: []string{"requirement-coverage-input-compose"},
		schema: requirementcoverageinput.OutputStructure,
	}, {
		id: "proofkit.requirement-coverage-view.input.v3.json-schema", direction: "input",
		predecessors: []string{"proofkit.requirement-coverage-view.input.v3.root-shape"}, commands: []string{"requirement-coverage-view"},
		schema: requirementcoverageview.InputStructure,
	}, {
		id: "proofkit.changed-path-set.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.changed-path-set.input.v1.root-shape"}, commands: []string{"changed-path-set"},
		schema: func() (map[string]any, error) { return changedpathset.InputStructure(), nil },
	}, {
		id: "proofkit.changed-path-set.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.changed-path-set.output.v1.root-shape"}, commands: []string{"changed-path-set"},
		variants: []nativeStructureVariant{
			{id: "01-report", when: "without --agent-envelope", schema: func() (map[string]any, error) { return changedpathset.OutputStructure(), nil }},
			{id: "02-agent-envelope", when: "--agent-envelope with admitted input", schema: func() (map[string]any, error) { return changedpathset.EnvelopeStructure(), nil }},
			{id: "03-invalid-input-envelope", when: "--agent-envelope after command admission rejects decoded input; JSON framing and argument errors use stderr", schema: func() (map[string]any, error) { return agentenvelope.InvalidInputStructure(), nil }},
		},
	}, {
		id: "proofkit.secret-scan.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.secret-scan.input.v1.root-shape"}, commands: []string{"secret-scan"},
		schema: func() (map[string]any, error) { return secretscan.InputStructure(), nil },
	}, {
		id: "proofkit.secret-scan.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.secret-scan.output.v1.root-shape"}, commands: []string{"secret-scan"},
		schema: func() (map[string]any, error) { return secretscan.OutputStructure(), nil },
	}, {
		id: "proofkit.self-check.input.v1.json-schema", direction: "input",
		predecessors: []string{"proofkit.self-check.input.v1.root-shape"}, commands: []string{"self-check"},
		jsonValueInput: true, outOfBandVersion: json.Number("1"),
		schema: func() (map[string]any, error) { return selfcheck.InputStructure(), nil },
	}, {
		id: "proofkit.self-check.output.v1.json-schema", direction: "output",
		predecessors: []string{"proofkit.self-check.output.v1.root-shape"}, commands: []string{"self-check"},
		schema: func() (map[string]any, error) { return selfcheck.OutputStructure(), nil },
	}}
}

func (owner nativeStructure) schemaVersionField() string {
	if owner.versionField != "" {
		return owner.versionField
	}
	return "schemaVersion"
}

func (owner nativeStructure) definition() (map[string]any, error) {
	if owner.direction != "input" && owner.direction != "output" {
		return nil, fmt.Errorf("native structure has an invalid direction")
	}
	rootKind := "object"
	if owner.jsonValueInput {
		rootKind = "json_value"
	}
	variants := owner.variants
	if len(variants) == 0 {
		variants = []nativeStructureVariant{{id: "01-root", when: "default JSON mode", schema: owner.schema}}
	}
	wireVariants := make([]any, 0, len(variants))
	for _, variant := range variants {
		if variant.id == "" || variant.when == "" || variant.schema == nil {
			return nil, fmt.Errorf("native structure %s has an invalid variant", owner.id)
		}
		schema, err := variant.schema()
		if err != nil {
			return nil, fmt.Errorf("native structure %s: %w", owner.id, err)
		}
		root, err := owner.root(schema)
		if err != nil {
			return nil, err
		}
		properties := root["properties"].(map[string]any)
		allowed := []any{}
		for _, key := range sortedKeys(properties) {
			allowed = append(allowed, key)
		}
		wireVariants = append(wireVariants, map[string]any{
			"variantId": variant.id, "when": []any{variant.when}, "rootKind": rootKind,
			"allowedFields": allowed, "requiredFields": root["required"], "schema": schema,
		})
	}
	record := map[string]any{
		"definitionId": owner.id, "schemaVersion": json.Number("1"),
		"rootType": rootKind, "closed": true, "definitionRefs": []any{},
		"fieldTree": map[string]any{
			"kind": "structural_json_schema",
			"nonClaims": []any{
				"Structural JSON Schema does not replace native canonicalization, semantic admission, or numeric representation checks.",
				"Structural JSON Schema does not replace direct public-CLI runtime witnesses for variant selection.",
			},
			"variants": wireVariants,
		},
	}
	encoded, err := canonicalJSON(record)
	if err != nil {
		return nil, err
	}
	record["canonicalDigest"] = sha256Digest(encoded)
	return record, nil
}

func (owner nativeStructure) contractID(command string, wireVersion json.Number) string {
	version := wireVersion.String()
	if owner.semanticVersion != 0 {
		version = fmt.Sprint(owner.semanticVersion)
	}
	return "proofkit." + command + "." + owner.direction + ".v" + version
}

func (owner nativeStructure) contractVersion(definition map[string]any) (json.Number, error) {
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	if owner.jsonValueInput {
		if len(variants) != 1 {
			return "", fmt.Errorf("arbitrary JSON input requires one variant")
		}
		_, err := owner.root(variants[0].(map[string]any)["schema"].(map[string]any))
		return owner.outOfBandVersion, err
	}
	if owner.aggregateVersion != "" {
		for _, raw := range variants {
			if _, err := owner.root(raw.(map[string]any)["schema"].(map[string]any)); err != nil {
				return "", err
			}
		}
		return owner.aggregateVersion, nil
	}
	if owner.optionalInputVersion {
		var version json.Number
		for _, raw := range variants {
			root, err := owner.root(raw.(map[string]any)["schema"].(map[string]any))
			if err != nil {
				return "", err
			}
			value, err := nativeObjectVersion(root, owner.schemaVersionField(), true)
			if err != nil || (version != "" && version != value) {
				return "", fmt.Errorf("optional input versions must agree across variants")
			}
			version = value
		}
		return version, nil
	}
	if owner.outOfBandVersion != "" {
		for _, raw := range variants {
			if _, err := owner.root(raw.(map[string]any)["schema"].(map[string]any)); err != nil {
				return "", err
			}
		}
		return owner.outOfBandVersion, nil
	}
	if owner.wireVersion != "" {
		for _, raw := range variants {
			version, err := nativeSchemaVersion(raw.(map[string]any)["schema"].(map[string]any), owner.schemaVersionField())
			if err != nil {
				return "", err
			}
			if version == owner.wireVersion {
				return version, nil
			}
		}
		return "", fmt.Errorf("native structure %s has no variant with wire version %s", owner.id, owner.wireVersion)
	}
	return nativeSchemaVersion(variants[0].(map[string]any)["schema"].(map[string]any), owner.schemaVersionField())
}

// The generic envelope owner fixes root keys and types; its nested records
// retain their separately admitted semantics.
func agentEnvelopeRootStructure() (map[string]any, error) {
	output := agentenvelope.Build(agentenvelope.Input{})
	properties := map[string]any{}
	required := []any{}
	for _, key := range sortedKeys(output) {
		var field map[string]any
		switch value := output[key].(type) {
		case string:
			field = map[string]any{"type": "string"}
		case []any:
			field = map[string]any{"type": "array"}
		case map[string]any:
			field = map[string]any{"type": "object"}
		case int:
			if key != "schemaVersion" || value != 1 {
				return nil, fmt.Errorf("agent envelope has an unexpected integer root field")
			}
			field = map[string]any{"type": "integer", "const": json.Number("1")}
		default:
			return nil, fmt.Errorf("agent envelope has an unsupported root field")
		}
		properties[key] = field
		required = append(required, key)
	}
	return map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type":    "object", "additionalProperties": false,
		"properties": properties, "required": required,
	}, nil
}

func (owner nativeStructure) summary(version json.Number) []any {
	identity := owner.schemaVersionField() + "=" + version.String()
	if owner.outOfBandVersion != "" {
		identity = "contractSchemaVersion=" + version.String() + " (out-of-band; no serialized schemaVersion field)"
	}
	if owner.jsonValueInput {
		identity = "contractSchemaVersion=" + version.String() + " (out-of-band; arbitrary input members are not version headers)"
	}
	if owner.aggregateVersion != "" {
		identity = "contractSchemaVersion=" + version.String() + " (aggregate; wire headers are defined per variant)"
	}
	return []any{identity, "structural JSON Schema definition " + owner.id + "; canonicalization and semantic validity remain native admission obligations"}
}

// Human field navigation is derived separately from the machine contract digest.
func nativeInputRootSummary(id string, definition map[string]any) ([]string, error) {
	owner, ok := nativeStructureOwner(id)
	if !ok {
		return nil, nil
	}
	return owner.inputRootSummary(definition)
}

func (owner nativeStructure) inputRootSummary(definition map[string]any) ([]string, error) {
	if owner.jsonValueInput {
		if _, err := owner.contractVersion(definition); err != nil {
			return nil, err
		}
		return []string{"any JSON value; no required fields or inline version header"}, nil
	}
	variants := definition["fieldTree"].(map[string]any)["variants"].([]any)
	result := make([]string, 0, len(variants))
	for _, raw := range variants {
		variant := raw.(map[string]any)
		schema := variant["schema"].(map[string]any)
		root, err := owner.root(schema)
		if err != nil {
			return nil, err
		}
		properties := root["properties"].(map[string]any)
		fields := make([]string, 0, len(properties))
		for _, name := range sortedKeys(properties) {
			if name == owner.schemaVersionField() && owner.aggregateVersion == "" {
				continue
			}
			field, _ := properties[name].(map[string]any)
			if value, literal := field["const"]; literal && owner.aggregateVersion != "" {
				encoded, err := canonicalJSON(value)
				if err != nil {
					return nil, err
				}
				fields = append(fields, name+"="+string(encoded))
				continue
			}
			if schema["type"] == "object" {
				switch field["type"] {
				case "array":
					name += "[]"
				case "object":
					name += "{}"
				}
			}
			fields = append(fields, name)
		}
		label := "root fields"
		if len(variants) > 1 {
			label += " (" + variant["variantId"].(string) + ")"
		}
		result = append(result, label+": "+strings.Join(fields, ", "))
	}
	return result, nil
}

func nativeSchemaVersion(schema map[string]any, versionField string) (json.Number, error) {
	root, err := nativeStructureRoot(schema, versionField)
	if err != nil {
		return "", err
	}
	return nativeObjectSchemaVersion(root, versionField)
}

func (owner nativeStructure) root(schema map[string]any) (map[string]any, error) {
	if owner.jsonValueInput {
		if owner.direction != "input" || owner.schema == nil || len(owner.variants) != 0 ||
			owner.versionField != "" || owner.wireVersion != "" || owner.aggregateVersion != "" ||
			owner.optionalInputVersion || owner.semanticVersion != 0 {
			return nil, fmt.Errorf("arbitrary JSON input requires one input schema and only an out-of-band version")
		}
		if err := validateNativeVersion(owner.outOfBandVersion); err != nil {
			return nil, err
		}
		description, ok := schema["description"].(string)
		if len(schema) != 2 || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || !ok || strings.TrimSpace(description) == "" {
			return nil, fmt.Errorf("arbitrary JSON input permits only dialect and description annotations")
		}
		// This is a field-navigation summary, not an object constraint on input.
		return map[string]any{"properties": map[string]any{}, "required": []any{}}, nil
	}
	if owner.aggregateVersion != "" {
		if len(owner.variants) < 2 || owner.schema != nil || owner.versionField != "" || owner.wireVersion != "" ||
			owner.outOfBandVersion != "" || owner.optionalInputVersion || owner.semanticVersion != 0 {
			return nil, fmt.Errorf("aggregate contract version requires multiple variants without other version modes")
		}
		if err := validateNativeVersion(owner.aggregateVersion); err != nil {
			return nil, err
		}
		return schema, validateNativeClosedObject(schema)
	}
	if owner.optionalInputVersion {
		if owner.direction != "input" || owner.outOfBandVersion != "" || owner.wireVersion != "" {
			return nil, fmt.Errorf("optional inline version requires an input owner without version overrides")
		}
		_, err := nativeObjectVersion(schema, owner.schemaVersionField(), true)
		return schema, err
	}
	if owner.outOfBandVersion == "" {
		return nativeStructureRoot(schema, owner.schemaVersionField())
	}
	if owner.versionField != "" || owner.wireVersion != "" || len(owner.variants) != 0 {
		return nil, fmt.Errorf("out-of-band contract version cannot select inline versions or variants")
	}
	if err := validateNativeVersion(owner.outOfBandVersion); err != nil {
		return nil, err
	}
	if err := validateNativeClosedObject(schema); err != nil {
		return nil, err
	}
	if _, exists := schema["properties"].(map[string]any)["schemaVersion"]; exists {
		return nil, fmt.Errorf("out-of-band contract version cannot coexist with a schemaVersion field")
	}
	return schema, nil
}

// A structural sum retains its full schema. Only its common root summary is
// projected; branches with different roots or wire versions need separate owners.
func nativeStructureRoot(schema map[string]any, versionField string) (map[string]any, error) {
	if schema["type"] == "object" {
		if _, err := nativeObjectSchemaVersion(schema, versionField); err != nil {
			return nil, err
		}
		return schema, nil
	}
	for key := range schema {
		if key != "$schema" && key != "oneOf" {
			return nil, fmt.Errorf("native structure requires a closed object projection or object alternatives")
		}
	}
	alternatives, ok := schema["oneOf"].([]any)
	if !ok || len(alternatives) < 2 {
		return nil, fmt.Errorf("native structure requires at least two closed object alternatives")
	}
	var root map[string]any
	var version json.Number
	for _, raw := range alternatives {
		branch, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("native structure alternative must be an object schema")
		}
		nextVersion, err := nativeObjectSchemaVersion(branch, versionField)
		if err != nil {
			return nil, err
		}
		if root == nil {
			root, version = branch, nextVersion
			continue
		}
		if nextVersion != version || !reflect.DeepEqual(root["required"], branch["required"]) ||
			!slices.Equal(sortedKeys(root["properties"].(map[string]any)), sortedKeys(branch["properties"].(map[string]any))) {
			return nil, fmt.Errorf("native structure alternatives must share root fields and schemaVersion")
		}
	}
	return root, nil
}

func nativeObjectSchemaVersion(schema map[string]any, versionField string) (json.Number, error) {
	return nativeObjectVersion(schema, versionField, false)
}

func nativeObjectVersion(schema map[string]any, versionField string, optional bool) (json.Number, error) {
	if err := validateNativeClosedObject(schema); err != nil {
		return "", err
	}
	properties, _ := schema["properties"].(map[string]any)
	field, _ := properties[versionField].(map[string]any)
	version, ok := field["const"].(json.Number)
	required, _ := schema["required"].([]any)
	if !ok || field["type"] != "integer" || (!optional && !slices.Contains(required, any(versionField))) {
		return "", fmt.Errorf("native structure requires a required literal integer %s", versionField)
	}
	if err := validateNativeVersion(version); err != nil {
		return "", err
	}
	return version, nil
}

func validateNativeClosedObject(schema map[string]any) error {
	if _, ok := schema["properties"].(map[string]any); !ok || schema["type"] != "object" || schema["additionalProperties"] != false {
		return fmt.Errorf("native structure requires a closed object projection")
	}
	return nil
}

func validateNativeVersion(version json.Number) error {
	number, err := version.Int64()
	if err != nil || number < 1 || version.String() != fmt.Sprint(number) {
		return fmt.Errorf("native structure schemaVersion must be a positive canonical integer")
	}
	return nil
}

func admitNativeStructureDefinition(id string, record map[string]any) error {
	owner, ok := nativeStructureOwner(id)
	if !ok {
		return fmt.Errorf("contract definition %s has no registered native structural owner", id)
	}
	expected, err := owner.definition()
	if err != nil {
		return err
	}
	actualBytes, err := canonicalJSON(record)
	if err != nil {
		return err
	}
	expectedBytes, err := canonicalJSON(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualBytes, expectedBytes) {
		return fmt.Errorf("contract definition %s differs from its native structural owner; use --refresh-structures", id)
	}
	return nil
}

func nativeStructureOwner(id string) (nativeStructure, bool) {
	for _, owner := range nativeStructures() {
		if owner.id == id {
			return owner, true
		}
	}
	return nativeStructure{}, false
}

func admitNativeStructureConsumers(contract map[string]any, definitions map[string]definitionRecord) error {
	commands, ok := contract["commands"].([]any)
	if !ok {
		return fmt.Errorf("CLI contract commands must be an array")
	}
	for _, owner := range nativeStructures() {
		seen := map[string]bool{}
		for _, raw := range commands {
			command, ok := raw.(map[string]any)
			if !ok {
				return fmt.Errorf("CLI contract command must be an object")
			}
			name, _ := command["command"].(string)
			for _, direction := range []string{"input", "output"} {
				binding, _ := command[direction+"Contract"].(map[string]any)
				isConsumer := direction == owner.direction && slices.Contains(owner.commands, name)
				usesOwner := binding["rootDefinitionRef"] == owner.id
				if isConsumer != usesOwner {
					return fmt.Errorf("%s %s contract violates native structure consumer ownership", name, direction)
				}
				if isConsumer {
					if owner.semanticVersion != 0 || owner.aggregateVersion != "" {
						definition, exists := definitions[owner.id]
						if !exists {
							return fmt.Errorf("%s %s contract lacks its native structural owner", name, direction)
						}
						wireVersion, err := owner.contractVersion(definition.Content)
						if err != nil {
							return err
						}
						if binding["schemaVersion"] != wireVersion || binding["contractId"] != owner.contractID(name, wireVersion) {
							return fmt.Errorf("%s %s contract violates native semantic contract identity", name, direction)
						}
					}
					if owner.outOfBandVersion != "" {
						expectedID := "proofkit." + name + "." + direction + ".v" + string(owner.outOfBandVersion)
						if binding["schemaVersion"] != owner.outOfBandVersion || binding["contractId"] != expectedID {
							return fmt.Errorf("%s %s contract violates native out-of-band contract identity", name, direction)
						}
					}
					seen[name] = true
				}
			}
		}
		_, defined := definitions[owner.id]
		if defined != (len(seen) > 0) || (len(seen) != 0 && len(seen) != len(owner.commands)) {
			return fmt.Errorf("native structure %s must have its complete consumer set", owner.id)
		}
		for _, predecessor := range owner.predecessors {
			if _, old := definitions[predecessor]; old {
				return fmt.Errorf("obsolete native structure %s remains", predecessor)
			}
		}
	}
	return nil
}
