package stackpreset

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var presetIDs = []string{
	"agentic_runtime_repo",
	"generated_docs_contract_repo",
	"python_service",
	"python_typescript_service",
	"typescript_monorepo",
	"typescript_workspace",
}

var presetNonClaims = []string{
	"Stack presets do not read repository state.",
	"Stack presets do not execute native witnesses.",
	"Stack presets do not own consuming repository policy.",
	"Stack presets do not prove requirement coverage or rollout readiness.",
}

type preset struct {
	ExpectedFiles             []string
	PrimaryLanguages          []string
	Purpose                   string
	StarterEnvironmentClasses []string
	StarterProofLikePaths     []string
	StarterWitnessKinds       []string
	SuggestedCommands         []string
}

type Profile struct {
	ExpectedFiles             []string
	PrimaryLanguages          []string
	Purpose                   string
	StarterEnvironmentClasses []string
	StarterProofLikePaths     []string
	StarterWitnessKinds       []string
	SuggestedCommands         []string
}

var presets = map[string]preset{
	"agentic_runtime_repo": {
		Purpose:                   "Starter profile for repositories that run agent harnesses, queues, or credentialed adapters.",
		PrimaryLanguages:          []string{"typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/specs/product-capability-spec.md"},
		StarterEnvironmentClasses: []string{"local-typecheck", "local-unit", "credentialed-live"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "packages/**/test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "falsification", "local-unit", "live-preflight"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "agentic_runtime_repo"), cliexec.DisplayCommand("requirement-bindings", "--input", "docs/contracts/requirement-proof-bindings.v1.json"), cliexec.DisplayCommand("proof-slice", "--input", "docs/contracts/requirement-proof-bindings.v1.json")},
	},
	"generated_docs_contract_repo": {
		Purpose:                   "Starter profile for repositories with generated lookup docs and machine-readable proof contracts.",
		PrimaryLanguages:          []string{"markdown", "typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/REQUIREMENT_EVIDENCE_GRAPH.md"},
		StarterEnvironmentClasses: []string{"local-docs", "local-generated-artifacts"},
		StarterProofLikePaths:     []string{"docs/**/*.md", "docs/contracts/**/*"},
		StarterWitnessKinds:       []string{"docs-surface", "generated-artifact", "schema"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "generated_docs_contract_repo"), cliexec.DisplayCommand("evidence-graph", "--input", "docs/contracts/requirement-proof-bindings.v1.json")},
	},
	"python_service": {
		Purpose:                   "Starter profile for Python services adopting proofkit through CLI reports.",
		PrimaryLanguages:          []string{"python"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/specs/product-capability-spec.md"},
		StarterEnvironmentClasses: []string{"local-pytest", "local-ruff"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "tests/**/*.py"},
		StarterWitnessKinds:       []string{"contract", "falsification", "pytest"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "python_service"), cliexec.DisplayCommand("witness-scheduler-plan", "--input", "proofkit/witness-plan.json")},
	},
	"python_typescript_service": {
		Purpose:                   "Starter profile for services with Python runtime code and TypeScript tooling or UI packages.",
		PrimaryLanguages:          []string{"python", "typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/specs/product-capability-spec.md", "package.json", "pyproject.toml"},
		StarterEnvironmentClasses: []string{"local-bun", "local-pytest", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "tests/**/*.py", "packages/**/test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "falsification", "pytest", "typescript-unit"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "python_typescript_service"), cliexec.DisplayCommand("selective-gate-plan", "--input", "proofkit/selective-gate-plan.json")},
	},
	"typescript_monorepo": {
		Purpose:                   "Starter profile for TypeScript monorepos with package graph and public API boundaries.",
		PrimaryLanguages:          []string{"typescript"},
		ExpectedFiles:             []string{"docs/contracts/typescript-public-api-surfaces.v1.json", "docs/contracts/repo-profile.v1.json", "package.json"},
		StarterEnvironmentClasses: []string{"local-bun", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "packages/**/test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "package-test", "public-api", "typecheck"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "typescript_monorepo"), cliexec.DisplayCommand("selective-gate-plan", "--input", "proofkit/selective-gate-plan.json")},
	},
	"typescript_workspace": {
		Purpose:                   "Starter profile for a TypeScript workspace adopting proofkit one module at a time.",
		PrimaryLanguages:          []string{"typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "package.json"},
		StarterEnvironmentClasses: []string{"local-bun", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "src/**/*.test.ts", "test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "falsification", "unit", "typecheck"},
		SuggestedCommands:         []string{cliexec.DisplayCommand("stack-preset", "--preset", "typescript_workspace"), cliexec.DisplayCommand("gradual-adoption-bootstrap", "--input", "proofkit/bootstrap.json")},
	},
}

func Build(presetID string) (report.Record, error) {
	preset, ok := ProfileFor(presetID)
	if !ok {
		return report.Record{}, fmt.Errorf("--preset requires a known stack preset id")
	}
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    "proofkit.stack-preset",
		ReportID:      "proofkit.stack-preset." + presetID,
		State:         "passed",
		Summary: map[string]any{
			"expectedFileCount":            len(preset.ExpectedFiles),
			"presetId":                     presetID,
			"primaryLanguages":             stringsToAny(preset.PrimaryLanguages),
			"starterEnvironmentClassCount": len(preset.StarterEnvironmentClasses),
			"starterWitnessKindCount":      len(preset.StarterWitnessKinds),
		},
		Diagnostics: []report.Diagnostic{
			{
				Key: "preset",
				Value: map[string]any{
					"expectedFiles":         stringsToAny(preset.ExpectedFiles),
					"purpose":               preset.Purpose,
					"starterProofLikePaths": stringsToAny(preset.StarterProofLikePaths),
					"suggestedCommands":     stringsToAny(preset.SuggestedCommands),
				},
			},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:      "proofkit.stack-preset.accepted",
				Status:      "passed",
				Message:     "stack preset is deterministic and non-authoritative",
				Diagnostics: []report.Diagnostic{},
			},
		},
		NonClaims: admit.StringSliceToAny(presetNonClaims),
	}, nil
}

func IsPresetID(value string) bool {
	for _, presetID := range presetIDs {
		if value == presetID {
			return true
		}
	}
	return false
}

func ProfileFor(presetID string) (Profile, bool) {
	preset, ok := presets[presetID]
	if !ok {
		return Profile{}, false
	}
	return Profile{
		ExpectedFiles:             append([]string{}, preset.ExpectedFiles...),
		PrimaryLanguages:          append([]string{}, preset.PrimaryLanguages...),
		Purpose:                   preset.Purpose,
		StarterEnvironmentClasses: append([]string{}, preset.StarterEnvironmentClasses...),
		StarterProofLikePaths:     append([]string{}, preset.StarterProofLikePaths...),
		StarterWitnessKinds:       append([]string{}, preset.StarterWitnessKinds...),
		SuggestedCommands:         append([]string{}, preset.SuggestedCommands...),
	}, true
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
