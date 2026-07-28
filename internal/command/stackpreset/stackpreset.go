package stackpreset

import (
	"fmt"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

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
	SuggestedCommandArgs      [][]string
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
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "agentic_runtime_repo"}, {"requirement-bindings", "--input", "docs/contracts/requirement-proof-bindings.v1.json"}, {"proof-slice", "--input", "docs/contracts/requirement-proof-bindings.v1.json"}},
	},
	"generated_docs_contract_repo": {
		Purpose:                   "Starter profile for repositories with generated lookup docs and machine-readable proof contracts.",
		PrimaryLanguages:          []string{"markdown", "typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/REQUIREMENT_EVIDENCE_GRAPH.md"},
		StarterEnvironmentClasses: []string{"local-docs", "local-generated-artifacts"},
		StarterProofLikePaths:     []string{"docs/**/*.md", "docs/contracts/**/*"},
		StarterWitnessKinds:       []string{"docs-surface", "generated-artifact", "schema"},
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "generated_docs_contract_repo"}, {"evidence-graph", "--input", "docs/contracts/requirement-proof-bindings.v1.json"}},
	},
	"python_service": {
		Purpose:                   "Starter profile for Python services adopting proofkit through CLI reports.",
		PrimaryLanguages:          []string{"python"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/specs/product-capability-spec.md"},
		StarterEnvironmentClasses: []string{"local-pytest", "local-ruff"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "tests/**/*.py"},
		StarterWitnessKinds:       []string{"contract", "falsification", "pytest"},
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "python_service"}, {"witness-scheduler-plan", "--input", "proofkit/witness-plan.json"}},
	},
	"python_typescript_service": {
		Purpose:                   "Starter profile for services with Python runtime code and TypeScript tooling or UI packages.",
		PrimaryLanguages:          []string{"python", "typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "docs/specs/product-capability-spec.md", "package.json", "pyproject.toml"},
		StarterEnvironmentClasses: []string{"local-bun", "local-pytest", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "tests/**/*.py", "packages/**/test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "falsification", "pytest", "typescript-unit"},
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "python_typescript_service"}, {"selective-gate-plan", "--input", "proofkit/selective-gate-plan.json"}},
	},
	"typescript_monorepo": {
		Purpose:                   "Starter profile for TypeScript monorepos with package graph and public API boundaries.",
		PrimaryLanguages:          []string{"typescript"},
		ExpectedFiles:             []string{"docs/contracts/typescript-public-api-surfaces.v1.json", "docs/contracts/repo-profile.v1.json", "package.json"},
		StarterEnvironmentClasses: []string{"local-bun", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "packages/**/test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "package-test", "public-api", "typecheck"},
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "typescript_monorepo"}, {"selective-gate-plan", "--input", "proofkit/selective-gate-plan.json"}},
	},
	"typescript_workspace": {
		Purpose:                   "Starter profile for a TypeScript workspace adopting proofkit one module at a time.",
		PrimaryLanguages:          []string{"typescript"},
		ExpectedFiles:             []string{"docs/contracts/repo-profile.v1.json", "docs/contracts/requirement-proof-bindings.v1.json", "package.json"},
		StarterEnvironmentClasses: []string{"local-bun", "local-typecheck"},
		StarterProofLikePaths:     []string{"docs/specs/**/*.md", "src/**/*.test.ts", "test/**/*.test.ts"},
		StarterWitnessKinds:       []string{"contract", "falsification", "unit", "typecheck"},
		SuggestedCommandArgs:      [][]string{{"stack-preset", "--preset", "typescript_workspace"}, {"gradual-adoption-bootstrap", "--input", "proofkit/bootstrap.json"}},
	},
}

func Build(presetID string) (report.Record, error) {
	return BuildWithRenderer(presetID, cliexec.PathRenderer())
}

func BuildWithRenderer(presetID string, renderer cliexec.Renderer) (report.Record, error) {
	preset, ok := ProfileForWithRenderer(presetID, renderer)
	if !ok {
		return report.Record{}, fmt.Errorf("--preset requires one of: %s", strings.Join(IDs(), ", "))
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
				Key: "pathPolicy",
				Value: map[string]any{
					"consumerOverrideRequired":   true,
					"defaultFilesAreSuggestions": true,
					"nonClaims": admit.StringSliceToAny([]string{
						"Stack presets do not override consuming repository documentation policy.",
						"Stack presets do not prove that suggested paths are complete for a consuming repository.",
					}),
					"policyClass": "starter_suggestion",
				},
			},
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

func IDs() []string {
	return append([]string(nil), presetIDs...)
}

func ProfileFor(presetID string) (Profile, bool) {
	return ProfileForWithRenderer(presetID, cliexec.PathRenderer())
}

func ProfileForWithRenderer(presetID string, renderer cliexec.Renderer) (Profile, bool) {
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
		SuggestedCommands:         renderCommands(renderer, preset.SuggestedCommandArgs),
	}, true
}

func renderCommands(renderer cliexec.Renderer, commands [][]string) []string {
	rendered := make([]string, 0, len(commands))
	for _, command := range commands {
		rendered = append(rendered, renderer.DisplayCommand(command...))
	}
	return rendered
}

func stringsToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
