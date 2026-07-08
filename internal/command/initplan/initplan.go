package initplan

import (
	"fmt"
	"sort"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

const reportKind = "proofkit.init"

var presets = map[string][]route{
	"change-set": {
		{"changed-path-set", "admit caller-owned changed paths before impact planning"},
		{"requirement-impact-input-compose", "compose admitted impact input from changed paths and proof records"},
		{"selective-gate-plan", "plan the smallest caller-owned gate set with explicit scan obligations"},
	},
	"code-audit": {
		{"capability-map-admission", "capture untrusted code observations as owner questions"},
		{"test-evidence-inventory --projection discovery-draft", "turn explicit discovered tests into candidate-only inventory guidance"},
		{"requirement-authoring-plan", "draft owner-review work without promoting observations to requirements"},
	},
	"code-baseline": {
		{"capability-map-admission", "freeze trusted current behavior as candidate requirement and binding seeds"},
		{"test-evidence-inventory --projection discovery-draft", "capture explicit discovered tests as candidate inventory only"},
		{"requirement-source-admission", "admit owner-reviewed requirements after materialization"},
	},
	"fresh": {
		{"scaffold-project-structure", "draft caller-owned starter file topology without writing files"},
		{"gradual-adoption-bootstrap", "draft bootstrap payloads from explicit caller input"},
		{"adoption-workflow-plan", "route the first bounded adoption workflow"},
	},
	"legacy": {
		{"migration-parity-admission", "admit explicit old/new parity rows"},
		{"migration-plan", "plan migration work from admitted parity records"},
		{"requirement-source-transition", "admit owner-reviewed requirement lifecycle transitions"},
	},
}

type route struct {
	Command string
	Reason  string
}

func Build(preset string) (report.Record, error) {
	if preset == "" {
		preset = "all"
	}
	if preset != "all" {
		if _, ok := presets[preset]; !ok {
			return report.Record{}, fmt.Errorf("init --preset must be all, fresh, code-baseline, code-audit, legacy, or change-set")
		}
	}
	routeRecords := selectedRouteRecords(preset)
	return report.Record{
		SchemaVersion: 1,
		ReportKind:    reportKind,
		ReportID:      "proofkit.init",
		State:         "passed",
		Summary: map[string]any{
			"dryRunOnly":     true,
			"selectedPreset": preset,
			"routeCount":     len(routeRecords),
			"routePresets":   stringsToAny(sortedPresetIDs()),
		},
		Diagnostics: []report.Diagnostic{
			{Key: "routes", Value: routeRecords},
		},
		RuleResults: []report.RuleResult{
			{
				RuleID:  "proofkit.init.dry-run-routes",
				Status:  "passed",
				Message: "Init emits dry-run route guidance only and does not scan, write, or promote repository facts.",
				Diagnostics: []report.Diagnostic{
					{Key: "selectedPreset", Value: preset},
					{Key: "routeCount", Value: len(routeRecords)},
				},
			},
		},
		NonClaims: []any{
			"Init does not read repository files, discover tests, execute commands, write files, create requirements, approve merge, release, rollout, or production readiness.",
			"Init route guidance is a decision aid; caller-owned repository facts must still be materialized and admitted by the target command owners.",
		},
	}, nil
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func selectedRouteRecords(preset string) []any {
	presetIDs := sortedPresetIDs()
	if preset != "all" {
		presetIDs = []string{preset}
	}
	records := []any{}
	for _, presetID := range presetIDs {
		for index, item := range presets[presetID] {
			records = append(records, map[string]any{
				"command": item.Command,
				"order":   index + 1,
				"preset":  presetID,
				"reason":  item.Reason,
			})
		}
	}
	return records
}

func sortedPresetIDs() []string {
	ids := make([]string, 0, len(presets))
	for id := range presets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
