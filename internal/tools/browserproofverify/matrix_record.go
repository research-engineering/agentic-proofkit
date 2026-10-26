package main

import (
	"fmt"
	"slices"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/secretjson"
)

// The accessibility matrix is owned here: every rendered view of the visual
// inventory in each engine, color scheme and mode, plus the two workspace
// panel dialogs in the narrow modes. Each of its two families, the static
// renderings and the workspace, runs as its own witness command and writes
// its own record; the record must name exactly the family's expected cells,
// negative controls and reader tasks in every engine.
const (
	matrixTestRoot   = "tests/matrix"
	matrixRecordKind = "proofkit.browser-matrix-proof"
)

var (
	// Five modes: 320 and 1440 CSS px, each also at a 200% root font size,
	// and full-page zoom emulated as a 720 CSS px viewport at device scale
	// factor 2. The dialogs are matrix states only in the narrow modes.
	matrixModes       = []string{"320", "1440", "320-root-200", "1440-root-200", "720-dsf-2"}
	matrixNarrowModes = []string{"320", "320-root-200", "720-dsf-2"}
	matrixDialogs     = []string{"workspace-navigation-dialog", "workspace-inspector-dialog"}
	// The negative controls of oracles 1 to 4 and 6, run in every engine on
	// one view of each family.
	matrixControlTitles = []string{
		"axe refuses an injected violation",
		"axe refuses a view in which target-size applies to no node",
		"axe refuses an incomplete target-size result",
		"axe refuses an incomplete color-contrast node that fails the computed-contrast oracle",
		"contrast refuses a placeholder below 4.5:1",
		"contrast refuses a checkbox without a 3:1 boundary",
		"reflow refuses a horizontally scrolling document",
		"reflow refuses an unlabelled scrolling region",
		"lost content refuses clipped record text",
		"keyboard refuses an interactive element that Tab cannot reach",
		"keyboard refuses an invisible focus indicator",
		"security refuses a page-initiated load that the CSP blocks",
		"security refuses a console error",
		"security refuses a document whose CSP differs from the exact policy",
	}
	matrixTaskTitles = map[string][]string{
		"static": {
			"a reader finds a requirement by searching the static source view",
			"a reader opens a requirement's scenario in the static source view",
			"a reader follows a proof hierarchy link to the binding's witness in the static proof view",
			"a reader sees the coverage gap of a static coverage view with an uncovered requirement",
		},
		"workspace": {
			"a reader finds a requirement by searching the workspace",
			"a reader follows a Traceability record to its relation in the workspace",
			"a reader sees that an admitted empty coverage report covers no requirement",
			"a reader reads a requirement change in the workspace diff",
		},
	}
	// The Firefox site-icon control runs only in Firefox, in the static family.
	matrixFirefoxSiteIconTitle = "Firefox's own favicon request is refused and seen without the site-icon preference and absent with it"
	matrixCommandArgv          = []string{"node_modules/@playwright/test/cli.js", "test", "--config", "playwright.matrix.config.mjs"}
)

var matrixProofNonClaims = []string{
	"A passed record proves only that every expected accessibility-matrix cell, negative control and reader task of its family passed with zero retries in each recorded engine, in the observed environment, before record creation.",
	"A record whose divergentFields is not empty was produced outside the recorded reference environment and claims its outcomes only for the observed environment.",
	"This record does not prove WCAG conformance certification, a human usability study, complete screen-reader interoperability, 400-percent zoom behavior or pixel identity.",
	"Playwright WebKit is not branded Safari compatibility proof.",
	"A dirty-tree record is content-bound only to its listed assets; sourceRevision is contextual.",
	"This record does not independently authenticate or sandbox the same-user proof runner, the container image beyond its observed tuple, external toolchain packages, or browser binaries.",
}

// matrixFamilyViews returns the views of a family; a workspace family view is
// one of the four tabs.
func matrixFamilyViews(family string) []string {
	if family == "static" {
		return slices.Clone(visualViews[:10])
	}
	return slices.Clone(visualViews[10:])
}

// expectedMatrixCellTitles returns the cell test identities of a family:
// "<mode> > <view> <scheme>" for every mode, view and scheme, and for the
// workspace family every dialog in each narrow mode.
func expectedMatrixCellTitles(family string) []string {
	titles := []string{}
	for _, mode := range matrixModes {
		for _, view := range matrixFamilyViews(family) {
			for _, scheme := range visualSchemes {
				titles = append(titles, fmt.Sprintf("%s > %s %s", mode, view, scheme))
			}
		}
		if family == "workspace" && slices.Contains(matrixNarrowModes, mode) {
			for _, dialog := range matrixDialogs {
				for _, scheme := range visualSchemes {
					titles = append(titles, fmt.Sprintf("%s > %s %s", mode, dialog, scheme))
				}
			}
		}
	}
	return titles
}

// expectedMatrixProjectTests is the exact test identity set each project of
// a family must pass: every cell, every control and every reader task, and
// in Firefox's static family the site-icon control.
func expectedMatrixProjectTests(family string) map[string][]string {
	root := matrixTestRoot + "/" + family
	result := make(map[string][]string, len(visualEngines))
	for _, engine := range visualEngines {
		ids := []string{}
		for _, title := range expectedMatrixCellTitles(family) {
			ids = append(ids, fmt.Sprintf("%s/cells.spec.mjs::cells.spec.mjs > %s", root, title))
		}
		for _, title := range matrixControlTitles {
			ids = append(ids, fmt.Sprintf("%s/controls.spec.mjs::controls.spec.mjs > %s", root, title))
		}
		for _, title := range matrixTaskTitles[family] {
			ids = append(ids, fmt.Sprintf("%s/tasks.spec.mjs::tasks.spec.mjs > %s", root, title))
		}
		if family == "static" && engine == "firefox" {
			ids = append(ids, fmt.Sprintf("%s/firefox-site-icons.spec.mjs::firefox-site-icons.spec.mjs > %s", root, matrixFirefoxSiteIconTitle))
		}
		slices.Sort(ids)
		result[engine] = ids
	}
	return result
}

// verifyMatrixRecord admits a passed matrix record of the kind's family. It
// binds the record to its content-bound inputs and to the recorded reference
// environment, recomputes the environment divergence, and requires every
// engine to pass exactly the family's expected tests; when no field diverges,
// the engine versions must equal the recorded browser versions.
func verifyMatrixRecord(root string, kind proofKind, raw any, expectedResolution proofInputResolution, revision, treeState string) error {
	record, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("browser matrix proof must be an object")
	}
	if err := admit.KnownKeys(record, []string{"assets", "command", "divergentFields", "engines", "family", "inputDigest", "inputResolution", "nonClaims", "observedEnvironment", "projects", "proofKind", "referenceEnvironment", "schemaVersion", "sourceRevision", "sourceTreeState", "state"}, "browser matrix proof"); err != nil {
		return err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["proofKind"] != matrixRecordKind || record["family"] != kind.Family || record["state"] != "passed" ||
		record["sourceRevision"] != revision || record["sourceTreeState"] != treeState {
		return fmt.Errorf("browser matrix proof identity or source state is invalid")
	}
	if err := exactTextArray(record["nonClaims"], matrixProofNonClaims, "browser matrix proof nonClaims"); err != nil {
		return err
	}
	if err := verifyContentBoundInputs(root, record, expectedResolution, "browser matrix proof"); err != nil {
		return err
	}
	environment, err := loadVisualEnvironment(root)
	if err != nil {
		return err
	}
	reference, ok := record["referenceEnvironment"].(map[string]any)
	if !ok || admit.KnownKeys(reference, []string{"environmentId"}, "browser matrix proof referenceEnvironment") != nil || reference["environmentId"] != environment.EnvironmentID {
		return fmt.Errorf("browser matrix proof is not bound to the recorded reference environment")
	}
	observed, ok := record["observedEnvironment"].(map[string]any)
	if !ok || admit.KnownKeys(observed, append([]string{"cpu"}, visualComparedEnvironmentFields...), "browser matrix proof observedEnvironment") != nil ||
		len(observed) != len(visualComparedEnvironmentFields)+1 {
		return fmt.Errorf("browser matrix proof must record the complete observed environment")
	}
	if err := admitObservedTuple(observed, false); err != nil {
		return err
	}
	if err := admitObservedCPU(observed["cpu"]); err != nil {
		return err
	}
	divergent, err := visualEnvironmentDivergence(environment.Observed, observed)
	if err != nil {
		return err
	}
	if err := exactTextArray(record["divergentFields"], divergent, "browser matrix proof divergentFields"); err != nil {
		return err
	}
	command, ok := record["command"].(map[string]any)
	if !ok || admit.KnownKeys(command, []string{"argv", "exitCode", "inputMode", "runner"}, "browser matrix proof command") != nil ||
		command["inputMode"] != "materialized_snapshot" || command["runner"] != "node" || !admit.JSONNumberEquals(command["exitCode"], 0) {
		return fmt.Errorf("browser matrix proof command is invalid")
	}
	if err := exactTextArray(command["argv"], matrixCommandArgv, "browser matrix proof command argv"); err != nil {
		return err
	}
	engines, ok := record["engines"].([]any)
	if !ok || len(engines) != len(visualEngines) {
		return fmt.Errorf("browser matrix proof must record three engines")
	}
	projects, ok := record["projects"].([]any)
	if !ok || len(projects) != len(visualEngines) {
		return fmt.Errorf("browser matrix proof must record three project executions")
	}
	expected := expectedMatrixProjectTests(kind.Family)
	for index, name := range visualEngines {
		project, ok := projects[index].(map[string]any)
		if !ok || admit.KnownKeys(project, []string{"browserName", "browserVersion", "executedTestCount", "name", "passedTestCount", "testIds"}, "browser matrix proof project") != nil ||
			project["name"] != name || project["browserName"] != name {
			return fmt.Errorf("browser matrix proof project identity is invalid")
		}
		version, err := admit.NonEmptyText(project["browserVersion"], "browser matrix proof project browserVersion")
		if err != nil {
			return err
		}
		if len(divergent) == 0 && version != environment.BrowserVersions[name] {
			return fmt.Errorf("browser matrix proof engine versions must equal the reference environment")
		}
		engine, ok := engines[index].(map[string]any)
		if !ok || admit.KnownKeys(engine, []string{"name", "version"}, "browser matrix proof engine") != nil || engine["name"] != name || engine["version"] != version {
			return fmt.Errorf("browser matrix proof engine versions must come from the recorded project executions")
		}
		testIDs, err := sortedUniqueTextArray(project["testIds"], "browser matrix proof testIds")
		if err != nil {
			return err
		}
		if !slices.Equal(testIDs, expected[name]) || !admit.JSONNumberEquals(project["executedTestCount"], int64(len(testIDs))) ||
			!admit.JSONNumberEquals(project["passedTestCount"], int64(len(testIDs))) {
			return fmt.Errorf("browser matrix proof project must pass exactly its family's expected cells, controls and tasks")
		}
	}
	findings, err := secretjson.Scan(record, "browser_matrix_proof")
	if err != nil || len(findings) > 0 {
		return fmt.Errorf("browser matrix proof contains secret-shaped data")
	}
	return nil
}
