package app

import (
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionmaterialization"
	"github.com/research-engineering/agentic-proofkit/internal/command/adoptionplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/repositorytransaction"
)

// commandHelpText returns the exact installed help of one route.
func commandHelpText(t *testing.T, route ...string) string {
	t.Helper()
	code, output, diagnostic := executeAgentWorkflowCLI(t, append(append([]string{}, route...), "--help"), panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" {
		t.Fatalf("%v --help exit=%d stderr=%q", route, code, diagnostic)
	}
	return output
}

func requireHelpLines(t *testing.T, label, help string, lines ...string) {
	t.Helper()
	normalized := strings.Join(strings.Fields(help), " ")
	for _, line := range lines {
		if !strings.Contains(normalized, strings.Join(strings.Fields(line), " ")) {
			t.Fatalf("%s help lacks %q", label, line)
		}
	}
}

// Pilot D2: the mode meaning lives where the owner chooses the mode.
func TestAdoptPlanHelpExplainsEveryMode(t *testing.T) {
	help := commandHelpText(t, "adopt", "plan")
	if !strings.Contains(help, adoptionplan.ModeGuide()) {
		t.Fatalf("adopt plan help lacks the mode guide:\n%s", help)
	}
	materialization := commandHelpText(t, "adopt", "materialize", "plan")
	requireHelpLines(t, "materialization", materialization, "adopt plan --help explains each --mode")
}

// Pilot D14 and D17: the sourcePlan freshness rule and the control-state
// policy are stated where the packet is built and applied.
func TestMaterializationHelpStatesSourcePlanFreshnessAndControlState(t *testing.T) {
	help := commandHelpText(t, "adopt", "materialize", "plan")
	requireHelpLines(t, "materialization", help,
		"Plan and apply accept only the sourcePlanId recorded in "+adoptionmaterialization.ProjectManifestPath+" or a plan whose repositoryInventory equals the current root; any other plan is stale.",
		"Apply also keeps control state under "+repositorytransaction.ControlRoot+"/: the journal and only the latest terminal receipt.",
		"Keep it out of version control",
		"oracle.oracleKind is a consumer-defined label that Proofkit admits as text and never interprets",
		"<specPackagePath>/overview.md is reserved for context the owner writes.",
	)
}

// Pilot D1: the root catalog names the bootstrap route and the route it
// starts, and the named bootstrap really starts with status then next.
func TestRootHelpNamesTheBootstrapRoute(t *testing.T) {
	code, help, diagnostic := executeAgentWorkflowCLI(t, []string{"help"}, panicReader{}, PresentationCapabilities{})
	if code != 0 || diagnostic != "" {
		t.Fatalf("help exit=%d stderr=%q", code, diagnostic)
	}
	requireHelpLines(t, "root", help,
		"Start here: the agent bootstrap, then the project's next action:\n  agentic-proofkit integration source --tool <claude|codex> --format text\n  agentic-proofkit next --repo-root <path>")
	code, bootstrap, diagnostic := executeAgentWorkflowCLI(t, []string{"integration", "source", "--tool", "codex", "--format", "text"}, panicReader{}, PresentationCapabilities{})
	status, next := strings.Index(bootstrap, "Run status --repo-root"), strings.Index(bootstrap, "Run next --repo-root")
	if code != 0 || diagnostic != "" || status < 0 || next < status {
		t.Fatalf("named bootstrap does not start with status then next: exit=%d %q", code, diagnostic)
	}
}

// Pilots D5, D6, D9 and D18: receipt subjects name the bytes they cover and
// identifier rules are rendered from the admission constants.
func TestReceiptGuidesMapBytesToSubjectsAndStateIdentifierGrammar(t *testing.T) {
	grammar := admit.RuleIDGrammar()
	receipt := commandHelpText(t, "proof-receipt-admission")
	requireHelpLines(t, "receipt", receipt,
		"One admissible encoding: UTF-8 JSON with sorted keys and no insignificant whitespace, hashed with SHA-256.",
		"proofBindingDigest: the binding row and the requirement and scenario records it binds",
		"dependencyDigest: native test and implementation bytes",
		"stable ID; number runs instead of timestamping them: "+grammar,
		"runnerClass and runnerIdentity are your labels; Proofkit never interprets them.",
	)
	requireHelpLines(t, "currentness", commandHelpText(t, "receipt-currentness-scope"),
		"proofRouteRef names that binding route as a stable ID, not a path or path#fragment", "IDs follow: "+grammar)
	requireHelpLines(t, "coverage compose", commandHelpText(t, "requirement-coverage-input-compose"), "IDs follow: "+grammar,
		"src/__init__.py -> src.init_py, not src.--init--")
}

// Pilot D10: usage lines name the --format values a command admits.
func TestUsageLinesNameAdmittedFormatValues(t *testing.T) {
	help := commandHelpText(t, "requirement-coverage-view")
	requireHelpLines(t, "coverage view", help, "[--format <html|json|markdown>]")
	code, _, diagnostic := executeAgentWorkflowCLI(t, []string{"requirement-coverage-view", "--input", "-", "--format", "text"}, panicReader{}, PresentationCapabilities{})
	if code != 1 || !strings.Contains(diagnostic, "--format must be json, markdown, or html") {
		t.Fatalf("unlisted text format exit=%d stderr=%q", code, diagnostic)
	}
	for _, descriptor := range commandDescriptors {
		if strings.Contains(commandUsageLine(descriptor), "--format <mode>") {
			t.Fatalf("%s usage hides its --format values", descriptor.name)
		}
	}
}

// Pilots D11, D19 and D21: owner questions, witness moves and dependency
// scope are explained where those decisions are made.
func TestDecisionGuidesExplainOwnerQuestionsWitnessMovesAndDependencyScope(t *testing.T) {
	requireHelpLines(t, "authoring", commandHelpText(t, "requirement-authoring-plan"),
		"Its non-empty ownerQuestions become the owner's ask_owner review action",
		"ask the owner to confirm the exact candidate wording and any assumption you added")
	requireHelpLines(t, "native evidence", commandHelpText(t, "native-evidence-guidance"),
		"8. To move a witness to another file, language or command, keep requirementId and scenarioId.",
		"Project a new scheduler plan: the moved edge's old receipt goes stale (and stops linking where its command changed)",
		"Receipts of unchanged commands stay linked; re-check their currentness, since they stay current only if the moved files are outside their declared dependency scope (change plan --help, step 1).",
		"Never copy a receipt under a new digest without running it.")
	requireHelpLines(t, "migration plan", commandHelpText(t, "migration-plan"),
		"Moving a requirement's native witness is not infrastructure migration; see adapter step 8 of:\n  agentic-proofkit native-evidence-guidance --help")
	requireHelpLines(t, "change plan", commandHelpText(t, "change", "plan"),
		"receipts go stale together: the sound default",
		"Narrow a scope only by changing that import structure or by an owner-recorded rule that a file cannot affect the outcome, never to keep a receipt current.")
	requireHelpLines(t, "scheduler", commandHelpText(t, "witness-scheduler-plan"),
		"passes no variable, not even PATH or HOME",
		"give them separate groups, run one after another, in an explicit catalog",
		"A receipt links only while its command's node digest is unchanged, so an edit to one command unlinks only that command's receipts; rerun that witness.")
	requireHelpLines(t, "bundle", commandHelpText(t, "spec-proof-bundle-admission"),
		"edits to other commands or to nonClaims do not unlink it",
		"never copy a receipt under a new digest without running it")
}
