package projectstatus

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// actionContinuation names the help route an agent reads next for one action
// class. A nil route means the state stops at an owner decision.
type actionContinuation struct {
	ActionClass string
	HelpRoute   []string
	Instruction string
}

// actionContinuations is total over the action classes of canonicalAction.
var actionContinuations = []actionContinuation{
	{ActionClass: ActionChooseAdoptionMode, HelpRoute: []string{"adopt", "plan"}, Instruction: "owner selects fresh, code-baseline or audit-from-code."},
	{ActionClass: ActionRematerializeProject, HelpRoute: []string{"adopt", "materialize", "plan"}, Instruction: "review drift, then plan and apply the record set."},
	{ActionClass: ActionChooseRecovery, HelpRoute: []string{"adopt", "materialize", "recover"}, Instruction: "owner selects resume or rollback for the transaction."},
	{ActionClass: ActionRunRepositoryVerification, HelpRoute: []string{"native-evidence-guidance"}, Instruction: "run owned witnesses; admit receipts and currentness."},
	{ActionClass: ActionRepairProjectRecords, Instruction: "stop; the owner repairs invalid project records."},
	{ActionClass: ActionRepairControlState, Instruction: "stop; the owner repairs transaction control state."},
}

// ContinuationGuide maps every next-action class to its CLI continuation.
func ContinuationGuide(renderer cliexec.Renderer) string {
	lines := []string{
		"Next-action continuation:",
		"  The action packet is never executable. Before any write, read the help",
		"  of its commandRoute; an empty route means the owner must act:",
	}
	for _, item := range actionContinuations {
		lines = append(lines, "  "+item.ActionClass+": "+item.Instruction)
		if len(item.HelpRoute) > 0 {
			lines = append(lines, "    "+renderer.DisplayCommand(append(append([]string{}, item.HelpRoute...), "--help")...))
		}
	}
	lines = append(lines,
		"  verification_required never means verified: status reads no receipts.",
		"  Completion is the consumer's decision over a passed bundle and current",
		"  receipts. A current receipt for one route does not reaffirm another;",
		"  rerun status after every repository write.",
	)
	return strings.Join(lines, "\n") + "\n"
}
