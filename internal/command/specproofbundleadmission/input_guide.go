package specproofbundleadmission

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide owns the bundle wrapper recipe; child commands still own admission.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Spec proof bundle input guide:
  Prerequisites: reviewed requirement-bindings input, witness-scheduler-plan
  input and a completed proof-receipt-admission input. This guide does not
  create the scheduler policy, execute its commands or authenticate results.
  Obtain binding shapes from adopt materialize plan --help and the receipt
  operand recipe from proof-receipt-admission --help. Preserve complete inputs,
  not report summaries. A later scheduler declaration is not proof that an
  earlier process executed under that policy.

  Admit each input separately and retain exact output plus process exit code:
  {{cli}} requirement-bindings --input <binding-input>
  {{cli}} witness-scheduler-plan --input <scheduler-input>
  {{cli}} proof-receipt-admission --input <receipt-input>
  Stop on admission errors or failed child reports. Do not edit a report to
  passed. A passed receipt report can contain failed/blocked/not_run receipts;
  it is admissibility evidence, not evidence those witnesses succeeded.

  Fill requirementBindings and witnessPlan with the respective complete inputs.
  For receiptAdmission, report is the exact receipt command's JSON stdout,
  exitCode is its actual process exit, receipts is the original input receipts,
  nonClaims is the original input nonClaims, producers is [], and failures is
  the report.diagnostics entry whose key is failures, using its value array.
  The report's reportId must equal the original receiptSetId. Do not zip arrays,
  drop nonClaims or reuse a report after modifying its receipt inputs. The
  bundle recomputes and compares the complete child report with its owner.

Bundle template (fill required inputs and child result operands):
` + "```json\n" + `{
  "schemaVersion": 1,
  "bundleId": null,
  "requirementBindings": null,
  "witnessPlan": null,
  "receiptAdmission": {
    "exitCode": null,
    "failures": null,
    "nonClaims": null,
    "producers": [],
    "receipts": null,
    "report": null
  },
  "receiptProducerAdmission": null,
  "mergeRequiredReceiptIds": [],
  "nonClaims": ["Bundle linkage does not execute witnesses, authenticate producers or approve merge."]
}
` + "```\n" + `
  Match each receipt's proofPlanId to schedulerPlanId, receiptKind to a binding
  commandId, and each logical witnessSelectors ID to a requirement/scenario
  covered by that command. Scheduler and binding command/environment sets must
  agree; unbound scheduler commands fail. Sorting does not repair a wrong link.
  Preserve each receipt's recorded environment; independently check it against
  the actual runner policy. Bundle linkage is not full environment/currentness
  verification and does not inspect files or recompute digest subjects.

Admit the completed bundle (use - for stdin):
  {{cli}} spec-proof-bundle-admission --input <bundle-input>
  Empty mergeRequiredReceiptIds declares no merge-required receipts; it does
  NOT mean all proof passed. Optional absent receipts can pass linkage without
  any execution. When the consumer requires merge receipts, name every required
  receiptId; each must exist, pass and be merge_satisfying, with a matching
  receiptProducerAdmission child. That child uses receipt-producer-admission's
  actual report/input plus its environmentClasses and receiptKinds arrays.
  Its producer policy remains caller-declared; structural agreement does not
  authenticate the producer. Do not manufacture that child for local examples.
  Run currentness and trust checks under consumer authority; neither is implied
  by bundle state passed. Keep their reports and the original subject bytes.
`
