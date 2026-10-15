package witnessschedulerplan

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide connects a reviewed binding record to declared scheduling policy
// without executing, selecting or discovering native witnesses.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Witness scheduler input guide:
  The scheduler admits declared execution policy. It does not run commands,
  select tests, read files or prove that an earlier run used this policy.
  Derive commands from the reviewed binding record instead of retyping argv.
  The binding record shape is /requirementProofBinding/record in:
    {{cli}} adopt materialize plan --help
  Store this projection request as <projection-input>, replacing the binding
  placeholder with that complete record and reusing the vocabulary below:
    {"schemaVersion":1,"projection":"requirement-bindings",
     "requirementProofBinding":<binding-record>,"vocabulary":<vocabulary>}
  {{cli}} witness-plan --input <projection-input>
  The projection needs exactly one parallelGroup, and each binding environment
  class needs a policy allowing network none, credential none and cache disabled.
  Copy its commands array unchanged into commands below; do not edit argv.

  Add exactly one policies row per command, ordered like commands. Replace
  commandId and inputSelectors (sorted repository-relative paths the command
  reads) with reviewed facts. sideEffectClass none requires empty resourceWrites,
  outputSelectors and exclusiveLocks; select another class for writers. Keep
  retry kind none unless the owner approves idempotent retries. Every nonClaims
  list must be nonempty and sorted. Never insert secrets or local credentials.

Scheduler template (required null operands deliberately reject admission):
` + "```json" + `
{
  "schemaVersion": 1,
  "schedulerPlanId": null,
  "vocabulary": {
    "artifactKinds": ["log"],
    "credentialClasses": ["none"],
    "environmentClasses": ["local-go"],
    "environmentClassPolicies": [{"environmentClass": "local-go", "networkPolicies": ["none"], "credentialClasses": ["none"], "cachePolicies": ["disabled"]}],
    "parallelGroups": ["example.native"],
    "nonCacheableCredentialClasses": [],
    "maxTimeoutMs": 60000
  },
  "commands": null,
  "policies": [{
    "commandId": null,
    "inputSelectors": null,
    "outputSelectors": [],
    "resourceReads": [],
    "resourceWrites": [],
    "exclusiveLocks": [],
    "sideEffectClass": "none",
    "deterministicOutput": true,
    "cacheAdmissionRefs": [],
    "retryPolicy": {"kind": "none", "maxAttempts": 1},
    "cancellationPolicy": {"kind": "cooperative", "graceMs": 1000},
    "timeoutPolicy": {"kind": "bounded", "timeoutMs": 60000},
    "nonClaims": ["Declared scheduling policy does not execute commands."]
  }],
  "nonClaims": ["Scheduler declarations do not prove execution or approve merge."]
}
` + "```" + `

  {{cli}} witness-scheduler-plan --input <scheduler-input>
  Require exit 0 and state passed; a failed report names the violated policy.
  Use this exact input as witnessPlan in spec-proof-bundle-admission and its
  schedulerPlanId as each receipt proofPlanId. Changing a binding command
  requires a new projection and plan. A passed plan is declared policy only:
  it is not execution, currentness, producer trust or merge evidence.
`
