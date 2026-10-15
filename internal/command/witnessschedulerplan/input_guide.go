package witnessschedulerplan

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide connects a reviewed binding record to declared scheduling policy
// without executing, selecting or discovering native witnesses.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.NewReplacer("{{cli}}", renderer.DisplayCommand(), "{{sideEffectClasses}}", strings.Join(sideEffectClasses, ", ")).Replace(inputGuide)
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
  It is conservative: environment inherit none with an empty allowlist passes
  no variable, not even PATH or HOME, so e.g. go test cannot run it literally.
  When the owner approves variables or separate groups, copy its commands,
  change only environment (inherit allowlist, sorted names) or parallelGroup
  (also listed in vocabulary.parallelGroups), and admit that explicit catalog
  with the same witness-plan command as {"schemaVersion":1,"commands":...,
  "vocabulary":...}. Copy admitted commands unchanged below; never edit argv.

  Add exactly one policies row per command, ordered like commands. Replace
  commandId, inputSelectors (sorted repository-relative paths the command
  reads) and sideEffectClass with reviewed facts. sideEffectClass is one of:
    {{sideEffectClasses}}
  none requires empty exclusiveLocks and resourceWrites and means no write at
  all (caches and bytecode included); admission cannot observe other writes.
  Commands of one parallelGroup may run concurrently, so two writers of one
  resource or lock collide: give them separate groups, run one after another,
  in an explicit catalog; renaming the resource only misdeclares it. Keep
  retry kind none unless the owner approves idempotent retries. Every
  nonClaims list must be nonempty and sorted. Never insert secrets or local
  credentials.

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
    "sideEffectClass": null,
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
  Use this exact input as witnessPlan in spec-proof-bundle-admission. Record
  its schedulerPlanId as each receipt's proofPlanId and, as its
  proofNodeDigest, the report's proofNodeDigests row for the receipt's
  command (receiptKind). A node digest covers exactly what decides how that
  command runs: its admitted command record, its policy without nonClaims and
  the vocabulary rows of the names it references (the policy rows of its
  environment classes and whether its credential class is non-cacheable).
  nonClaims, unreferenced vocabulary rows, maxTimeoutMs and other commands,
  including group co-members, are excluded.
  A receipt links only while its command's node digest is unchanged, so an
  edit to one command unlinks only that command's receipts; rerun that
  witness. Changing a binding command requires a new projection and plan. A
  passed plan is declared policy only:
  it is not execution, currentness, producer trust or merge evidence.
`
