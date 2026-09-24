package requirementcoverageinput

import (
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
)

// InputGuide owns the direct-mode recipe, not the child schemas or test policy.
func InputGuide(renderer cliexec.Renderer) string {
	return strings.ReplaceAll(inputGuide, "{{cli}}", renderer.DisplayCommand())
}

const inputGuide = `Declaration coverage input guide:
  This recipe uses direct inputs, not compact proof contracts or source sets.
  Obtain connected source, binding and inventory shapes without writing files:
    {{cli}} adopt materialize plan --help
  Copy whole input records from that packet, not their admission reports:
    requirementSource <- /requirementSources/0
    requirementProofBinding <- /requirementProofBinding/record
    testEvidenceInventory <- /testEvidenceInventory/record
  Its sourcePlan may stay null for this read-only operation. The inventory must
  use caller_owned_inventory. Do not include compactProofContract or
  normalizedTestEvidenceInventory, even as null, in this direct-mode input.

  Fill required nulls from reviewed records and actual native discovery.
  selectedOwnerIds must equal coverageUniverse.ownerIds; every inventory entry
  must belong to those owners. Choose full_repository only with a complete
  repository inventory; selected_owner_surfaces makes declared gaps failures;
  selected_paths_advisory keeps dead-zone findings advisory, not completeness.
  Do not narrow scope just to hide an absent test. The CLI does not scan files.
  Give each surface a stable surfaceId, ownerId and repository-relative path.
  Include the required test surfaces independently of discovered entries so a
  missing test remains visible. Include expected command IDs in commandRefs.
  The composer adds inventory paths/commands; omission is not proof of absence.
  Sort unique owner/command IDs and nonClaims; preserve source/binding identity.
  For another source repeat this operation with its exact matching inputs.

Coverage template (required null operands deliberately reject admission):
` + "```json\n" + `{
  "schemaVersion": 3,
  "composerInputId": null,
  "viewInputId": null,
  "selectedOwnerIds": null,
  "requirementSource": null,
  "requirementProofBinding": null,
  "testEvidenceInventory": null,
  "coverageUniverse": {
    "schemaVersion": 1,
    "universeId": null,
    "authority": "caller_owned_inventory",
    "completenessDeclaration": null,
    "ownerIds": null,
    "codeSurfaces": [],
    "specSurfaces": [],
    "testSurfaces": [],
    "commandRefs": [],
    "nonClaims": ["Declared scope does not prove discovery or test execution."]
  },
  "ownerInvariantRegistry": null,
  "localEnvironmentPolicy": null,
  "options": null
}
` + "```\n" + `
  Empty surface arrays are placeholders, not a claim that no surfaces exist.
  A surface is {"surfaceId":"<id>","ownerId":"<owner>","path":"<path>"}.
  ownerInvariantRegistry may stay null when no ownerInvariantRefs are used.
  localEnvironmentPolicy may stay null in direct mode; when supplied it is
  {"authority":"caller_provided","localEnvironmentClasses":["<class>"]}.
  options may stay null. Never insert secrets into paths, records or diagnostics.

  Store the completed input at <coverage-input>. Capture the first command's
  stdout bytes as <view-input> only after exit0, preserving stderr separately:
  {{cli}} requirement-coverage-input-compose --input <coverage-input>
  {{cli}} requirement-coverage-view --input <view-input> --format json
  Do not pass the compose request to the view or rebuild its output by hand.
  Composer exit0 proves downstream input admission, not coverage success.
  The view may exit1 with JSON state failed; retain failures, warnings,
  unmappedTests and deadZones. An unmapped test can be reported without causing
  exit1: the consumer decides whether it blocks. A declared route is not a
  proved assertion or executed test. Do not relabel these observations as pass.
  Native execution and receipt/currentness/trust admission are separate:
    {{cli}} native-evidence-guidance --help
`
