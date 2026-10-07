package externalconsumer

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var reportInputFields = []string{"evidence", "input", "schemaVersion"}
var inputFields = []string{"npmIntegrity", "npmShasum", "nonClaims", "packageName", "packageVersion", "packMetadataPath", "packMetadataSha256", "pilotId", "pilotMode", "releaseAuthorityInput", "rollback", "binarySmokeProbeRuleId", "schemaVersion", "sourceArtifactName", "sourceCommit", "sourceRepository", "sourceWorkflowRun", "tarballPath", "tarballSha256", "witnessPlan"}
var witnessFields = []string{"commands", "vocabulary"}
var rollbackFields = []string{"dependencyRemoval", "localWorkspaceFallbackPreserved"}
var evidenceFields = []string{"consumerProof", "packMetadata", "schemaVersion", "tarball"}
var tarballFields = []string{"path", "sha1", "sha256"}
var packMetadataFields = []string{"path", "records", "sha256"}
var packRecordFields = []string{"filename", "files", "integrity", "name", "shasum", "version"}
var packFileFields = []string{"path"}
var proofFields = []string{"cliWitnessPlanOutputSha256", "dependencySpec", "frozenLockContainsPackage", "frozenLockContainsTarball", "frozenLockUsesWorkspace", "installLockContainsPackage", "installLockContainsTarball", "installLockUsesWorkspace", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState", "rollbackLockContainsPackage", "binarySmokeOutputSha256", "tempConsumerLocation"}

const acceptedRuleID = "proofkit.external-consumer.accepted"
const acceptedMessage = "external consumer evidence is explicit and bounded to the tarball pilot channel"
const failureRulePrefix = "proofkit.external-consumer.failure."

func proofStructure(output bool) jsonshape.Shape {
	text := jsonshape.NonBlankString()
	fields := map[string]jsonshape.Shape{}
	for _, name := range proofFields {
		fields[name] = jsonshape.Boolean()
	}
	for _, name := range []string{"cliWitnessPlanOutputSha256", "dependencySpec", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState", "binarySmokeOutputSha256", "tempConsumerLocation"} {
		fields[name] = text
	}
	if output {
		fields["tempConsumerLocation"] = jsonshape.StringLiteral("os-temp")
	}
	return jsonshape.ObjectFromKeys(proofFields, fields)
}

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	fields := map[string]jsonshape.Shape{}
	for _, name := range inputFields {
		fields[name] = text
	}
	fields["schemaVersion"], fields["pilotMode"] = jsonshape.IntegerLiteral(1), jsonshape.StringLiteral("non_blocking")
	fields["pilotId"], fields["binarySmokeProbeRuleId"] = id, id
	fields["nonClaims"] = jsonshape.Array(text, 1)
	fields["rollback"] = jsonshape.ObjectFromKeys(rollbackFields, map[string]jsonshape.Shape{
		"dependencyRemoval": jsonshape.StringLiteral("temp_consumer_package_and_lockfile"), "localWorkspaceFallbackPreserved": jsonshape.BooleanLiteral(true),
	})
	fields["releaseAuthorityInput"], fields["witnessPlan"] = jsonshape.Null(), jsonshape.Null()
	input := jsonshape.ObjectFromKeys(inputFields, fields, "releaseAuthorityInput").JSONSchema()
	properties := input["properties"].(map[string]any)
	properties["releaseAuthorityInput"] = map[string]any{}
	// Only this wrapper is parent admission; child failures remain report evidence.
	properties["witnessPlan"] = map[string]any{"type": "object", "additionalProperties": false,
		"required": admit.StringSliceToAny(witnessFields), "properties": map[string]any{
			"commands":   map[string]any{"type": "array", "minItems": 1, "items": map[string]any{}},
			"vocabulary": map[string]any{"type": "object"},
		}}
	packFields := map[string]jsonshape.Shape{}
	for _, name := range packRecordFields {
		packFields[name] = text
	}
	packFields["files"] = jsonshape.Array(jsonshape.ObjectFromKeys(packFileFields, map[string]jsonshape.Shape{"path": text}), 0)
	evidence := jsonshape.ObjectFromKeys(evidenceFields, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(1), "consumerProof": jsonshape.Nullable(proofStructure(false)),
		"tarball": jsonshape.ObjectFromKeys(tarballFields, map[string]jsonshape.Shape{"path": text, "sha1": text, "sha256": text}),
		"packMetadata": jsonshape.ObjectFromKeys(packMetadataFields, map[string]jsonshape.Shape{
			"path": text, "sha256": text, "records": jsonshape.Array(jsonshape.ObjectFromKeys(packRecordFields, packFields), 0),
		}),
	})
	schema := jsonshape.ObjectFromKeys(reportInputFields, map[string]jsonshape.Shape{
		"evidence": evidence, "input": jsonshape.Null(), "schemaVersion": jsonshape.IntegerLiteral(1),
	}).JSONSchema()
	schema["properties"].(map[string]any)["input"] = input
	schema["description"] = "Root input/evidence/header1 are required. Input releaseAuthorityInput is optional arbitrary JSON; rejection by its owner is retained as failed-report evidence. Witness wrapper requires commands (nonempty array of arbitrary JSON) and vocabulary (arbitrary object); child command/vocabulary/plan rejection also yields failed-report evidence. Evidence.consumerProof is required nullable; null yields a failed report. Pack records/files arrays may be empty and then fail semantic evaluation, not input admission. All other fields are required. Raw pilot/probe IDs are boundedASCII; ordinary text trims. Native admission owns fixed package name, exact version, safe paths, normalized unique nonClaims, canonical number spelling and privacy. Evaluation owns digest, artifact, packed inventory, witness and consumer relations. These supplied declarations do not execute consumers or authenticate publication."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	channels := releasechannel.IDSet()
	channels["invalid"] = struct{}{}
	summary := jsonshape.Object(
		jsonshape.Required("consumerProofExecuted", jsonshape.Boolean()), jsonshape.Required("localWorkspaceFallbackPreserved", jsonshape.BooleanLiteral(true)),
		jsonshape.Required("packageName", jsonshape.StringLiteral("@research-engineering/agentic-proofkit")), jsonshape.Required("packageVersion", text),
		jsonshape.Required("pilotMode", jsonshape.StringLiteral("non_blocking")), jsonshape.Required("provenanceArtifactNameHint", text),
		jsonshape.Required("provenanceCommitHint", text), jsonshape.Required("provenanceRepositoryHint", text), jsonshape.Required("provenanceWorkflowRunHint", text),
		jsonshape.Required("releaseAuthorityChannel", jsonshape.Enum(channels)), jsonshape.Required("tarballPath", text),
	)
	artifact := jsonshape.Object(jsonshape.Required("npmIntegrity", text), jsonshape.Required("npmShasum", text), jsonshape.Required("packMetadataPath", text),
		jsonshape.Required("packMetadataSha256", text), jsonshape.Required("tarballPath", text), jsonshape.Required("tarballSha256", text))
	proof := jsonshape.OneOf(jsonshape.Object(jsonshape.Required("executed", jsonshape.BooleanLiteral(false))), proofStructure(true))
	rules := jsonshape.OneOf(jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"),
		jsonshape.StringLiteral(acceptedMessage), jsonshape.Tuple())), jsonshape.Array(report.RuleStructure(
		jsonshape.StringGrammar(regexp.QuoteMeta(failureRulePrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()), 1))
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), summary,
		jsonshape.Tuple(report.DiagnosticStructure("artifactEvidence", artifact), report.DiagnosticStructure("consumerProof", proof)), rules).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes).JSONSchema()
	properties["nonClaims"] = jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	schema["description"] = "Fixed report/header1, eleven summary fields and two ordered diagnostics. consumerProofExecuted reflects supplied proof presence only, not independently observed execution. Absent proof diagnostic contains only executed:false; supplied proof contains all fourteen admitted declarations. releaseAuthorityChannel is invalid after child admission failure, otherwise the admitted release channel. Passed reports contain one fixed accepted rule; failed reports contain nonempty sequential failed rules. Native Build owns dependent relations, state/failure order and sorted deduplicated builtin/caller nonClaims. No publication, authentication, rollout or readiness authority."
	return schema
}
