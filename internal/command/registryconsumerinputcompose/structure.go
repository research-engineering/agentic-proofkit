package registryconsumerinputcompose

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/command/registryconsumer"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputFields = []string{"compositionId", "consumerId", "dependencyName", "dependencySpec", "frozenInstall", "install", "nonClaims", "packageName", "packageVersion", "preconditions", "registryMetadata", "registryPackProof", "registryUrl", "releaseAuthorityInput", "releaseAuthorityReport", "rollback", "rollbackVersionPin", "schemaVersion", "smoke"}
var metadataFields = []string{"packageName", "packageVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}
var packProofFields = []string{"integrityMatches", "nameMatches", "shasumMatches", "versionMatches"}
var lockFields = []string{"dependencySpec", "lockContainsPackage", "lockUsesWorkspace"}
var smokeFields = []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256"}
var releaseReportFields = []string{"outputSha256", "reportKind", "state"}
var rollbackFields = []string{"lockContainsPackage"}
var preconditionFields = []string{"preconditionId", "reason", "state"}
var preconditionStates = map[string]struct{}{"available": {}, "unavailable": {}}

const preconditionRuleID = "proofkit.registry-consumer-proof-input-compose.preconditions"
const acceptedRuleID = "proofkit.registry-consumer-proof-input-compose.accepted"
const acceptedMessage = "registry-consumer input composition is accepted by registry-consumer"
const failureRulePrefix = "proofkit.registry-consumer-proof-input-compose.failure."

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	fields := map[string]jsonshape.Shape{}
	for _, name := range inputFields {
		fields[name] = text
	}
	fields["schemaVersion"], fields["compositionId"], fields["consumerId"] = jsonshape.IntegerLiteral(1), id, id
	fields["nonClaims"] = jsonshape.Array(text, 0)
	fields["registryMetadata"] = jsonshape.ObjectFromKeys(metadataFields, map[string]jsonshape.Shape{
		"packageName": text, "packageVersion": text, "tarballFileName": text, "tarballIntegrity": text, "tarballShasum": text,
	})
	fields["registryPackProof"] = jsonshape.ObjectFromKeys(packProofFields, map[string]jsonshape.Shape{
		"integrityMatches": jsonshape.Boolean(), "nameMatches": jsonshape.Boolean(), "shasumMatches": jsonshape.Boolean(), "versionMatches": jsonshape.Boolean(),
	})
	lock := jsonshape.ObjectFromKeys(lockFields, map[string]jsonshape.Shape{"dependencySpec": text, "lockContainsPackage": jsonshape.Boolean(), "lockUsesWorkspace": jsonshape.Boolean()})
	fields["install"], fields["frozenInstall"] = lock, lock
	fields["smoke"] = jsonshape.ObjectFromKeys(smokeFields, map[string]jsonshape.Shape{"binarySmokeOutputSha256": text, "cliWitnessPlanOutputSha256": text})
	fields["releaseAuthorityReport"] = jsonshape.ObjectFromKeys(releaseReportFields, map[string]jsonshape.Shape{"outputSha256": text, "reportKind": text, "state": text})
	fields["rollback"] = jsonshape.ObjectFromKeys(rollbackFields, map[string]jsonshape.Shape{"lockContainsPackage": jsonshape.Boolean()})
	fields["preconditions"] = jsonshape.Array(jsonshape.ObjectFromKeys(preconditionFields, map[string]jsonshape.Shape{"preconditionId": id, "reason": text, "state": jsonshape.Enum(preconditionStates)}), 1)
	fields["releaseAuthorityInput"] = jsonshape.Null()
	schema := jsonshape.ObjectFromKeys(inputFields, fields, "releaseAuthorityInput").JSONSchema()
	schema["properties"].(map[string]any)["releaseAuthorityInput"] = map[string]any{}
	schema["description"] = "Header1 and eighteen fields other than releaseAuthorityInput are required. releaseAuthorityInput is optional arbitrary JSON: child owner rejection becomes failed-report evidence. NonClaims may be empty; preconditions is nonempty with raw boundedASCII IDs and exact available/unavailable states. Native admission owns sorted unique precondition IDs/nonClaims, package/version/HTTPS/tarball/rollback grammar, lowercase SHA256 smoke/report fields, canonical numeric tokens and privacy. Missing members of the seven required precondition IDs are evaluation failures, while unavailable members block; blockers dominate other semantic failures. Declaration acceptance does not execute package managers or authenticate producers."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	count := jsonshape.IntegerMinimum(0)
	id := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes)
	precondition := report.RuleStructure(jsonshape.StringLiteral(preconditionRuleID), jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}, "blocked": {}}), text, jsonshape.Tuple())
	accepted := report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"), jsonshape.StringLiteral(acceptedMessage), jsonshape.Tuple())
	failure := report.RuleStructure(jsonshape.StringGrammar(regexp.QuoteMeta(failureRulePrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple())
	rules := jsonshape.Array(failure, 1).JSONSchema()
	rules["prefixItems"] = []any{precondition.JSONSchema()}
	schema := jsonshape.Object(
		jsonshape.Required("compositionId", id), jsonshape.Required("compositionKind", jsonshape.StringLiteral(compositionKind)),
		jsonshape.Required("nonClaims", jsonshape.Array(text, len(standardNonClaims))), jsonshape.Required("registryConsumerInput", jsonshape.Null()),
		jsonshape.Required("ruleResults", jsonshape.Null()), jsonshape.Required("schemaVersion", jsonshape.IntegerLiteral(1)),
		jsonshape.Required("state", jsonshape.Enum(map[string]struct{}{"passed": {}, "blocked": {}, "failed": {}})),
		jsonshape.Required("summary", jsonshape.Object(jsonshape.Required("blockedPreconditionCount", count), jsonshape.Required("dependencySpec", text),
			jsonshape.Required("failureCount", count), jsonshape.Required("packageName", text), jsonshape.Required("packageVersion", text), jsonshape.Required("registryUrl", text))),
	).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["ruleResults"] = map[string]any{"oneOf": []any{jsonshape.Tuple(precondition, accepted).JSONSchema(), rules}}
	properties["registryConsumerInput"] = map[string]any{"oneOf": []any{jsonshape.Null().JSONSchema(), registryconsumer.InputStructure()}}
	schema["description"] = "Fixed composition identity/header1 and all eight root fields, six summary fields. Rules begin with the fixed preconditions rule; successful composition adds a fixed accepted rule, otherwise sequential semantic failure rules follow (possibly none). registryConsumerInput is required nullable and uses the registry consumer owner's complete input structure when materialized. Native Build materializes it only for passed composition after registryconsumer.Build passes, prioritizes blocked over failed, and owns counter/rule/state relations. Builtin/caller nonClaims are sorted and deduplicated. No consumer execution, registry access, freshness or merge/release/readiness approval."
	return schema
}
