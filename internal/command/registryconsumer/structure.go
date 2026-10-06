package registryconsumer

import (
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var reportInputFields = []string{"input", "proof", "schemaVersion"}
var inputFields = []string{"consumerId", "dependencyName", "dependencySpec", "nonClaims", "packageName", "packageVersion", "registryUrl", "releaseAuthorityInput", "rollbackVersionPin", "schemaVersion", "tarballFileName", "tarballIntegrity", "tarballShasum"}
var proofFields = []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256", "dependencySpec", "frozenLockContainsPackage", "frozenLockUsesWorkspace", "installLockContainsPackage", "installLockUsesWorkspace", "registryPackIntegrityMatches", "registryPackNameMatches", "registryPackShasumMatches", "registryPackVersionMatches", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState", "rollbackLockContainsPackage", "tempConsumerLocation"}

const acceptedRuleID = "proofkit.registry-consumer.accepted"
const acceptedMessage = "registry consumer install proof accepted"
const failureRulePrefix = "proofkit.registry-consumer.failure."

func proofStructure(output bool) jsonshape.Shape {
	text := jsonshape.NonBlankString()
	fields := map[string]jsonshape.Shape{}
	for _, name := range proofFields {
		fields[name] = jsonshape.Boolean()
	}
	for _, name := range []string{"binarySmokeOutputSha256", "cliWitnessPlanOutputSha256", "dependencySpec", "releaseAuthorityOutputSha256", "releaseAuthorityReportKind", "releaseAuthorityState"} {
		fields[name] = text
	}
	fields["tempConsumerLocation"] = text
	if output {
		fields["tempConsumerLocation"] = jsonshape.StringLiteral("os-temp")
	}
	return jsonshape.ObjectFromKeys(proofFields, fields)
}

func InputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	fields := map[string]jsonshape.Shape{}
	for _, name := range inputFields {
		fields[name] = text
	}
	fields["schemaVersion"], fields["nonClaims"] = jsonshape.IntegerLiteral(1), jsonshape.Array(text, 1)
	// Child rejection is report evidence, not rejection of the parent carrier.
	fields["releaseAuthorityInput"] = jsonshape.Null()
	input := jsonshape.ObjectFromKeys(inputFields, fields, "releaseAuthorityInput").JSONSchema()
	input["properties"].(map[string]any)["releaseAuthorityInput"] = map[string]any{}
	schema := jsonshape.ObjectFromKeys(reportInputFields, map[string]jsonshape.Shape{
		"input": jsonshape.Null(), "proof": jsonshape.Nullable(proofStructure(false)), "schemaVersion": jsonshape.IntegerLiteral(1),
	}, "proof").JSONSchema()
	schema["properties"].(map[string]any)["input"] = input
	schema["description"] = "Root input and schemaVersion1 are required; proof is optional nullable and absent/null yields a failed report. Inner releaseAuthorityInput is optional arbitrary JSON: the release owner admits it and parent evaluation retains rejection as failed-report evidence. Other inner fields and all present proof fields are required. ConsumerId is ordinary unbounded trimmed text, not RuleID. Native admission owns package/version/HTTPS/tarball/rollback grammars, canonical number spelling, privacy and normalized nonClaims uniqueness. Digest, integrity, dependency, release and lock relations are evaluation constraints: structurally admitted invalid declarations may emit failed reports. No registry fetch, authentication or native execution occurs."
	return schema
}

func OutputStructure() map[string]any {
	text := jsonshape.NonBlankString()
	summary := jsonshape.Object(jsonshape.Required("consumerId", text), jsonshape.Required("dependencyName", text),
		jsonshape.Required("dependencySpec", text), jsonshape.Required("packageName", text), jsonshape.Required("packageVersion", text), jsonshape.Required("registryUrl", text))
	proof := proofStructure(true).JSONSchema()
	properties := proof["properties"].(map[string]any)
	for _, name := range []string{"dependencySpec", "registryPackIntegrityMatches", "registryPackNameMatches", "registryPackShasumMatches", "registryPackVersionMatches"} {
		delete(properties, name)
	}
	required := []any{}
	for _, name := range proofFields {
		if _, exists := properties[name]; exists {
			required = append(required, name)
		}
	}
	proof["required"] = required
	rules := jsonshape.OneOf(jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"),
		jsonshape.StringLiteral(acceptedMessage), jsonshape.Tuple())), jsonshape.Array(report.RuleStructure(
		jsonshape.StringGrammar(regexp.QuoteMeta(failureRulePrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()), 1))
	schema := report.Structure(1, reportKind, jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}}), summary,
		jsonshape.Tuple(report.DiagnosticStructure("consumerProof", jsonshape.Null()), report.DiagnosticStructure("registryArtifact",
			jsonshape.Object(jsonshape.Required("tarballFileName", text), jsonshape.Required("tarballIntegrity", text), jsonshape.Required("tarballShasum", text)))), rules).JSONSchema()
	schema["properties"].(map[string]any)["diagnostics"].(map[string]any)["prefixItems"].([]any)[0].(map[string]any)["properties"].(map[string]any)["value"] = map[string]any{"oneOf": []any{
		jsonshape.Object(jsonshape.Required("executed", jsonshape.BooleanLiteral(false))).JSONSchema(), proof,
	}}
	schema["description"] = "Fixed report identity/header1, six summary fields and two ordered diagnostics. Absent proof emits only executed:false; supplied proof emits eleven admitted declarations without an executed flag. Presence does not authenticate execution. Passed reports have one fixed accepted rule; failed reports have nonempty sequential failed rules. Native Build owns state, failure order, sorted deduplicated builtin/caller nonClaims and dependent relations. No registry freshness, rollout or readiness claim."
	schema["properties"].(map[string]any)["reportId"] = text.JSONSchema()
	schema["properties"].(map[string]any)["nonClaims"] = jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	return schema
}
