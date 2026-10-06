package releaseauthority

import (
	"fmt"
	"regexp"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/jsonshape"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
)

var inputFields = []string{"artifactProof", "channel", "consumerContract", "nonClaims", "package", "registryAuthority", "releaseId", "rollback", "rolloutClaim", "schemaVersion"}
var packageFields = []string{"artifactPath", "manifestPrivate", "name", "packageManagerLockfile", "packManifestPath", "publishConfigRegistry", "version"}
var artifactProofFields = []string{"cliSmokeProofId", "deepImportRejectionProofId", "outsideConsumerInstallProofId", "packageArtifactCommandId", "packDryRunCommandId", "registryPublishDryRunProofId", "binarySmokeProofId"}
var consumerFields = []string{"dependencyPinType", "lockfileRequired", "binarySmokeOnly", "siblingSourceCheckoutAllowed"}
var legacyRegistryFields = []string{"consumerMigrationPath", "packageScope", "provenanceMode", "publishWorkflowPath", "registryKind", "registryUrl", "releaseTagPattern", "rollbackPolicy", "visibility"}
var registryFields = []string{"consumerMigrationPath", "packageScope", "publishAuthorityMode", "publishWorkflowPath", "registryKind", "registryUrl", "releaseTagPattern", "rollbackPolicy", "sourceRepository", "visibility"}
var sourceRepositoryFields = []string{"name", "owner", "url", "visibility"}
var rollbackFields = []string{"owner", "procedure", "versionPin"}

const acceptedRuleID = "proofkit.release-authority.accepted"
const acceptedMessage = "release authority is explicit and bounded to the selected channel"
const failureRulePrefix = "proofkit.release-authority.failure."

func registryInputStructure(version int64) jsonshape.Shape {
	text := jsonshape.NonBlankString()
	fields := map[string]jsonshape.Shape{
		"consumerMigrationPath": text, "packageScope": jsonshape.OneOf(jsonshape.StringLiteral(""), text),
		"publishWorkflowPath": text, "registryKind": jsonshape.Enum(registryKinds), "registryUrl": text,
		"releaseTagPattern": text, "rollbackPolicy": text, "visibility": jsonshape.Enum(releaseVisibilities),
	}
	if version == 1 {
		fields["provenanceMode"] = jsonshape.Enum(provenanceModes)
		return jsonshape.ObjectFromKeys(legacyRegistryFields, fields)
	}
	fields["publishAuthorityMode"] = jsonshape.Enum(publisherAuthorityModes)
	fields["sourceRepository"] = jsonshape.ObjectFromKeys(sourceRepositoryFields, map[string]jsonshape.Shape{
		"name": text, "owner": text, "url": text, "visibility": jsonshape.Enum(sourceRepositoryVisibilities),
	})
	return jsonshape.ObjectFromKeys(registryFields, fields)
}

func InputStructure(version int64) (map[string]any, error) {
	if version < 1 || version > 3 {
		return nil, fmt.Errorf("release authority structural version must be one of: 1, 2, 3")
	}
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	artifactFields := map[string]jsonshape.Shape{}
	for _, field := range artifactProofFields {
		artifactFields[field] = id
	}
	schema := jsonshape.ObjectFromKeys(inputFields, map[string]jsonshape.Shape{
		"schemaVersion": jsonshape.IntegerLiteral(version), "releaseId": id, "channel": jsonshape.Enum(releasechannel.IDSet()),
		"rolloutClaim": jsonshape.Boolean(), "nonClaims": jsonshape.Array(text, 1),
		"package": jsonshape.ObjectFromKeys(packageFields, map[string]jsonshape.Shape{
			"artifactPath": text, "manifestPrivate": jsonshape.Boolean(), "name": text, "packageManagerLockfile": text,
			"packManifestPath": text, "publishConfigRegistry": jsonshape.Nullable(text), "version": text,
		}, "publishConfigRegistry"),
		"artifactProof": jsonshape.ObjectFromKeys(artifactProofFields, artifactFields, "registryPublishDryRunProofId"),
		"consumerContract": jsonshape.ObjectFromKeys(consumerFields, map[string]jsonshape.Shape{
			"dependencyPinType": jsonshape.Enum(dependencyPinTypes), "lockfileRequired": jsonshape.Boolean(),
			"binarySmokeOnly": jsonshape.Boolean(), "siblingSourceCheckoutAllowed": jsonshape.Boolean(),
		}),
		"registryAuthority": jsonshape.Nullable(registryInputStructure(version)),
		"rollback":          jsonshape.ObjectFromKeys(rollbackFields, map[string]jsonshape.Shape{"owner": text, "procedure": text, "versionPin": text}),
	}).JSONSchema()
	schema["description"] = "Payload headers1,2,3 are existing variants of aggregate input contract1. Ten root fields are required; registryAuthority is required nullable. Package publishConfigRegistry is optional nullable; registryPublishDryRunProofId is optional but present null is rejected. Registry header1 uses provenanceMode; headers2/3 use publishAuthorityMode and required nonnull sourceRepository. IDs are raw boundedASCII; other text trims. NonClaims is nonempty and rejects normalized duplicates. Native admission owns npm names, exact semversion, HTTPS/path/scope grammars, lowercased GitHub identity and URL equality, privacy and canonical numeric tokens. Native evaluation owns channel, registry, consumer, package and publisher relations: violations may produce failed reports rather than malformed-input errors. No declaration authenticates publication, credentials, consumer execution or rollout."
	return schema, nil
}

func OutputStructure() map[string]any {
	id, text := jsonshape.BoundedStringGrammar(admit.RuleIDPatternBody, admit.MaxRuleIDBytes), jsonshape.NonBlankString()
	status := jsonshape.Enum(map[string]struct{}{"passed": {}, "failed": {}})
	artifactFields := map[string]jsonshape.Shape{}
	for _, field := range artifactProofFields {
		artifactFields[field] = id
	}
	registry := jsonshape.OneOf(jsonshape.Object(jsonshape.Required("declared", jsonshape.BooleanLiteral(false))),
		jsonshape.Object(jsonshape.Required("declared", jsonshape.BooleanLiteral(true)), jsonshape.Required("packageScope", jsonshape.String()),
			jsonshape.Required("publishAuthorityMode", jsonshape.Enum(publisherAuthorityModes)), jsonshape.Required("publishWorkflowPath", text),
			jsonshape.Required("registryKind", jsonshape.Enum(registryKinds)), jsonshape.Required("registryUrl", text),
			jsonshape.Required("sourceRepository", jsonshape.Nullable(jsonshape.Object(jsonshape.Required("name", text), jsonshape.Required("owner", text),
				jsonshape.Required("visibility", jsonshape.Enum(sourceRepositoryVisibilities))))), jsonshape.Required("visibility", jsonshape.Enum(releaseVisibilities))))
	summary := jsonshape.Object(jsonshape.Required("channel", jsonshape.Enum(releasechannel.IDSet())), jsonshape.Required("dependencyPinType", jsonshape.Enum(dependencyPinTypes)),
		jsonshape.Required("manifestPrivate", jsonshape.Boolean()), jsonshape.Required("packageName", text), jsonshape.Required("packageVersion", text),
		jsonshape.Required("registryAuthorityDeclared", jsonshape.Boolean()), jsonshape.Required("rolloutClaim", jsonshape.Boolean()))
	rules := jsonshape.OneOf(jsonshape.Tuple(report.RuleStructure(jsonshape.StringLiteral(acceptedRuleID), jsonshape.StringLiteral("passed"),
		jsonshape.StringLiteral(acceptedMessage), jsonshape.Tuple())), jsonshape.Array(report.RuleStructure(
		jsonshape.StringGrammar(regexp.QuoteMeta(failureRulePrefix)+`[0-9]{3,}`), jsonshape.StringLiteral("failed"), text, jsonshape.Tuple()), 1))
	schema := report.Structure(1, reportKind, status, summary, jsonshape.Tuple(
		report.DiagnosticStructure("artifactProof", jsonshape.ObjectFromKeys(artifactProofFields, artifactFields, "registryPublishDryRunProofId")),
		report.DiagnosticStructure("consumerContract", jsonshape.Object(jsonshape.Required("dependencyPinType", jsonshape.Enum(dependencyPinTypes)),
			jsonshape.Required("inputBinarySmokeOnly", jsonshape.Boolean()), jsonshape.Required("inputLockfileRequired", jsonshape.Boolean()),
			jsonshape.Required("inputSiblingSourceCheckoutAllowed", jsonshape.Boolean()))),
		report.DiagnosticStructure("packageArtifact", jsonshape.Object(jsonshape.Required("artifactPath", text), jsonshape.Required("packageManagerLockfile", text), jsonshape.Required("packManifestPath", text))),
		report.DiagnosticStructure("registryAuthority", registry),
		report.DiagnosticStructure("rollback", jsonshape.ObjectFromKeys(rollbackFields, map[string]jsonshape.Shape{"owner": text, "procedure": text, "versionPin": text})),
	), rules).JSONSchema()
	properties := schema["properties"].(map[string]any)
	properties["reportId"] = id.JSONSchema()
	nonClaims := jsonshape.Array(text, len(boundaryNonClaims)).JSONSchema()
	contains := make([]any, 0, len(boundaryNonClaims))
	for _, claim := range boundaryNonClaims {
		contains = append(contains, map[string]any{"contains": map[string]any{"const": claim}})
	}
	nonClaims["allOf"], nonClaims["uniqueItems"], properties["nonClaims"] = contains, true, nonClaims
	schema["description"] = "Header1 and fixed release-authority report identity are required. Seven summary fields and five ordered diagnostic entries describe admitted caller declarations. registryAuthority has either only declared:false or a complete declared:true record; sourceRepository diagnostics are nullable and omit the admitted URL. Optional registry dry-run proof remains absent when undeclared. Passed reports have one fixed accepted rule; failed reports have nonempty sequential failed rules with empty diagnostics. Native Build owns state, failure order and all dependent relations. Builtin/caller nonClaims are sorted and deduplicated. This report proves no publication, authentication, consumer installation, rollout or operational readiness."
	return schema
}
