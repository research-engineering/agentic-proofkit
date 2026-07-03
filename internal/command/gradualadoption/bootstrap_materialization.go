package gradualadoption

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

func BuildBootstrapMaterializationManifest(raw any) (map[string]any, int, error) {
	result, err := buildBootstrap(raw)
	if err != nil {
		return nil, 1, err
	}
	manifest, err := BootstrapMaterializationManifest(result)
	if err != nil {
		return nil, 1, err
	}
	return manifest, result.ExitCode, nil
}

func BuildBootstrapMaterializationManifestFromContractEnvelope(raw any) (map[string]any, int, error) {
	input, err := BootstrapInputFromContractEnvelope(raw)
	if err != nil {
		return nil, 1, err
	}
	return BuildBootstrapMaterializationManifest(input)
}

func BootstrapMaterializationManifest(result BootstrapResult) (map[string]any, error) {
	files := make([]any, 0, len(result.PlannedFiles))
	payloadFileCount := 0
	for _, rawFile := range result.PlannedFiles {
		file := rawFile.(map[string]any)
		payloadKey, _ := file["payloadKey"].(string)
		if payloadKey == "" {
			files = append(files, map[string]any{
				"content":               nil,
				"contentKind":           "caller_owned",
				"contentSha256":         nil,
				"materializationStatus": "caller_content_required",
				"nonClaims": []any{
					"Proofkit identifies this caller-owned file but does not provide authoritative content for it.",
					"The consuming repository must review or author this file before treating it as created.",
				},
				"path":       file["path"],
				"payloadKey": nil,
				"purpose":    file["purpose"],
			})
			continue
		}
		payload, ok := result.Payloads[payloadKey]
		if !ok {
			return nil, fmt.Errorf("bootstrap payload missing for planned file: %s", payloadKey)
		}
		content, err := stablejson.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadFileCount++
		files = append(files, map[string]any{
			"content":               string(content),
			"contentKind":           "json",
			"contentSha256":         digest.SHA256TextRef(string(content)),
			"materializationStatus": "payload_available",
			"nonClaims": []any{
				"Proofkit provides deterministic starter content only.",
				"The consuming repository must review the content before writing or committing it.",
			},
			"path":       file["path"],
			"payloadKey": payloadKey,
			"purpose":    file["purpose"],
		})
	}
	reportHash, err := digest.StableJSONSHA256Ref(result.Record.JSONValue())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fileCount":    len(files),
		"files":        files,
		"manifestId":   result.Record.ReportID + ".materialization-manifest",
		"manifestKind": "proofkit.gradual-adoption-bootstrap-materialization-manifest",
		"nextCommands": stringSliceAny(result.NextCommands),
		"nonClaims": []any{
			"Bootstrap materialization manifests do not write files.",
			"Bootstrap materialization manifests do not prove files exist in the consuming repository.",
			"Bootstrap materialization manifests do not execute native witnesses.",
			"Bootstrap materialization manifests do not approve merge, enforcement promotion, rollout, or product readiness.",
		},
		"payloadFileCount": payloadFileCount,
		"schemaVersion":    1,
		"sourceReport": map[string]any{
			"nonClaim":   "Source report identity does not prove file creation, file freshness, or caller approval.",
			"reportId":   result.Record.ReportID,
			"reportKind": result.Record.ReportKind,
			"stableHash": reportHash,
			"state":      result.Record.State,
		},
	}, nil
}

func stringSliceAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
