package projectstructure

import (
	"fmt"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/report"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
)

type projectPathSet struct {
	bootstrapInputPath           string
	repoProfileScaffoldInputPath string
	workflowInputPath            string
}

type materializationInput struct {
	adoptionWorkflowInput map[string]any
	bootstrapInput        map[string]any
	bootstrapManifest     map[string]any
	paths                 projectPathSet
	repoProfileInput      map[string]any
	repoProfilePlan       map[string]any
	scaffoldID            string
	sourceReports         []report.Record
}

func projectPaths(raw any) (projectPathSet, error) {
	record, err := object(raw, "project structure scaffold paths")
	if err != nil {
		return projectPathSet{}, err
	}
	repoProfileScaffoldInputPath, err := safePath(record["repoProfileScaffoldInputPath"], "project structure scaffold repoProfileScaffoldInputPath")
	if err != nil {
		return projectPathSet{}, err
	}
	bootstrapInputPath, err := safePath(record["bootstrapInputPath"], "project structure scaffold bootstrapInputPath")
	if err != nil {
		return projectPathSet{}, err
	}
	workflowInputPath, err := safePath(record["workflowInputPath"], "project structure scaffold workflowInputPath")
	if err != nil {
		return projectPathSet{}, err
	}
	return projectPathSet{
		bootstrapInputPath:           bootstrapInputPath,
		repoProfileScaffoldInputPath: repoProfileScaffoldInputPath,
		workflowInputPath:            workflowInputPath,
	}, nil
}

func buildMaterializationManifest(input materializationInput) (map[string]any, error) {
	files := []map[string]any{}
	repoProfileFile, err := payloadFile(input.paths.repoProfileScaffoldInputPath, "caller-owned repo-profile scaffold input", "project_scaffold", input.repoProfileInput, nil)
	if err != nil {
		return nil, err
	}
	bootstrapFile, err := payloadFile(input.paths.bootstrapInputPath, "caller-owned gradual adoption bootstrap input", "project_scaffold", input.bootstrapInput, nil)
	if err != nil {
		return nil, err
	}
	workflowFile, err := payloadFile(input.paths.workflowInputPath, "caller-owned adoption workflow input", "project_scaffold", input.adoptionWorkflowInput, nil)
	if err != nil {
		return nil, err
	}
	files = append(files, repoProfileFile, bootstrapFile, workflowFile)
	profilePath := stringValue(input.repoProfilePlan["profilePath"])
	for _, rawFile := range anyArray(input.bootstrapManifest["files"]) {
		file := mapValue(rawFile)
		if stringValue(file["path"]) == profilePath {
			profilePayload, err := payloadFile(
				stringValue(file["path"]),
				"caller-reviewed repository profile draft",
				"repo_profile_scaffold",
				input.repoProfilePlan["repoProfileDraft"],
				[]any{
					"Repository profile draft content is starter content only.",
					"The consuming repository must review final profile policy before admitting it.",
				},
			)
			if err != nil {
				return nil, err
			}
			files = append(files, profilePayload)
			continue
		}
		files = append(files, map[string]any{
			"content":               file["content"],
			"contentKind":           file["contentKind"],
			"contentSha256":         file["contentSha256"],
			"materializationStatus": file["materializationStatus"],
			"nonClaims":             file["nonClaims"],
			"path":                  file["path"],
			"purpose":               file["purpose"],
			"source":                "bootstrap_manifest",
		})
	}
	sort.Slice(files, func(left int, right int) bool {
		return stringValue(files[left]["path"]) < stringValue(files[right]["path"])
	})
	if err := assertUniquePaths(files); err != nil {
		return nil, err
	}
	payloadFileCount := 0
	callerContentRequiredCount := 0
	for _, file := range files {
		if file["materializationStatus"] == "payload_available" {
			payloadFileCount++
		}
		if file["materializationStatus"] == "caller_content_required" {
			callerContentRequiredCount++
		}
	}
	nextCommands := []any{
		cliexec.DisplayCommand("scaffold-profile-plan", "--input", input.paths.repoProfileScaffoldInputPath),
		cliexec.DisplayCommand("gradual-adoption-bootstrap", "--input", input.paths.bootstrapInputPath),
		cliexec.DisplayCommand("adoption-workflow-plan", "--input", input.paths.workflowInputPath),
	}
	nextCommands = append(nextCommands, anyArray(input.bootstrapManifest["nextCommands"])...)
	return map[string]any{
		"callerContentRequiredCount": callerContentRequiredCount,
		"fileCount":                  len(files),
		"files":                      mapsToAny(files),
		"manifestId":                 input.scaffoldID + ".materialization-manifest",
		"manifestKind":               "proofkit.project-structure-scaffold-materialization-manifest",
		"nextCommands":               nextCommands,
		"nonClaims": []any{
			"Project-structure materialization manifests do not write files.",
			"Project-structure materialization manifests do not prove files exist in the consuming repository.",
			"Project-structure materialization manifests do not execute native witnesses.",
			"Project-structure materialization manifests do not approve merge, enforcement promotion, release, rollout, or product readiness.",
		},
		"payloadFileCount": payloadFileCount,
		"schemaVersion":    1,
		"sourceReports":    sourceReportRefs(input.sourceReports),
	}, nil
}

func payloadFile(path string, purpose string, source string, payload any, nonClaims []any) (map[string]any, error) {
	safe, err := admit.SafeRepoRelativePath(path, "project structure scaffold file path")
	if err != nil {
		return nil, err
	}
	contentBytes, err := stablejson.Marshal(payload)
	if err != nil {
		return nil, err
	}
	content := string(contentBytes)
	if nonClaims == nil {
		nonClaims = []any{
			"Proofkit provides deterministic starter content only.",
			"The consuming repository must review the content before writing or committing it.",
		}
	}
	return map[string]any{
		"content":               content,
		"contentKind":           "json",
		"contentSha256":         digest.SHA256TextRef(content),
		"materializationStatus": "payload_available",
		"nonClaims":             nonClaims,
		"path":                  safe,
		"purpose":               purpose,
		"source":                source,
	}, nil
}

func sourceReportRefs(records []report.Record) []any {
	values := make([]any, 0, len(records))
	for _, record := range records {
		hash, _ := digest.StableJSONSHA256Ref(record.JSONValue())
		values = append(values, map[string]any{
			"nonClaim":   "Source report identity does not prove file creation, file freshness, or caller approval.",
			"reportId":   record.ReportID,
			"reportKind": record.ReportKind,
			"stableHash": hash,
			"state":      record.State,
		})
	}
	return values
}

func materializationManifestSummary(manifest map[string]any) map[string]any {
	files := []any{}
	for _, rawFile := range anyArray(manifest["files"]) {
		file := mapValue(rawFile)
		files = append(files, map[string]any{
			"contentSha256":         file["contentSha256"],
			"materializationStatus": file["materializationStatus"],
			"path":                  file["path"],
			"source":                file["source"],
		})
	}
	return map[string]any{
		"callerContentRequiredCount": manifest["callerContentRequiredCount"],
		"fileCount":                  manifest["fileCount"],
		"files":                      files,
		"manifestId":                 manifest["manifestId"],
		"payloadFileCount":           manifest["payloadFileCount"],
	}
}

func assertUniquePaths(files []map[string]any) error {
	seen := map[string]struct{}{}
	for _, file := range files {
		path := stringValue(file["path"])
		if path == "" {
			return fmt.Errorf("project structure scaffold file paths must be sorted and unique")
		}
		if _, ok := seen[path]; ok {
			return fmt.Errorf("project structure scaffold file paths must be sorted and unique")
		}
		seen[path] = struct{}{}
	}
	return nil
}

func projectStructureFilePurpose(file map[string]any) string {
	hashSuffix := ""
	if hash, ok := file["contentSha256"].(string); ok && hash != "" {
		hashSuffix = " Content hash: " + hash + "."
	}
	return fmt.Sprintf("%s; materialization status %s.%s", file["purpose"], file["materializationStatus"], hashSuffix)
}

func projectStructureFileRole(file map[string]any) string {
	filePath := stringValue(file["path"])
	purpose := stringValue(file["purpose"])
	switch {
	case strings.Contains(filePath, "requirement-proof") || strings.Contains(purpose, "proof binding"):
		return "proof_binding"
	case strings.Contains(filePath, "witness") || strings.Contains(filePath, "workflow") || strings.Contains(purpose, "workflow"):
		return "command_registry"
	case strings.Contains(filePath, "spec") || strings.Contains(purpose, "spec"):
		return "spec_source"
	case strings.Contains(filePath, "profile") || strings.Contains(purpose, "repository profile"):
		return "owner_surface"
	case strings.Contains(filePath, "adoption-guidance"):
		return "router"
	default:
		return "supporting"
	}
}
