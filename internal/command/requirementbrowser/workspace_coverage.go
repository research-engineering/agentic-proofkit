package requirementbrowser

import "github.com/research-engineering/agentic-proofkit/internal/command/requirementcoverageview"

// Coverage joins admitted rows after the shared filter algebra. The membership
// scan counts the complete matching cohort; only item candidates are cloned.
func workspaceCoveragePage(session *workspaceSession, query workspaceLookupQuery) workspacePage {
	matches := session.Lookup.matchingRequirements(query)
	matchingIDs := make(map[string]struct{}, len(matches))
	for _, position := range matches {
		matchingIDs[session.Lookup.Rows[position].Requirement.RequirementID] = struct{}{}
	}
	coverage := session.Snapshot.Coverage
	reported := requirementcoverageview.CountSelectedRequirements(coverage, matchingIDs)
	start := min(query.Page.Offset, len(matches))
	end := start + min(query.Page.MaxRecords, len(matches)-start)
	candidates := make(map[string]struct{}, end-start)
	for _, position := range matches[start:end] {
		candidates[session.Lookup.Rows[position].Requirement.RequirementID] = struct{}{}
	}
	fragment := requirementcoverageview.SelectRequirements(coverage, candidates)
	byID := make(map[string]any, len(candidates))
	for _, raw := range fragment["requirementCoverage"].([]any) {
		byID[raw.(map[string]any)["requirementId"].(string)] = raw
	}
	page := workspaceRequirementPage(session.Lookup, matches, query.Page)
	requirementRow, requirementProjection := page.Row, page.Projection
	page.Row = func(position int) map[string]any {
		row := requirementRow(position)
		row["coverage"] = byID[row["requirementId"].(string)]
		return row
	}
	page.Projection = func(rows []any) (map[string]any, string) {
		projection, state := requirementProjection(rows)
		projection["projectionKind"] = "proofkit.requirement-browser-coverage-fragment"
		projection["coverageAuthority"] = fragment["authority"]
		projection["nonClaims"] = coverage["nonClaims"]
		projection["proofMode"] = coverage["proofMode"]
		projection["sourceViewInputId"] = fragment["sourceViewInputId"]
		projection["matchingReportedRequirementCount"] = reported
		projection["matchingNotReportedRequirementCount"] = len(matches) - reported
		return projection, state
	}
	return page
}
