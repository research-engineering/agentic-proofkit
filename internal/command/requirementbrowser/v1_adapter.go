package requirementbrowser

func admitV1WorkspaceInput(record map[string]any) error {
	return requireWorkspaceNestedVersions(record, 1)
}
