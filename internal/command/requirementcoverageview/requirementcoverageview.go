package requirementcoverageview

func BuildJSON(raw any, options Options) (any, int, error) {
	view, err := build(raw)
	if err != nil {
		return nil, 1, err
	}
	if options.AgentEnvelope {
		return agentEnvelope(view), exitCode(view), nil
	}
	return view, exitCode(view), nil
}
func BuildMarkdown(raw any) (string, int, error) {
	view, err := build(raw)
	if err != nil {
		return "", 1, err
	}
	return markdown(view) + "\n", exitCode(view), nil
}
func BuildHTML(raw any) (string, int, error) {
	view, err := build(raw)
	if err != nil {
		return "", 1, err
	}
	return html(view), exitCode(view), nil
}
