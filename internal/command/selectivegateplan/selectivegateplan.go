package selectivegateplan

func Build(raw any) (map[string]any, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return nil, 1, err
	}
	plan := buildPlan(input)
	exitCode := 0
	if plan["planState"] == "fail_closed" {
		exitCode = 1
	}
	return plan, exitCode, nil
}
