package requirementspectree

import "github.com/research-engineering/agentic-proofkit/internal/kernel/report"

func Build(raw any) (report.Record, int, error) {
	input, err := admitInput(raw)
	if err != nil {
		return report.Record{}, 1, err
	}
	validation := validate(input)
	record := buildRecord(input, validation)
	if record.State == "passed" {
		return record, 0, nil
	}
	return record, 1, nil
}
