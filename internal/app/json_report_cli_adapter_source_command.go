package app

import "fmt"

func parseJSONReportCLIAdapterSourceArgs(args []string) (string, string, error) {
	language := ""
	format := "json"
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--language":
			if language != "" || index+1 >= len(args) || args[index+1] == "" {
				return "", "", fmt.Errorf("json-report-cli-adapter-source requires --language typescript")
			}
			language = args[index+1]
			index++
		case "--format":
			if index+1 >= len(args) || args[index+1] == "" {
				return "", "", fmt.Errorf("--format requires json")
			}
			format = args[index+1]
			index++
		case "--input", "--input-pointer":
			return "", "", fmt.Errorf("%s is not valid for json-report-cli-adapter-source", args[index])
		default:
			return "", "", fmt.Errorf("unsupported argument for json-report-cli-adapter-source: %s", args[index])
		}
	}
	if language == "" {
		return "", "", fmt.Errorf("json-report-cli-adapter-source requires --language typescript")
	}
	if language != "typescript" {
		return "", "", fmt.Errorf("--language must be typescript")
	}
	if format != "json" {
		return "", "", fmt.Errorf("--format must be json")
	}
	return language, format, nil
}
