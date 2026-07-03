package app

import "fmt"

func parseInputOnlyArgs(command string, args []string) (string, string, error) {
	inputPath := ""
	inputPointer := ""
	inputPointerSeen := false
	for index := 0; index < len(args); index++ {
		switch args[index] {
		case "--input":
			if inputPath != "" || index+1 >= len(args) || args[index+1] == "" {
				return "", "", fmt.Errorf("%s requires --input <path|->", command)
			}
			inputPath = args[index+1]
			index++
		case "--input-pointer":
			if inputPointerSeen || index+1 >= len(args) {
				return "", "", fmt.Errorf("--input-pointer requires a JSON pointer")
			}
			inputPointerSeen = true
			inputPointer = args[index+1]
			index++
		default:
			return "", "", fmt.Errorf("unsupported argument for %s: %s", command, args[index])
		}
	}
	if inputPath == "" {
		return "", "", fmt.Errorf("%s requires --input <path|->", command)
	}
	if command == "self-check" && inputPointerSeen {
		return "", "", fmt.Errorf("self-check does not support --input-pointer")
	}
	return inputPath, inputPointer, nil
}

func stringSliceToAny(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}
