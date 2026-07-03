package cliexec

import "strings"

const BinaryName = "agentic-proofkit"

func DisplayCommand(args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, BinaryName)
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(value string) string {
	if shellSafeToken(value) {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func shellSafeToken(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case strings.ContainsRune("-._/:=@%+,", character):
		default:
			return false
		}
	}
	return true
}
