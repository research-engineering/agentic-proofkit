package cliexec

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	BinaryName                  = "agentic-proofkit"
	LauncherProfileEnvironment  = "AGENTIC_PROOFKIT_LAUNCHER_PROFILE"
	PythonExecutableEnvironment = "AGENTIC_PROOFKIT_PYTHON_EXECUTABLE"

	ProfileNPMOffline   = "npm_offline"
	ProfilePath         = "path"
	ProfilePythonModule = "python_module"
)

type Renderer struct {
	profile          string
	pythonExecutable string
}

func PathRenderer() Renderer {
	return Renderer{profile: ProfilePath}
}

func AdmitLauncherProfile(profile string, pythonExecutable string) (Renderer, error) {
	switch profile {
	case "", ProfilePath:
		if pythonExecutable != "" {
			return Renderer{}, fmt.Errorf("%s must be empty unless %s is %s", PythonExecutableEnvironment, LauncherProfileEnvironment, ProfilePythonModule)
		}
		return PathRenderer(), nil
	case ProfileNPMOffline:
		if pythonExecutable != "" {
			return Renderer{}, fmt.Errorf("%s must be empty unless %s is %s", PythonExecutableEnvironment, LauncherProfileEnvironment, ProfilePythonModule)
		}
		return Renderer{profile: ProfileNPMOffline}, nil
	case ProfilePythonModule:
		if pythonExecutable == "" || !filepath.IsAbs(pythonExecutable) {
			return Renderer{}, fmt.Errorf("%s must be a non-empty absolute path when %s is %s", PythonExecutableEnvironment, LauncherProfileEnvironment, ProfilePythonModule)
		}
		if admit.ContainsSecretLikeValue(pythonExecutable) || strings.IndexFunc(pythonExecutable, isControlOrFormat) >= 0 {
			return Renderer{}, fmt.Errorf("%s must not contain secret-like or control values", PythonExecutableEnvironment)
		}
		return Renderer{profile: ProfilePythonModule, pythonExecutable: pythonExecutable}, nil
	default:
		return Renderer{}, fmt.Errorf("%s must be empty, %s, %s, or %s", LauncherProfileEnvironment, ProfilePath, ProfileNPMOffline, ProfilePythonModule)
	}
}

func isControlOrFormat(character rune) bool {
	return unicode.In(character, unicode.Cc, unicode.Cf)
}

func (renderer Renderer) Profile() string {
	if renderer.profile == "" {
		return ProfilePath
	}
	return renderer.profile
}

func (renderer Renderer) DisplayCommand(args ...string) string {
	return DisplayArgv(renderer.Argv(args...))
}

func DisplayArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, value := range argv {
		parts = append(parts, shellQuote(value))
	}
	return strings.Join(parts, " ")
}

func (renderer Renderer) Argv(args ...string) []string {
	argv := renderer.invocationPrefix()
	return append(argv, args...)
}

func DisplayCommand(args ...string) string {
	return PathRenderer().DisplayCommand(args...)
}

func (renderer Renderer) invocationPrefix() []string {
	switch renderer.Profile() {
	case ProfileNPMOffline:
		return []string{"npm", "exec", "--offline", "--", BinaryName}
	case ProfilePythonModule:
		return []string{renderer.pythonExecutable, "-m", "agentic_proofkit"}
	default:
		return []string{BinaryName}
	}
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
