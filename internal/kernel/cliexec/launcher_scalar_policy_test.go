package cliexec

import (
	"reflect"
	"strings"
	"testing"
	"unicode"
)

func isControlOrFormat(character rune) bool {
	return unicode.In(character, unicode.Cc, unicode.Cf)
}

func TestLauncherAdmissionRejectsUnrepresentableScalars(t *testing.T) {
	for _, scalar := range []string{"\u2028", "\u2029", "\n", "\u202e", "\xff"} {
		path := "/opt/" + scalar + "/bin/python"
		if _, err := AdmitLauncherProfile(ProfilePythonModule, path); err == nil {
			t.Errorf("launcher admitted a wire-unsafe scalar %q", scalar)
		} else if strings.Contains(err.Error(), path) {
			t.Error("launcher error disclosed the rejected path")
		}
	}
}

func TestLauncherAdmissionPreservesOrdinaryUnicodeAndLongPaths(t *testing.T) {
	for _, path := range []string{
		"/opt/caf\u00e9/\u65e5\u672c/bin/python",
		"/opt/task-validation/bin/python",
		"/opt/" + strings.Repeat("p", 496) + "/bin/python",
		"/opt/" + strings.Repeat("p", 497) + "/bin/python",
	} {
		renderer, err := AdmitLauncherProfile(ProfilePythonModule, path)
		if err != nil {
			t.Fatal("safe absolute interpreter was rejected", err)
		}
		want := []string{path, "-m", "agentic_proofkit", "self-check"}
		if !reflect.DeepEqual(renderer.Argv("self-check"), want) {
			t.Error("launcher changed admitted argv")
		}
	}
}
