package cliexec

import (
	"path/filepath"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

func TestDisplayCommandQuotesAmbiguousArgs(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{
			args: []string{"gradual-adoption", "--input", "proofkit/profile.json"},
			want: "agentic-proofkit gradual-adoption --input proofkit/profile.json",
		},
		{
			args: []string{"gradual-adoption", "--input", "proofkit/adoption profile.v1.json"},
			want: "agentic-proofkit gradual-adoption --input 'proofkit/adoption profile.v1.json'",
		},
		{
			args: []string{"text-policy", "--input", "proofkit/owner's file.json"},
			want: "agentic-proofkit text-policy --input 'proofkit/owner'\"'\"'s file.json'",
		},
		{
			args: []string{"self-check", "--input", ""},
			want: "agentic-proofkit self-check --input ''",
		},
	}
	for _, item := range cases {
		if got := DisplayCommand(item.args...); got != item.want {
			t.Fatalf("DisplayCommand(%#v) = %q, want %q", item.args, got, item.want)
		}
	}
}

func TestLauncherProfileAdmissionMatrix(t *testing.T) {
	python := "/tmp/proofkit venv/bin/python"
	valid := []struct {
		name             string
		profile          string
		pythonExecutable string
		wantProfile      string
		wantCommand      string
	}{
		{
			name:        "absent fields use path",
			wantProfile: ProfilePath,
			wantCommand: "agentic-proofkit self-check --input proofkit/input.json",
		},
		{
			name:        "explicit path",
			profile:     ProfilePath,
			wantProfile: ProfilePath,
			wantCommand: "agentic-proofkit self-check --input proofkit/input.json",
		},
		{
			name:        "npm offline",
			profile:     ProfileNPMOffline,
			wantProfile: ProfileNPMOffline,
			wantCommand: "npm exec --offline -- agentic-proofkit self-check --input proofkit/input.json",
		},
		{
			name:             "python module",
			profile:          ProfilePythonModule,
			pythonExecutable: python,
			wantProfile:      ProfilePythonModule,
			wantCommand:      "'/tmp/proofkit venv/bin/python' -m agentic_proofkit self-check --input proofkit/input.json",
		},
	}
	for _, item := range valid {
		t.Run(item.name, func(t *testing.T) {
			renderer, err := AdmitLauncherProfile(item.profile, item.pythonExecutable)
			if err != nil {
				t.Fatalf("AdmitLauncherProfile(%q, %q) error=%v", item.profile, item.pythonExecutable, err)
			}
			if renderer.Profile() != item.wantProfile {
				t.Fatalf("profile=%q want %q", renderer.Profile(), item.wantProfile)
			}
			if got := renderer.DisplayCommand("self-check", "--input", "proofkit/input.json"); got != item.wantCommand {
				t.Fatalf("command=%q want %q", got, item.wantCommand)
			}
		})
	}

	invalid := []struct {
		name             string
		profile          string
		pythonExecutable string
		want             string
		mustNotContain   string
	}{
		{
			name:             "absent profile with executable",
			pythonExecutable: python,
			want:             PythonExecutableEnvironment + " must be empty",
		},
		{
			name:             "path with executable",
			profile:          ProfilePath,
			pythonExecutable: python,
			want:             PythonExecutableEnvironment + " must be empty",
		},
		{
			name:             "npm with executable",
			profile:          ProfileNPMOffline,
			pythonExecutable: python,
			want:             PythonExecutableEnvironment + " must be empty",
		},
		{
			name:    "python without executable",
			profile: ProfilePythonModule,
			want:    PythonExecutableEnvironment + " must be a non-empty absolute path",
		},
		{
			name:             "python with relative executable",
			profile:          ProfilePythonModule,
			pythonExecutable: "venv/bin/python",
			want:             PythonExecutableEnvironment + " must be a non-empty absolute path",
		},
		{
			name:    "unknown profile",
			profile: "network_fallback",
			want:    LauncherProfileEnvironment + " must be empty",
		},
		{
			name:             "unknown profile with executable",
			profile:          "network_fallback",
			pythonExecutable: python,
			want:             LauncherProfileEnvironment + " must be empty",
		},
		{
			name:             "python with secret-like path component",
			profile:          ProfilePythonModule,
			pythonExecutable: filepath.Join(string(filepath.Separator), "tmp", strings.Join([]string{"gh", "p_", "12345678901234567890"}, ""), "bin", "python"),
			want:             PythonExecutableEnvironment + " must not contain secret-like or control values",
			mustNotContain:   "12345678901234567890",
		},
		{
			name:             "python with control rune",
			profile:          ProfilePythonModule,
			pythonExecutable: string(filepath.Separator) + "tmp/line\nbreak/bin/python",
			want:             PythonExecutableEnvironment + " must not contain secret-like or control values",
			mustNotContain:   "line\nbreak",
		},
	}
	for _, item := range invalid {
		t.Run(item.name, func(t *testing.T) {
			_, err := AdmitLauncherProfile(item.profile, item.pythonExecutable)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("AdmitLauncherProfile(%q, %q) error=%v, want %q", item.profile, item.pythonExecutable, err, item.want)
			}
			if item.mustNotContain != "" && strings.Contains(err.Error(), item.mustNotContain) {
				t.Fatalf("AdmitLauncherProfile error disclosed rejected value")
			}
		})
	}

	for character := rune(0); character <= unicode.MaxRune; character++ {
		if !utf8.ValidRune(character) {
			continue
		}
		wantRejected := unicode.In(character, unicode.Cc, unicode.Cf)
		if got := isControlOrFormat(character); got != wantRejected {
			t.Fatalf("isControlOrFormat(U+%04X)=%t, want %t", character, got, wantRejected)
		}
		if !wantRejected {
			continue
		}
		rejected := string(filepath.Separator) + "tmp/" + string(character) + "spoof/bin/python"
		_, err := AdmitLauncherProfile(ProfilePythonModule, rejected)
		if err == nil || !strings.Contains(err.Error(), PythonExecutableEnvironment+" must not contain secret-like or control values") {
			t.Fatalf("AdmitLauncherProfile accepted control or format U+%04X: %v", character, err)
		}
		if strings.Contains(err.Error(), rejected) || strings.ContainsRune(err.Error(), character) {
			t.Fatalf("AdmitLauncherProfile error disclosed rejected control or format U+%04X", character)
		}
	}

	for _, fixture := range admit.ReportVisibleRedactionFixtures() {
		t.Run("python rejects and does not disclose "+fixture.Name, func(t *testing.T) {
			separator := string(filepath.Separator)
			pythonExecutable := separator + "tmp" + separator + fixture.Input + separator + "bin" + separator + "python"
			_, err := AdmitLauncherProfile(ProfilePythonModule, pythonExecutable)
			if err == nil || !strings.Contains(err.Error(), PythonExecutableEnvironment+" must not contain secret-like or control values") {
				t.Fatalf("AdmitLauncherProfile accepted a report-visible secret class: %v", err)
			}
			for _, needle := range fixture.SensitiveNeedles {
				if strings.Contains(err.Error(), needle) {
					t.Fatalf("AdmitLauncherProfile error disclosed rejected value")
				}
			}
		})
	}
}

func TestRendererArgvAndDisplayShareOneImmutableInvocation(t *testing.T) {
	renderer, err := AdmitLauncherProfile(ProfilePythonModule, "/tmp/proofkit venv/bin/python")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/tmp/proofkit venv/bin/python", "-m", "agentic_proofkit", "self-check", "--input", "proofkit/input.json"}
	argv := renderer.Argv("self-check", "--input", "proofkit/input.json")
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv=%q, want %q", argv, want)
	}
	if got := DisplayArgv(argv); got != renderer.DisplayCommand("self-check", "--input", "proofkit/input.json") {
		t.Fatalf("display argv=%q, renderer display=%q", got, renderer.DisplayCommand("self-check", "--input", "proofkit/input.json"))
	}
	argv[0] = "mutated"
	if got := renderer.Argv("self-check")[0]; got != "/tmp/proofkit venv/bin/python" {
		t.Fatalf("renderer retained caller mutation: %q", got)
	}
}
