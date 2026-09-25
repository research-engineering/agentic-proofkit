package gitfixture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCommandRejectsAmbientGitSettings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hostile executable controls require a POSIX shell")
	}
	for _, source := range []string{"home", "xdg", "global", "system", "count", "parameters", "local", "template"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			home := t.TempDir()
			xdg := t.TempDir()
			hooks := t.TempDir()
			marker := filepath.Join(t.TempDir(), "executed")
			program := filepath.Join(hooks, "pre-commit")
			writeTestFile(t, program, "#!/bin/sh\nprintf executed > \"$PROOFKIT_GIT_MARKER\"\nexit 1\n", 0o755)
			config := fmt.Sprintf("[core]\n\thooksPath = %q\n[commit]\n\tgpgSign = true\n[tag]\n\tgpgSign = true\n[gpg]\n\tprogram = %q\n", hooks, program)
			configPath := filepath.Join(t.TempDir(), "hostile.config")
			writeTestFile(t, configPath, config, 0o600)
			env := Command(root, "version").Env
			// Only the spawned test/Git processes receive hostile settings.
			env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+xdg, "PROOFKIT_GIT_MARKER="+marker, "GOCOVERDIR="+t.TempDir())
			switch source {
			case "home", "xdg":
				filtered := make([]string, 0, len(env))
				for _, entry := range env {
					if !strings.HasPrefix(entry, "GIT_CONFIG_GLOBAL=") {
						filtered = append(filtered, entry)
					}
				}
				env = filtered
				if source == "home" {
					writeTestFile(t, filepath.Join(home, ".gitconfig"), config, 0o600)
				} else {
					writeTestFile(t, filepath.Join(xdg, "git", "config"), config, 0o600)
				}
			case "global":
				env = append(env, "GIT_CONFIG_GLOBAL="+configPath)
			case "system":
				env = append(env, "GIT_CONFIG_NOSYSTEM=0", "GIT_CONFIG_SYSTEM="+configPath)
			case "count":
				env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=include.path", "GIT_CONFIG_VALUE_0="+configPath)
			case "parameters":
				env = append(env, "GIT_CONFIG_PARAMETERS='include.path'='"+configPath+"'")
			case "local":
				runTestGit(t, root, "init", "-q")
				runTestGit(t, root, "config", "include.path", configPath)
			case "template":
				template := t.TempDir()
				writeTestFile(t, filepath.Join(template, "hooks", "pre-commit"), "#!/bin/sh\nprintf executed > \"$PROOFKIT_GIT_MARKER\"\nexit 1\n", 0o755)
				env = append(env, "GIT_TEMPLATE_DIR="+template)
			}

			// Positive controls establish that the injected settings really execute.
			control := t.TempDir()
			if source == "local" {
				control = root
			}
			raw := func(args ...string) ([]byte, error) {
				command := exec.Command("git", args...)
				command.Dir, command.Env = control, env
				return command.CombinedOutput()
			}
			for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "test@example.invalid"}, {"config", "user.name", "Test"}} {
				if output, err := raw(args...); err != nil {
					t.Fatalf("control setup: %v %s", err, output)
				}
			}
			controls := [][]string{{"commit", "--allow-empty", "-m", "hook-control"}}
			if source != "template" {
				controls = append(controls, []string{"-c", "core.hooksPath=" + os.DevNull, "commit", "--allow-empty", "-m", "signing-control"})
			}
			for _, args := range controls {
				if output, err := raw(args...); err == nil {
					t.Fatalf("hostile control unexpectedly succeeded: %s", output)
				}
				if content, err := os.ReadFile(marker); err != nil || string(content) != "executed" {
					t.Fatalf("hostile control did not execute: %q %v", content, err)
				}
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}

			command := exec.Command(os.Args[0], "-test.run=^TestCommandHostileEnvironmentHelper$", "--", "git-fixture-helper", root)
			command.Env = env
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("isolated fixture failed: %v\n%s", err, output)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("fixture executed hostile program: %v", err)
			}
		})
	}
}

func TestCommandHostileEnvironmentHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "git-fixture-helper" {
		return
	}
	root := os.Args[len(os.Args)-1]
	runTestGit(t, root, "init", "-q")
	runTestGit(t, root, "config", "user.email", "test@example.invalid")
	runTestGit(t, root, "config", "user.name", "Test")
	writeTestFile(t, filepath.Join(root, "source.txt"), "source\n", 0o600)
	runTestGit(t, root, "add", "source.txt")
	runTestGit(t, root, "commit", "-m", "fixture")
	runTestGit(t, root, "tag", "-a", "fixture", "-m", "fixture")
	for _, object := range []string{"HEAD", "refs/tags/fixture"} {
		output := runTestGit(t, root, "cat-file", "-p", object)
		if strings.Contains(output, "gpgsig") || strings.Contains(output, "BEGIN PGP SIGNATURE") {
			t.Fatal("fixture object was signed")
		}
	}
	if output := runTestGit(t, root, "show", "HEAD:source.txt"); output != "source\n" {
		t.Fatalf("fixture commit lost source: %q", output)
	}
}

func TestCommandClearsGitEnvironment(t *testing.T) {
	if len(os.Args) >= 2 && os.Args[len(os.Args)-1] == "git-environment-helper" {
		command := Command(t.TempDir(), "version")
		allowed := map[string]string{"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.DevNull, "GIT_CONFIG_GLOBAL": os.DevNull}
		for _, entry := range command.Env {
			key, value, _ := strings.Cut(entry, "=")
			if strings.HasPrefix(strings.ToUpper(key), "GIT_") {
				if want, ok := allowed[key]; !ok || value != want {
					t.Fatalf("ambient Git setting survived: %s", key)
				}
			}
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("clean command failed: %v %s", err, output)
		}
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestCommandClearsGitEnvironment$", "--", "git-environment-helper")
	command.Env = append(os.Environ(), "GOCOVERDIR="+t.TempDir(),
		"GIT_DIR=/nonexistent-fixture-git", "GIT_WORK_TREE=/nonexistent-fixture-worktree",
		"GIT_INDEX_FILE=/nonexistent-fixture-index", "GIT_CONFIG=/nonexistent-fixture-config",
		"GIT_CONFIG_COUNT=invalid", "GIT_CONFIG_PARAMETERS=invalid", "GIT_CONFIG_KEY_99=leftover",
		"GIT_CONFIG_VALUE_99=leftover", "GIT_CONFIG_SYSTEM=/nonexistent-fixture-system",
		"GIT_CONFIG_GLOBAL=/nonexistent-fixture-global", "GIT_TRACE=/nonexistent-fixture-trace",
		"GIT_TEMPLATE_DIR=/nonexistent-fixture-template", "GIT_EXEC_PATH=/nonexistent-fixture-exec")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("environment clearing failed: %v\n%s", err, output)
	}
}

func runTestGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	output, err := Command(root, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return string(output)
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
