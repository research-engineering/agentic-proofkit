// Package gitfixture isolates synthetic test repository writes from ambient Git settings.
package gitfixture

import (
	"os"
	"os/exec"
	"strings"
)

// Command retains the host Git executable but not its ambient configuration.
// Callers must use it only for synthetic test repositories.
func Command(root string, args ...string) *exec.Cmd {
	command := exec.Command("git", append([]string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false",
		"-c", "commit.gpgSign=false",
		"-c", "tag.gpgSign=false",
		"-c", "init.templateDir=",
	}, args...)...)
	command.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(strings.ToUpper(key), "GIT_") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
	)
	return command
}
