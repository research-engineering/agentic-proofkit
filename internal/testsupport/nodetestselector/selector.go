package nodetestselector

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const maximumTAPBytes = 256 << 10

var errTAPLimit = errors.New("node test selector output exceeds the byte limit")

// Run executes one exact top-level Node test and rejects zero-match success.
func Run(ctx context.Context, nodePath string, workdir string, file string, name string) error {
	if nodePath == "" || workdir == "" || file == "" || name == "" || strings.ContainsAny(file+name, "\r\n") {
		return errors.New("node test selector coordinates are invalid")
	}
	pattern := "^" + regexp.QuoteMeta(name) + "$"
	command := exec.CommandContext(ctx, nodePath, "--test", "--test-reporter=tap", "--test-name-pattern", pattern, file)
	command.Dir = workdir
	var stdout boundedBuffer
	var stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return errors.New("node test selector execution failed")
	}
	return admitTAP(stdout.String(), name)
}

func admitTAP(value string, name string) error {
	if value == "" || strings.Contains(value, "\r") || strings.ContainsAny(name, "\r\n") {
		return errors.New("node test selector emitted invalid TAP")
	}
	subtestLine := "# Subtest: " + name
	selectedSubtests := 0
	selectedPasses := 0
	summary := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# Subtest: "):
			if line == subtestLine {
				selectedSubtests++
			}
		case strings.HasPrefix(line, "ok "):
			parts := strings.SplitN(line, " - ", 2)
			if len(parts) == 2 && parts[1] == name {
				selectedPasses++
			}
		case strings.HasPrefix(line, "not ok "):
			return errors.New("node test selector reported a failure")
		case strings.HasPrefix(line, "# "):
			parts := strings.Fields(line)
			if len(parts) != 3 {
				continue
			}
			count, err := strconv.Atoi(parts[2])
			if err == nil {
				summary[parts[1]] = count
			}
		}
	}
	if selectedSubtests != 1 || selectedPasses != 1 || summary["tests"] != 1 || summary["pass"] != 1 || summary["fail"] != 0 || summary["cancelled"] != 0 || summary["skipped"] != 0 || summary["todo"] != 0 {
		return errors.New("node test selector did not execute exactly one passing test")
	}
	return nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	if buffer.buffer.Len()+len(value) > maximumTAPBytes {
		return 0, errTAPLimit
	}
	return buffer.buffer.Write(value)
}

func (buffer *boundedBuffer) String() string {
	return buffer.buffer.String()
}
