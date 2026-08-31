package nodetestselector

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const maximumTAPBytes = 256 << 10

var errTAPLimit = errors.New("node test selector output exceeds the byte limit")

// Run executes one exact top-level Node test and rejects zero-match success.
func Run(ctx context.Context, nodePath string, workdir string, file string, name string) error {
	return RunSet(ctx, nodePath, workdir, file, []string{name})
}

// RunSet executes one exact sorted set of top-level Node tests in one process.
func RunSet(ctx context.Context, nodePath string, workdir string, file string, names []string) error {
	if nodePath == "" || workdir == "" || file == "" || len(names) == 0 || strings.ContainsAny(file, "\r\n") {
		return errors.New("node test selector coordinates are invalid")
	}
	selected := slices.Clone(names)
	if !validSelectorNames(selected) {
		return errors.New("node test selector names must be sorted and unique")
	}
	patterns := make([]string, len(selected))
	for index, name := range selected {
		patterns[index] = regexp.QuoteMeta(name)
	}
	pattern := "^(?:" + strings.Join(patterns, "|") + ")$"
	command := exec.CommandContext(ctx, nodePath, "--test", "--test-reporter=tap", "--test-name-pattern", pattern, file)
	command.Dir = workdir
	var stdout boundedBuffer
	var stderr boundedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return errors.New("node test selector execution failed")
	}
	return admitTAPSet(stdout.String(), selected)
}

func admitTAP(value string, name string) error {
	return admitTAPSet(value, []string{name})
}

func admitTAPSet(value string, names []string) error {
	if value == "" || strings.Contains(value, "\r") || !validSelectorNames(names) {
		return errors.New("node test selector emitted invalid TAP")
	}
	selectedSubtests := make(map[string]int, len(names))
	selectedPasses := make(map[string]int, len(names))
	selectedNames := make(map[string]struct{}, len(names))
	for _, name := range names {
		selectedNames[name] = struct{}{}
	}
	totalSubtests := 0
	totalPasses := 0
	summary := map[string]int{}
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# Subtest: "):
			totalSubtests++
			name := strings.TrimPrefix(line, "# Subtest: ")
			if _, selected := selectedNames[name]; !selected {
				return errors.New("node test selector reported an unselected test")
			}
			selectedSubtests[name]++
		case strings.HasPrefix(line, "ok "):
			parts := strings.SplitN(line, " - ", 2)
			if len(parts) != 2 {
				return errors.New("node test selector emitted invalid TAP")
			}
			totalPasses++
			if _, selected := selectedNames[parts[1]]; !selected {
				return errors.New("node test selector reported an unselected test")
			}
			selectedPasses[parts[1]]++
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
	for _, name := range names {
		if selectedSubtests[name] != 1 || selectedPasses[name] != 1 {
			return errors.New("node test selector did not execute exactly the selected passing tests")
		}
	}
	if totalSubtests != len(names) || totalPasses != len(names) || summary["tests"] != len(names) || summary["pass"] != len(names) || summary["fail"] != 0 || summary["cancelled"] != 0 || summary["skipped"] != 0 || summary["todo"] != 0 {
		return errors.New("node test selector did not execute exactly the selected passing tests")
	}
	return nil
}

func validSelectorNames(names []string) bool {
	if len(names) == 0 || !slices.IsSorted(names) {
		return false
	}
	for index, name := range names {
		if name == "" || strings.ContainsAny(name, "\r\n") || index > 0 && names[index-1] == name {
			return false
		}
	}
	return true
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
