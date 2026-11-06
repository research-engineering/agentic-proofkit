package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPublishedOutputMirrorUsesSameBytes(t *testing.T) {
	grouped := conversionFixture(t, "source.grouped.json")
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		name  string
		args  []string
		input []byte
	}{
		{"json", []string{"requirement-spec-tree-view", "--format", "json"}, []byte(cliRequirementSpecTreeInput())},
		{"compact", []string{"--json-layout", "compact", "requirement-spec-tree-view", "--format", "json"}, []byte(cliRequirementSpecTreeInput())},
		{"markdown", []string{"requirement-spec-tree-view", "--format", "markdown"}, []byte(cliRequirementSpecTreeInput())},
		{"html", []string{"requirement-spec-tree-view", "--format", "html"}, []byte(cliRequirementSpecTreeInput())},
		{"conversion", []string{"requirement-source-conversion", "--to", "flat"}, grouped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arguments := append(append([]string{}, tc.args...), "--input", "-")
			plain := runConversion(t, tc.input, arguments...)
			if plain.exit != 0 || len(plain.stdout) == 0 || plain.stderr != "" {
				t.Fatalf("plain output failed: %d %s", plain.exit, plain.stderr)
			}
			output := "reports/" + tc.name
			mirrored := runConversion(t, tc.input, append(arguments, "--mirror-output", "--output", output)...)
			file, err := os.ReadFile(output)
			if err != nil || mirrored.exit != 0 || mirrored.stderr != "" ||
				!bytes.Equal(plain.stdout, file) || !bytes.Equal(file, mirrored.stdout) {
				t.Fatalf("mirror differs from the admitted published bytes: exit %d, stderr %q, read %v", mirrored.exit, mirrored.stderr, err)
			}
			if tc.name == "conversion" {
				runConversion(t, tc.input, append(arguments, "--mirror-output", "--output", output)...).refused(t, "output path already exists")
			}
		})
	}
}

func TestPublishedOutputMirrorRequiresAdmittedOutput(t *testing.T) {
	t.Chdir(t.TempDir())
	runConversion(t, []byte("not JSON"), "requirement-spec-tree-view", "--input", "-", "--mirror-output").refused(t, "--mirror-output requires --output")
	runConversion(t, []byte("not JSON"), "requirement-spec-tree-view", "--input", "-", "--output", ".git/config", "--mirror-output").refused(t, "must not enter repository metadata")
	if _, err := os.Stat(".git"); !os.IsNotExist(err) {
		t.Fatalf("refused path caused a filesystem effect: %v", err)
	}
	arguments := []string{"requirement-spec-tree-view", "--input", "-", "--output", "report.json", "--mirror-output"}
	reader, writer := io.Pipe()
	defer writer.Close()
	if err := reader.CloseWithError(errors.New("test stdout closed")); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	status := Run(t.Context(), arguments, strings.NewReader(cliRequirementSpecTreeInput()), writer, &stderr)
	content, readErr := os.ReadFile("report.json")
	if status != 1 || !strings.Contains(stderr.String(), "test stdout closed") || readErr != nil || len(content) == 0 {
		t.Fatalf("publish-then-mirror outcome status=%d stderr=%q fileBytes=%d read=%v", status, stderr.String(), len(content), readErr)
	}
}
