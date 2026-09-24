package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNativeRegistryWholeRouteRejectsCoherentDriftBeforeWrite(t *testing.T) {
	for _, mutation := range []string{"kind-downgrade", "fourth-consumer", "wrong-direction"} {
		t.Run(mutation, func(t *testing.T) {
			root := writeNativeStructureFixture(t)
			if err := refreshStructures(root); err != nil {
				t.Fatal(err)
			}
			contract := readFixtureContract(t, root)
			owner := nativeStructures()[0]
			want := "consumer ownership"
			switch mutation {
			case "kind-downgrade":
				want = "differs from its native structural owner"
				for _, raw := range contract["contractDefinitions"].([]any) {
					definition := raw.(map[string]any)
					if definition["definitionId"] != owner.id {
						continue
					}
					tree := definition["fieldTree"].(map[string]any)
					tree["kind"] = "root_shape_only"
					tree["nonClaims"] = structuralFixtureDefinition("unused")["fieldTree"].(map[string]any)["nonClaims"]
					delete(tree["variants"].([]any)[0].(map[string]any), "schema")
				}
			case "fourth-consumer":
				commandAt(contract, "sample")["inputContract"].(map[string]any)["rootDefinitionRef"] = owner.id
			case "wrong-direction":
				commandAt(contract, "proof-slice")["outputContract"].(map[string]any)["rootDefinitionRef"] = owner.id
			}
			refreshDefinitionDigests(contract)
			refreshRootDefinitionDigests(contract)
			writeFixtureContract(t, root, contract)
			_, admitted, err := readContract(filepath.Join(root, cliContractPath))
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "kind-downgrade" {
				if _, err := admitDefinitions(admitted); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("direct definition owner error=%v", err)
				}
			}
			before := generatedOutputBytes(t, root)
			if err := run(root, false); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("ordinary generation must reject through its ownership guard: %v", err)
			}
			assertGeneratedBytes(t, root, before)
			if mutation == "kind-downgrade" {
				// Explicit refresh may restore its own derived representation.
				if err := refreshStructures(root); err != nil {
					t.Fatal(err)
				}
				if err := run(root, true); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestContractReadBoundsActualWorkAndPreservesOneSnapshot(t *testing.T) {
	root := writeFixture(t)
	prefix, err := os.ReadFile(filepath.Join(root, cliContractPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int64{maxContractBytes - 1, maxContractBytes, maxContractBytes + 1, 2 * maxContractBytes} {
		t.Run(strconv.FormatInt(size, 10), func(t *testing.T) {
			reader := &countingContractReader{source: io.MultiReader(bytes.NewReader(prefix), &contractPadding{remaining: size - int64(len(prefix))})}
			content, record, err := readContractInput(reader)
			if reader.bytes != min(size, maxContractBytes+1) {
				t.Fatalf("read %d bytes for size %d", reader.bytes, size)
			}
			if size > maxContractBytes {
				if err == nil || !strings.Contains(err.Error(), "exceeds size limit") || content != nil || record != nil {
					t.Fatalf("overflow admission=%v", err)
				}
				return
			}
			if err != nil || int64(len(content)) != size || !bytes.Equal(content[:len(prefix)], prefix) || record["contractId"] != "proofkit.cli-contract.v2" {
				t.Fatalf("bounded positive admission=%v", err)
			}
		})
	}
	broken := &countingContractReader{source: failingContractReader{}}
	if _, _, err := readContractInput(broken); !errors.Is(err, errContractRead) {
		t.Fatalf("read error lost: %v", err)
	}
}

func TestOversizedContractCannotChangeGeneratedOutputs(t *testing.T) {
	root := writeNativeStructureFixture(t)
	if err := refreshStructures(root); err != nil {
		t.Fatal(err)
	}
	before := generatedOutputBytes(t, root)
	path := filepath.Join(root, cliContractPath)
	if err := os.Truncate(path, maxContractBytes+1); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []func(string) error{refreshStructures, func(root string) error { return run(root, false) }} {
		if err := operation(root); err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
			t.Fatalf("oversized file not rejected before publication: %v", err)
		}
		assertGeneratedBytes(t, root, before)
	}
}

func TestInterruptedStructureRefreshIsDetectedAndRecoverable(t *testing.T) {
	root := writeNativeStructureFixture(t)
	// A directory at the second output simulates failure after the contract write.
	if err := os.Mkdir(filepath.Join(root, appGeneratedPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := refreshStructures(root); err == nil {
		t.Fatal("interrupted publication returned success")
	}
	if err := run(root, true); err == nil {
		t.Fatal("check accepted partially published projections")
	}
	if err := os.Remove(filepath.Join(root, appGeneratedPath)); err != nil {
		t.Fatal(err)
	}
	if err := refreshStructures(root); err != nil {
		t.Fatal(err)
	}
	if err := run(root, true); err != nil {
		t.Fatal(err)
	}
}

func generatedOutputBytes(t *testing.T, root string) [][]byte {
	t.Helper()
	result := [][]byte{}
	for _, path := range []string{appGeneratedPath, presetGeneratedPath} {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, content)
	}
	return result
}

func assertGeneratedBytes(t *testing.T, root string, before [][]byte) {
	t.Helper()
	if !slices.EqualFunc(before, generatedOutputBytes(t, root), bytes.Equal) {
		t.Fatal("rejected generation changed output bytes")
	}
}

type countingContractReader struct {
	source io.Reader
	bytes  int64
}

func (r *countingContractReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	r.bytes += int64(n)
	return n, err
}

type contractPadding struct{ remaining int64 }

func (r *contractPadding) Read(p []byte) (int, error) {
	n := int(min(int64(len(p)), r.remaining))
	if n == 0 {
		return 0, io.EOF
	}
	for i := range n {
		p[i] = ' '
	}
	r.remaining -= int64(n)
	return n, nil
}

var errContractRead = errors.New("fixture read failure")

type failingContractReader struct{}

func (failingContractReader) Read([]byte) (int, error) { return 0, errContractRead }
