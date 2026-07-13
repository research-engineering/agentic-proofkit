package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const proofInputResolutionEnvironment = "PROOFKIT_BROWSER_INPUT_RESOLUTION"

type proofInputResolution struct {
	InputPaths   []string
	ServerTarget string
	WriterPath   string
	Selectors    []string
}

type goListPackage struct {
	Dir          string
	Module       *struct{ Main bool }
	GoFiles      []string
	CgoFiles     []string
	CFiles       []string
	CXXFiles     []string
	MFiles       []string
	HFiles       []string
	FFiles       []string
	SFiles       []string
	SwigFiles    []string
	SwigCXXFiles []string
	SysoFiles    []string
	EmbedFiles   []string
}

func resolveProofInputs(root string, manifest proofInputManifest) (proofInputResolution, error) {
	goDirs, goFiles, err := repoLocalGoInputs(root, []string{proofVerifierTarget, manifest.ServerTarget})
	if err != nil {
		return proofInputResolution{}, err
	}
	if err := validateRegularInputPaths(root, goFiles); err != nil {
		return proofInputResolution{}, err
	}
	roleOwnedPaths := []string{proofInputManifestPath, manifest.TestRoot, manifest.WriterPath}
	selectors := sortedUnique(append(roleOwnedPaths, append(manifest.Paths, goDirs...)...))
	if err := validateBrowserWitnessPolicy(root, selectors); err != nil {
		return proofInputResolution{}, err
	}
	explicitPaths, err := collectInputPaths(root, append(roleOwnedPaths, manifest.Paths...))
	if err != nil {
		return proofInputResolution{}, err
	}
	inputPaths := sortedUnique(append(explicitPaths, goFiles...))
	return proofInputResolution{
		InputPaths:   inputPaths,
		ServerTarget: manifest.ServerTarget,
		WriterPath:   manifest.WriterPath,
		Selectors:    selectors,
	}, nil
}

func repoLocalGoInputs(root string, targets []string) ([]string, []string, error) {
	arguments := append([]string{"list", "-deps", "-json"}, targets...)
	command := exec.Command("go", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve browser proof Go dependency closure: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	dirs := []string{}
	files := []string{}
	for {
		var pkg goListPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("decode browser proof Go dependency closure: %w", err)
		}
		if pkg.Module == nil || !pkg.Module.Main {
			continue
		}
		relativeDir, err := repoRelativePath(root, pkg.Dir)
		if err != nil {
			return nil, nil, err
		}
		dirs = append(dirs, relativeDir)
		for _, name := range goPackageSourceFiles(pkg) {
			absolute := name
			if !filepath.IsAbs(absolute) {
				absolute = filepath.Join(pkg.Dir, name)
			}
			relative, err := repoRelativePath(root, absolute)
			if err != nil {
				return nil, nil, err
			}
			files = append(files, relative)
		}
	}
	return sortedUnique(dirs), sortedUnique(files), nil
}

func validateRegularInputPaths(root string, paths []string) error {
	for _, path := range paths {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("browser proof resolved inputs must be regular non-symlink files")
		}
	}
	return nil
}

func goPackageSourceFiles(pkg goListPackage) []string {
	groups := [][]string{
		pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles,
		pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles,
	}
	result := []string{}
	for _, group := range groups {
		result = append(result, group...)
	}
	return result
}

func repoRelativePath(root, absolute string) (string, error) {
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return "", err
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("browser proof input escaped the repository")
	}
	return admit.SafeRepoRelativePath(relative, "browser proof resolved input")
}

func validateBrowserWitnessPolicy(root string, expected []string) error {
	raw, err := os.ReadFile(filepath.Join(root, "proofkit/witness-plan.json"))
	if err != nil {
		return err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("witness plan must be an object")
	}
	policies, ok := record["policies"].([]any)
	if !ok {
		return fmt.Errorf("witness plan policies must be an array")
	}
	matches := 0
	for index, rawPolicy := range policies {
		policy, ok := rawPolicy.(map[string]any)
		if !ok {
			return fmt.Errorf("witness plan policies[%d] must be an object", index)
		}
		if policy["commandId"] != "proofkit.browser-check" {
			continue
		}
		matches++
		selectors, err := admittedTextArray(policy["inputSelectors"], "browser witness inputSelectors")
		if err != nil {
			return err
		}
		if !slices.Equal(selectors, expected) {
			return fmt.Errorf("browser witness inputSelectors drifted from the input manifest")
		}
	}
	if matches != 1 {
		return fmt.Errorf("witness plan must contain exactly one browser-check policy")
	}
	return nil
}

func admittedTextArray(raw any, context string) ([]string, error) {
	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", context)
	}
	result := make([]string, 0, len(values))
	for index, rawValue := range values {
		value, err := admit.NonEmptyText(rawValue, fmt.Sprintf("%s[%d]", context, index))
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	if !slices.Equal(result, sortedUnique(result)) {
		return nil, fmt.Errorf("%s must be sorted and unique", context)
	}
	return result, nil
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
