package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admit"
)

const (
	proofInputManifestPath = "scripts/browser-runtime-proof-inputs.v1.json"
	proofVerifierTarget    = "./internal/tools/browserproofverify"
)

type proofInputManifest struct {
	ServerTarget string
	TestRoot     string
	WriterPath   string
	Paths        []string
}

func loadProofInputManifest(root string) (proofInputManifest, error) {
	raw, err := os.ReadFile(filepath.Join(root, proofInputManifestPath))
	if err != nil {
		return proofInputManifest{}, err
	}
	value, err := admission.DecodeJSON(bytes.NewReader(raw), 1<<20)
	if err != nil {
		return proofInputManifest{}, err
	}
	record, ok := value.(map[string]any)
	if !ok {
		return proofInputManifest{}, fmt.Errorf("browser proof input manifest must be an object")
	}
	if err := admit.KnownKeys(record, []string{"paths", "proofKind", "schemaVersion", "serverTarget", "testRoot", "writerPath"}, "browser proof input manifest"); err != nil {
		return proofInputManifest{}, err
	}
	if !admit.JSONNumberEquals(record["schemaVersion"], 1) || record["proofKind"] != "proofkit.browser-runtime-proof-inputs" {
		return proofInputManifest{}, fmt.Errorf("browser proof input manifest identity is invalid")
	}
	serverTarget, err := admitManifestGoTarget(record["serverTarget"])
	if err != nil {
		return proofInputManifest{}, err
	}
	writerPath, err := admitManifestPath(record["writerPath"], "browser proof input manifest writerPath")
	if err != nil {
		return proofInputManifest{}, err
	}
	testRoot, err := admitManifestPath(record["testRoot"], "browser proof input manifest testRoot")
	if err != nil {
		return proofInputManifest{}, err
	}
	paths, err := admitManifestPaths(record["paths"])
	if err != nil {
		return proofInputManifest{}, err
	}
	for _, ownedPath := range []string{proofInputManifestPath, testRoot, writerPath} {
		for _, path := range paths {
			if path == ownedPath || strings.HasPrefix(ownedPath, path+"/") || strings.HasPrefix(path, ownedPath+"/") {
				return proofInputManifest{}, fmt.Errorf("browser proof input manifest paths must not duplicate role-owned paths")
			}
		}
	}
	return proofInputManifest{ServerTarget: serverTarget, TestRoot: testRoot, WriterPath: writerPath, Paths: paths}, nil
}

func admitManifestGoTarget(raw any) (string, error) {
	value, err := admit.NonEmptyText(raw, "browser proof input manifest serverTarget")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, "./") {
		return "", fmt.Errorf("browser proof input manifest serverTarget must be an explicit relative package")
	}
	path, err := admit.SafeRepoRelativePath(strings.TrimPrefix(value, "./"), "browser proof input manifest serverTarget")
	if err != nil {
		return "", err
	}
	return "./" + path, nil
}

func admitManifestPath(raw any, context string) (string, error) {
	value, err := admit.NonEmptyText(raw, context)
	if err != nil {
		return "", err
	}
	return admit.SafeRepoRelativePath(value, context)
}

func admitManifestPaths(raw any) ([]string, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, fmt.Errorf("browser proof input manifest paths must be a non-empty array")
	}
	result := make([]string, 0, len(values))
	for index, rawValue := range values {
		value, err := admitManifestPath(rawValue, fmt.Sprintf("browser proof input manifest paths[%d]", index))
		if err != nil {
			return nil, err
		}
		for _, previous := range result {
			if value == previous || strings.HasPrefix(value, previous+"/") || strings.HasPrefix(previous, value+"/") {
				return nil, fmt.Errorf("browser proof input manifest paths must be sorted, unique, and non-overlapping")
			}
		}
		if len(result) > 0 && value <= result[len(result)-1] {
			return nil, fmt.Errorf("browser proof input manifest paths must be sorted, unique, and non-overlapping")
		}
		result = append(result, value)
	}
	return result, nil
}
