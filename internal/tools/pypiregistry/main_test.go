package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/releaseplatform"
)

func TestCompareRegistryFilesAcceptsMatchingWheels(t *testing.T) {
	target, ok := releaseplatform.TargetByPlatformSuffix("linux-x64")
	if !ok {
		t.Fatal("missing linux-x64 release platform target")
	}
	candidate := wheelRecordForTarget(target, "1.2.3", "wheel")
	candidates := pythonPackageSet{
		PackageName:    "agentic-proofkit",
		PackageVersion: "1.2.3",
		Packages:       []wheelRecord{candidate},
	}
	registry := pypiResponse{}
	registry.Info.Name = "agentic-proofkit"
	registry.Info.Version = "1.2.3"
	registry.URLs = []pypiFile{
		{
			Filename:      candidate.Filename,
			PackageType:   "bdist_wheel",
			PythonVersion: "py3",
			URL:           "https://files.pythonhosted.org/packages/example.whl",
		},
	}
	registry.URLs[0].Digests.SHA256 = "wheel"

	evidence, err := compareRegistryFiles(candidates, registry)
	if err != nil {
		t.Fatalf("compareRegistryFiles() error = %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("compareRegistryFiles() evidence count = %d", len(evidence))
	}
	if evidence[0].URL != registry.URLs[0].URL || evidence[0].Sha256 != "wheel" {
		t.Fatalf("compareRegistryFiles() evidence = %#v", evidence[0])
	}
}

func TestCompareRegistryFilesRejectsInvalidRegistryEvidence(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*pythonPackageSet, *pypiResponse)
		want   string
	}{
		{
			name: "missing wheel",
			mutate: func(_ *pythonPackageSet, registry *pypiResponse) {
				registry.URLs = nil
			},
			want: "missing wheel",
		},
		{
			name: "digest mismatch",
			mutate: func(_ *pythonPackageSet, registry *pypiResponse) {
				registry.URLs[0].Digests.SHA256 = "other"
			},
			want: "sha256 mismatch",
		},
		{
			name: "duplicate candidate filename",
			mutate: func(candidates *pythonPackageSet, _ *pypiResponse) {
				candidates.Packages = append(candidates.Packages, candidates.Packages[0])
			},
			want: "candidate package set contains duplicate filename",
		},
		{
			name: "incomplete candidate evidence",
			mutate: func(candidates *pythonPackageSet, _ *pypiResponse) {
				candidates.Packages[0].BinarySha256 = ""
			},
			want: "candidate package set contains incomplete wheel evidence",
		},
		{
			name: "duplicate registry filename",
			mutate: func(_ *pythonPackageSet, registry *pypiResponse) {
				registry.URLs = append(registry.URLs, registry.URLs[0])
			},
			want: "pypi response contains duplicate filename",
		},
		{
			name: "unexpected registry file",
			mutate: func(_ *pythonPackageSet, registry *pypiResponse) {
				registry.URLs = append(registry.URLs, pypiFile{
					Filename:      "agentic_proofkit-1.2.3.tar.gz",
					PackageType:   "sdist",
					PythonVersion: "source",
					URL:           "https://files.pythonhosted.org/packages/example.tar.gz",
				})
			},
			want: "unexpected file",
		},
		{
			name: "yanked wheel",
			mutate: func(_ *pythonPackageSet, registry *pypiResponse) {
				registry.URLs[0].Yanked = true
			},
			want: "is yanked",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			candidates, registry := matchingCandidateAndRegistry()
			item.mutate(&candidates, &registry)

			_, err := compareRegistryFiles(candidates, registry)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("compareRegistryFiles() error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestRegistryArtifactOutputCarriesPyPIAuthorityMetadata(t *testing.T) {
	manifest := packageJSON{Name: "agentic-proofkit", Version: "1.2.3"}
	evidence := []registryWheelEvidence{{
		AbiTag:         "none",
		BinarySha256:   "binary",
		Filename:       "agentic_proofkit-1.2.3-py3-none-any.whl",
		Name:           "agentic-proofkit",
		PackageType:    "bdist_wheel",
		PlatformSuffix: "any",
		PlatformTag:    "any",
		PythonTag:      "py3",
		Sha256:         "wheel",
		URL:            "https://files.pythonhosted.org/packages/example.whl",
		Version:        "1.2.3",
		WheelTag:       "py3-none-any",
	}}

	output := registryArtifactOutput(manifest, evidence)
	definition := releasechannel.Must(releasechannel.PyPIRegistryRelease)
	if output.AuthorityChannel != string(definition.ID) || output.AuthorityValidator != definition.AuthorityValidator {
		t.Fatalf("registryArtifactOutput() authority = %s/%s, want %s/%s", output.AuthorityChannel, output.AuthorityValidator, definition.ID, definition.AuthorityValidator)
	}
	if output.Registry != releasechannel.PyPIRegistryURL || len(output.Packages) != 1 {
		t.Fatalf("registryArtifactOutput() = %#v, want PyPI registry package evidence", output)
	}
}

func TestRequireCandidatePlatformCompletenessUsesReleasePlatformOwner(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]wheelRecord) []wheelRecord
		want   string
	}{
		{
			name: "missing owner platform",
			mutate: func(records []wheelRecord) []wheelRecord {
				return records[:len(records)-1]
			},
			want: "missing wheel for release platform",
		},
		{
			name: "extra unmanaged platform",
			mutate: func(records []wheelRecord) []wheelRecord {
				return append(records, wheelRecord{
					AbiTag:         "none",
					BinarySha256:   "binary-extra",
					Filename:       "agentic_proofkit-1.2.3-py3-none-freebsd_13_0_x86_64.whl",
					Name:           "agentic-proofkit",
					PlatformSuffix: "freebsd-x64",
					PlatformTag:    "freebsd_13_0_x86_64",
					PythonTag:      "py3",
					Sha256:         "wheel-extra",
					Version:        "1.2.3",
					WheelTag:       "py3-none-freebsd_13_0_x86_64",
				})
			},
			want: "unmanaged release platform suffixes",
		},
		{
			name: "wrong platform tag",
			mutate: func(records []wheelRecord) []wheelRecord {
				records[0].PlatformTag = releaseplatform.Targets()[1].PlatformTag
				return records
			},
			want: "does not match release platform owner",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			records := item.mutate(completeReleasePlatformCandidates())

			err := requireCandidatePlatformCompleteness(records)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("requireCandidatePlatformCompleteness() error=%v, want %q", err, item.want)
			}
		})
	}
	if err := requireCandidatePlatformCompleteness(completeReleasePlatformCandidates()); err != nil {
		t.Fatalf("requireCandidatePlatformCompleteness() error=%v, want complete release platform set", err)
	}
}

func TestPyPIRegistryReadersRejectAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		read    func(string) error
		want    string
	}{
		{
			name:    "package manifest duplicate key",
			content: `{"name":"agentic-proofkit","name":"other","version":"1.2.3"}`,
			read: func(path string) error {
				_, err := readPackageJSON(path)
				return err
			},
			want: "duplicate object key",
		},
		{
			name:    "python package set trailing value",
			content: `{"artifactKind":"proofkit.python-package-set.v1","schemaVersion":1,"packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[]} false`,
			read: func(path string) error {
				_, err := readPythonPackageSet(path)
				return err
			},
			want: "multiple JSON values",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			if err := os.WriteFile(path, []byte(item.content), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			err := item.read(path)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("reader error = %v, want %q", err, item.want)
			}
		})
	}
}

func completeReleasePlatformCandidates() []wheelRecord {
	records := []wheelRecord{}
	for index, target := range releaseplatform.Targets() {
		records = append(records, wheelRecordForTarget(target, "1.2.3", "wheel-"+string(rune('a'+index))))
	}
	return records
}

func wheelRecordForTarget(target releaseplatform.Target, version string, sha string) wheelRecord {
	return wheelRecord{
		AbiTag:         "none",
		BinarySha256:   "binary",
		Filename:       "agentic_proofkit-" + version + "-" + target.WheelTag + ".whl",
		Name:           "agentic-proofkit",
		PlatformSuffix: target.PlatformSuffix,
		PlatformTag:    target.PlatformTag,
		PythonTag:      "py3",
		Sha256:         sha,
		Version:        version,
		WheelTag:       target.WheelTag,
	}
}

func matchingCandidateAndRegistry() (pythonPackageSet, pypiResponse) {
	candidates := pythonPackageSet{
		PackageName:    "agentic-proofkit",
		PackageVersion: "1.2.3",
		Packages: []wheelRecord{
			{
				AbiTag:         "none",
				BinarySha256:   "binary",
				Filename:       "agentic_proofkit-1.2.3-py3-none-any.whl",
				Name:           "agentic-proofkit",
				PlatformSuffix: "any",
				PlatformTag:    "any",
				PythonTag:      "py3",
				Sha256:         "wheel",
				Version:        "1.2.3",
				WheelTag:       "py3-none-any",
			},
		},
	}
	registry := pypiResponse{}
	registry.Info.Name = "agentic-proofkit"
	registry.Info.Version = "1.2.3"
	registry.URLs = []pypiFile{
		{
			Filename:      "agentic_proofkit-1.2.3-py3-none-any.whl",
			PackageType:   "bdist_wheel",
			PythonVersion: "py3",
			URL:           "https://files.pythonhosted.org/packages/example.whl",
		},
	}
	registry.URLs[0].Digests.SHA256 = "wheel"
	return candidates, registry
}
