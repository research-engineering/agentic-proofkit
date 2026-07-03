package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
)

func TestReleaseManifestReadersRejectAmbiguousJSON(t *testing.T) {
	cases := []struct {
		name  string
		write func(string)
		read  func(string) error
		want  string
	}{
		{
			name: "package manifest duplicate key",
			write: func(path string) {
				writeFile(t, path, `{"name":"agentic-proofkit","name":"other","version":"1.2.3","license":"MIT","repository":{"url":"https://example.test/repo"}}`)
			},
			read: func(path string) error {
				_, err := readPackageJSON(path)
				return err
			},
			want: "duplicate object key",
		},
		{
			name: "pack records trailing value",
			write: func(path string) {
				writeFile(t, path, `[{"name":"agentic-proofkit","version":"1.2.3","filename":"agentic-proofkit.tgz","integrity":"sha512-x","shasum":"abc"}] true`)
			},
			read: func(path string) error {
				_, err := readPackRecords(path)
				return err
			},
			want: "multiple JSON values",
		},
		{
			name: "python package set duplicate key",
			write: func(path string) {
				writeFile(t, path, `{"artifactKind":"proofkit.python-package-set.v1","schemaVersion":1,"packageName":"agentic-proofkit","packageName":"other","packageVersion":"1.2.3","packages":[{"filename":"agentic_proofkit-1.2.3-py3-none-any.whl","name":"agentic-proofkit","version":"1.2.3","sha256":"abc","binarySha256":"def","pythonTag":"py3","abiTag":"none","platformTag":"any","platformSuffix":"any","wheelTag":"py3-none-any"}]}`)
			},
			read: func(path string) error {
				_, err := optionalPythonPackageSet(path)
				return err
			},
			want: "duplicate object key",
		},
		{
			name: "pypi registry set duplicate key",
			write: func(path string) {
				writeFile(t, path, `{"artifactKind":"proofkit.pypi-registry-artifact-set.v1","schemaVersion":1,"registry":"https://pypi.org","packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[],"packages":[]}`)
			},
			read: func(path string) error {
				_, err := optionalPyPIRegistrySet(path)
				return err
			},
			want: "duplicate object key",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input.json")
			item.write(path)
			err := item.read(path)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("reader error = %v, want %q", err, item.want)
			}
		})
	}
}

func TestReleaseChannelsCarryAuthorityAndPublisherEnvironment(t *testing.T) {
	channels := releaseChannels(
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		"published_by_workflow",
		&pythonPackageSet{Packages: []pythonWheelRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic_proofkit-1.2.3-py3-none-any.whl", Sha256: "def"}}},
		completePyPIRegistrySet(),
		"published_by_workflow",
		nil,
		completeTrustedPublishers(),
	)
	byAuthority := channelsByAuthority(t, channels)
	assertChannel(t, byAuthority[string(releasechannel.RegistryRelease)], "public-npm", "releaseauthority", "github-actions:environment:npm-production")
	assertChannel(t, byAuthority[string(releasechannel.PyPIRegistryRelease)], "pypi", "pypiregistry", "github-actions:environment:pypi")
	assertChannel(t, byAuthority[string(releasechannel.PythonWheelCandidate)], "pypi-wheel-candidate", "pythonpackage", "")
	assertChannel(t, byAuthority[string(releasechannel.GitHubReleaseArchive)], "github-release", "releasepreflight.github-release", "github-actions:contents-write")
}

func TestReleaseChannelsKeepWheelCandidateOutOfPyPIRegistryChannel(t *testing.T) {
	channels := releaseChannels(
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		nil,
		"",
		&pythonPackageSet{Packages: []pythonWheelRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic_proofkit-1.2.3-py3-none-any.whl", Sha256: "def"}}},
		nil,
		"",
		nil,
		trustedPublisherSet{},
	)
	byAuthority := channelsByAuthority(t, channels)
	candidate := byAuthority[string(releasechannel.PythonWheelCandidate)]
	if candidate.Status != "candidate" || len(candidate.Packages) != 1 {
		t.Fatalf("python_wheel_candidate = status %q packages %d, want candidate with one package", candidate.Status, len(candidate.Packages))
	}
	pypi := byAuthority[string(releasechannel.PyPIRegistryRelease)]
	if pypi.Status != "planned" || len(pypi.Packages) != 0 {
		t.Fatalf("pypi_registry_release = status %q packages %d, want planned with no local candidate packages", pypi.Status, len(pypi.Packages))
	}
}

func TestReleaseChannelsDoNotInventPublisherProvenanceForExistingByteMatch(t *testing.T) {
	channels := releaseChannels(
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		"existing_byte_match",
		nil,
		completePyPIRegistrySet(),
		"existing_byte_match",
		nil,
		completeTrustedPublishers(),
	)
	byAuthority := channelsByAuthority(t, channels)
	npm := byAuthority[string(releasechannel.RegistryRelease)]
	if npm.Status != "published" || npm.PublicationMode != "existing_byte_match" || npm.PublisherEnvironment != "" {
		t.Fatalf("npm channel = status %q mode %q publisher %q, want published existing byte match without publisher provenance", npm.Status, npm.PublicationMode, npm.PublisherEnvironment)
	}
	if npm.TrustedPublisher != nil {
		t.Fatalf("npm trustedPublisher=%#v, want nil for existing byte match", npm.TrustedPublisher)
	}
	if !containsText(npm.NonClaims, "not publisher provenance") {
		t.Fatalf("npm nonClaims=%v, want publisher provenance non-claim", npm.NonClaims)
	}
	pypi := byAuthority[string(releasechannel.PyPIRegistryRelease)]
	if pypi.Status != "published" || pypi.PublicationMode != "existing_byte_match" || pypi.PublisherEnvironment != "" {
		t.Fatalf("pypi channel = status %q mode %q publisher %q, want published existing byte match without publisher provenance", pypi.Status, pypi.PublicationMode, pypi.PublisherEnvironment)
	}
	if pypi.TrustedPublisher != nil {
		t.Fatalf("pypi trustedPublisher=%#v, want nil for existing byte match", pypi.TrustedPublisher)
	}
	if !containsText(pypi.NonClaims, "not publisher provenance") {
		t.Fatalf("pypi nonClaims=%v, want publisher provenance non-claim", pypi.NonClaims)
	}
}

func TestReleaseChannelsRetainPublisherIdentityForMixedPublication(t *testing.T) {
	channels := releaseChannels(
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		"mixed",
		nil,
		nil,
		"",
		nil,
		completeTrustedPublishers(),
	)
	npm := channelsByAuthority(t, channels)[string(releasechannel.RegistryRelease)]
	if npm.PublicationMode != "mixed" || npm.PublisherEnvironment != "github-actions:environment:npm-production" || npm.TrustedPublisher == nil {
		t.Fatalf("npm channel = mode %q environment %q trustedPublisher %#v, want mixed publisher identity", npm.PublicationMode, npm.PublisherEnvironment, npm.TrustedPublisher)
	}
}

func TestReleaseChannelsDoNotInventPublisherProvenanceForCandidateOnlyChannel(t *testing.T) {
	channels := releaseChannels(
		[]packRecord{{Name: "agentic-proofkit", Version: "1.2.3", Filename: "agentic-proofkit-1.2.3.tgz", Integrity: "sha512-x", Shasum: "abc"}},
		nil,
		"published_by_workflow",
		nil,
		nil,
		"",
		nil,
		trustedPublisherSet{},
	)
	npm := channelsByAuthority(t, channels)[string(releasechannel.RegistryRelease)]
	if npm.Status != "candidate" || npm.PublicationMode != "" || npm.PublisherEnvironment != "" {
		t.Fatalf("npm channel = status %q mode %q publisher %q, want candidate without publication mode or publisher provenance", npm.Status, npm.PublicationMode, npm.PublisherEnvironment)
	}
	if !containsText(npm.NonClaims, "do not prove npm registry publication") {
		t.Fatalf("npm nonClaims=%v, want registry publication non-claim", npm.NonClaims)
	}
}

func TestTrustedPublisherSetFromEnvRequiresIdentityOnlyForWorkflowPublication(t *testing.T) {
	manifest := packageJSON{
		Name:    "agentic-proofkit",
		Version: "1.2.3",
		Repository: repositoryJSON{
			URL: "git+https://github.com/research-engineering/agentic-proofkit.git",
		},
	}
	values := map[string]string{
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_ENVIRONMENT":   "npm-production",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_JOB":           "publish",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROJECT":       "agentic-proofkit",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROVIDER":      "npm",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REGISTRY":      releasechannel.NPMRegistryURL,
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REPOSITORY":    "research-engineering/agentic-proofkit",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_WORKFLOW_REF":  "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_ENVIRONMENT":  "pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_JOB":          "publish-pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_PROJECT":      "agentic-proofkit",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_PROVIDER":     "pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_REGISTRY":     releasechannel.PyPIRegistryURL,
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_REPOSITORY":   "research-engineering/agentic-proofkit",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_WORKFLOW_REF": "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	getenv := func(key string) string { return values[key] }
	publishers, err := trustedPublisherSetFromEnv(manifest, "published_by_workflow", "mixed", getenv)
	if err != nil {
		t.Fatalf("trustedPublisherSetFromEnv() error = %v", err)
	}
	if publishers.NPM == nil || publishers.PyPI == nil {
		t.Fatalf("publishers=%#v, want npm and pypi identities", publishers)
	}
	publishers, err = trustedPublisherSetFromEnv(manifest, "existing_byte_match", "", getenv)
	if err != nil {
		t.Fatalf("trustedPublisherSetFromEnv() existing_byte_match error = %v", err)
	}
	if publishers.NPM != nil || publishers.PyPI != nil {
		t.Fatalf("publishers=%#v, want no identities for non-workflow publication", publishers)
	}
	_, err = trustedPublisherSetFromEnv(manifest, "published_by_workflow", "", func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "trustedPublisher") {
		t.Fatalf("trustedPublisherSetFromEnv() error=%v, want missing trustedPublisher failure", err)
	}
}

func TestReleaseNotesIncludeRollbackInstruction(t *testing.T) {
	content := releaseNotes(packageJSON{Name: "agentic-proofkit", Version: "1.2.3"}, false)
	for _, want := range []string{
		"Rollback:",
		"npm install -D agentic-proofkit@<previous-version>",
		"Treat local package artifacts as candidates until registry identity is proven.",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("releaseNotes() missing %q:\n%s", want, content)
		}
	}
}

func TestRequirePublicationModeFailsClosedWhenRegistryEvidenceExists(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		present   bool
		wantError bool
	}{
		{name: "registry evidence without sidecar", present: true, wantError: true},
		{name: "registry evidence with sidecar", mode: "existing_byte_match", present: true},
		{name: "sidecar without registry evidence", mode: "published_by_workflow", present: false, wantError: true},
		{name: "no registry evidence", present: false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := requirePublicationMode(item.mode, "npm", item.present)
			if item.wantError {
				if err == nil || !strings.Contains(err.Error(), "publication mode") {
					t.Fatalf("error=%v, want publication mode failure", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRegistryRecordsMustMatchLocalPackageEvidence(t *testing.T) {
	local := []packRecord{{
		Filename:  "agentic-proofkit-1.2.3.tgz",
		Integrity: "sha512-local",
		Name:      "agentic-proofkit",
		Shasum:    "local",
		Version:   "1.2.3",
	}}
	registry := []packRecord{{
		Filename:  "agentic-proofkit-1.2.3.tgz",
		Integrity: "sha512-registry",
		Name:      "agentic-proofkit",
		Shasum:    "local",
		Version:   "1.2.3",
	}}

	err := requireRegistryRecordsMatchLocal(registry, local)
	if err == nil || !strings.Contains(err.Error(), "does not match local package identity and bytes") {
		t.Fatalf("requireRegistryRecordsMatchLocal() error=%v, want byte identity mismatch", err)
	}

	registry[0].Integrity = "sha512-local"
	if err := requireRegistryRecordsMatchLocal(registry, local); err != nil {
		t.Fatalf("requireRegistryRecordsMatchLocal() error=%v, want match", err)
	}
}

func TestPyPIRegistryEvidenceMustMatchLocalWheelEvidence(t *testing.T) {
	registry := completePyPIRegistrySet()
	local := &pythonPackageSet{
		PackageName:    "agentic-proofkit",
		PackageVersion: "1.2.3",
		Packages: []pythonWheelRecord{{
			AbiTag:         "none",
			BinarySha256:   "different",
			Filename:       "agentic_proofkit-1.2.3-py3-none-any.whl",
			Name:           "agentic-proofkit",
			PlatformSuffix: "any",
			PlatformTag:    "any",
			PythonTag:      "py3",
			Sha256:         "def",
			Version:        "1.2.3",
			WheelTag:       "py3-none-any",
		}},
	}
	manifest := packageJSON{Name: "agentic-proofkit", Version: "1.2.3"}

	err := requirePyPIRegistryMatchesLocal(registry, local, manifest)
	if err == nil || !strings.Contains(err.Error(), "does not match local wheel identity and bytes") {
		t.Fatalf("requirePyPIRegistryMatchesLocal() error=%v, want byte identity mismatch", err)
	}

	local.Packages[0].BinarySha256 = "bin"
	if err := requirePyPIRegistryMatchesLocal(registry, local, manifest); err != nil {
		t.Fatalf("requirePyPIRegistryMatchesLocal() error=%v, want match", err)
	}
}

func TestPyPIRegistryEvidenceRequiresCanonicalAuthorityMetadata(t *testing.T) {
	cases := map[string]struct {
		json string
		want string
	}{
		"wrong authority channel": {
			json: `{"artifactKind":"proofkit.pypi-registry-artifact-set.v1","schemaVersion":1,"authorityChannel":"python_wheel_candidate","authorityValidator":"pythonpackage","registry":"https://pypi.org","packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[{"filename":"agentic_proofkit-1.2.3-py3-none-any.whl","name":"agentic-proofkit","version":"1.2.3","sha256":"def"}]}`,
			want: "canonical pypi_registry_release authority metadata",
		},
		"wrong registry URL": {
			json: `{"artifactKind":"proofkit.pypi-registry-artifact-set.v1","schemaVersion":1,"authorityChannel":"pypi_registry_release","authorityValidator":"pypiregistry","registry":"https://example.test","packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[{"filename":"agentic_proofkit-1.2.3-py3-none-any.whl","name":"agentic-proofkit","version":"1.2.3","sha256":"def"}]}`,
			want: "canonical pypi_registry_release registry URL",
		},
		"candidate-shaped evidence": {
			json: `{"artifactKind":"proofkit.pypi-registry-artifact-set.v1","schemaVersion":1,"authorityChannel":"pypi_registry_release","authorityValidator":"pypiregistry","registry":"https://pypi.org","packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[{"filename":"agentic_proofkit-1.2.3-py3-none-any.whl","name":"agentic-proofkit","version":"1.2.3","sha256":"def"}]}`,
			want: "post-publish PyPI JSON API source",
		},
	}
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pypi-release.json")
			writeFile(t, path, item.json)

			_, err := optionalPyPIRegistrySet(path)
			if err == nil || !strings.Contains(err.Error(), item.want) {
				t.Fatalf("optionalPyPIRegistrySet() error=%v, want %q", err, item.want)
			}
		})
	}
}

func TestPyPIRegistryEvidenceAdmitsCompletePostPublishShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pypi-release.json")
	writeFile(t, path, `{"artifactKind":"proofkit.pypi-registry-artifact-set.v1","schemaVersion":1,"authorityChannel":"pypi_registry_release","authorityValidator":"pypiregistry","registry":"https://pypi.org","source":"post-publish PyPI JSON API","packageName":"agentic-proofkit","packageVersion":"1.2.3","packages":[{"abiTag":"none","binarySha256":"bin","filename":"agentic_proofkit-1.2.3-py3-none-any.whl","name":"agentic-proofkit","packageType":"bdist_wheel","platformSuffix":"any","platformTag":"any","pythonTag":"py3","sha256":"def","url":"https://files.pythonhosted.org/packages/example.whl","version":"1.2.3","wheelTag":"py3-none-any"}],"nonClaims":["PyPI registry identity does not prove consumer installation."]}`)

	out, err := optionalPyPIRegistrySet(path)
	if err != nil {
		t.Fatalf("optionalPyPIRegistrySet() error=%v", err)
	}
	if out.Source != releasechannel.PyPIRegistryEvidenceSource || len(out.Packages) != 1 {
		t.Fatalf("optionalPyPIRegistrySet() = %#v, want one post-publish package", out)
	}
}

func TestReleaseAssetsRejectStalePackageArtifacts(t *testing.T) {
	root := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
	for _, dir := range []string{"artifacts/package", "artifacts/pypi", "artifacts/release"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	writeFile(t, "artifacts/package/agentic-proofkit-1.2.3.tgz", "expected")
	writeFile(t, "artifacts/package/stale.tgz", "stale")
	writeFile(t, "artifacts/pypi/agentic_proofkit-1.2.3-py3-none-any.whl", "wheel")
	writeFile(t, "artifacts/release/sbom.cdx.json", "{}")

	_, _, _, err = releaseAssets(
		[]packRecord{{Filename: "agentic-proofkit-1.2.3.tgz", Name: "agentic-proofkit", Version: "1.2.3", Integrity: "sha512-x", Shasum: "abc"}},
		&pythonPackageSet{Packages: []pythonWheelRecord{{Filename: "agentic_proofkit-1.2.3-py3-none-any.whl"}}},
	)
	if err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("releaseAssets() error=%v, want unexpected stale package artifact", err)
	}
}

func TestOptionalRegistryInstallEvidenceIsAllOrNone(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "root-install-help.txt"), "help")

	_, err := optionalRegistryInstallEvidence(root)
	if err == nil || !strings.Contains(err.Error(), "registry install evidence is partial") {
		t.Fatalf("optionalRegistryInstallEvidence() error=%v, want partial evidence rejection", err)
	}
}

func TestOptionalRegistryInstallEvidenceAdmitsCompleteEvidence(t *testing.T) {
	root := t.TempDir()
	for _, file := range []string{
		"audit-signatures.txt",
		"published-registry-artifact-set.json",
		"root-install-help.txt",
		"root-install-json-failed.json",
		"root-install-json-success.json",
		"root-install-package-lock.json",
	} {
		writeFile(t, filepath.Join(root, file), file)
	}

	evidence, err := optionalRegistryInstallEvidence(root)
	if err != nil {
		t.Fatalf("optionalRegistryInstallEvidence() error=%v", err)
	}
	if evidence == nil ||
		evidence.AuditSignaturesSha256 == "" ||
		evidence.FailedReportSha256 == "" ||
		evidence.HelpOutputSha256 == "" ||
		evidence.PackageLockSha256 == "" ||
		evidence.PublishedArtifactSetSha256 == "" ||
		evidence.SuccessReportSha256 == "" {
		t.Fatalf("optionalRegistryInstallEvidence() = %#v, want complete digest evidence", evidence)
	}
}

func assertChannel(t *testing.T, channel channelEvidence, kind string, validator string, environment string) {
	t.Helper()
	if channel.Kind != kind {
		t.Fatalf("%s kind=%q, want %q", channel.AuthorityChannel, channel.Kind, kind)
	}
	if channel.AuthorityValidator != validator {
		t.Fatalf("%s authorityValidator=%q, want %q", channel.Kind, channel.AuthorityValidator, validator)
	}
	if channel.PublisherEnvironment != environment {
		t.Fatalf("%s publisherEnvironment=%q, want %q", channel.Kind, channel.PublisherEnvironment, environment)
	}
	if (channel.AuthorityChannel == string(releasechannel.RegistryRelease) || channel.AuthorityChannel == string(releasechannel.PyPIRegistryRelease)) &&
		environment != "" &&
		channel.TrustedPublisher == nil {
		t.Fatalf("%s trustedPublisher is missing", channel.Kind)
	}
}

func completeTrustedPublishers() trustedPublisherSet {
	return trustedPublisherSet{
		NPM: &trustedpublisher.Identity{
			Environment: "npm-production",
			Job:         "publish",
			ProjectName: "agentic-proofkit",
			Provider:    "npm",
			Registry:    releasechannel.NPMRegistryURL,
			Repository:  "research-engineering/agentic-proofkit",
			WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
		},
		PyPI: &trustedpublisher.Identity{
			Environment: "pypi",
			Job:         "publish-pypi",
			ProjectName: "agentic-proofkit",
			Provider:    "pypi",
			Registry:    releasechannel.PyPIRegistryURL,
			Repository:  "research-engineering/agentic-proofkit",
			WorkflowRef: "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
		},
	}
}

func channelsByAuthority(t *testing.T, channels []channelEvidence) map[string]channelEvidence {
	t.Helper()
	byAuthority := map[string]channelEvidence{}
	for _, channel := range channels {
		if _, ok := releasechannel.CanonicalID(channel.AuthorityChannel); !ok {
			t.Fatalf("channel %s has unknown authorityChannel %s", channel.Kind, channel.AuthorityChannel)
		}
		if _, ok := byAuthority[channel.AuthorityChannel]; ok {
			t.Fatalf("duplicate authorityChannel %s", channel.AuthorityChannel)
		}
		byAuthority[channel.AuthorityChannel] = channel
		if channel.AuthorityValidator == "" {
			t.Fatalf("channel %s missing authority validator", channel.Kind)
		}
	}
	return byAuthority
}

func containsText(values []string, expected string) bool {
	for _, value := range values {
		if strings.Contains(value, expected) {
			return true
		}
	}
	return false
}

func completePyPIRegistrySet() *pypiRegistrySet {
	return &pypiRegistrySet{
		ArtifactKind:       "proofkit.pypi-registry-artifact-set.v1",
		AuthorityChannel:   string(releasechannel.PyPIRegistryRelease),
		AuthorityValidator: "pypiregistry",
		PackageName:        "agentic-proofkit",
		PackageVersion:     "1.2.3",
		Registry:           releasechannel.PyPIRegistryURL,
		SchemaVersion:      1,
		Source:             releasechannel.PyPIRegistryEvidenceSource,
		Packages: []pythonWheelRecord{{
			AbiTag:         "none",
			BinarySha256:   "bin",
			Filename:       "agentic_proofkit-1.2.3-py3-none-any.whl",
			Name:           "agentic-proofkit",
			PackageType:    "bdist_wheel",
			PlatformSuffix: "any",
			PlatformTag:    "any",
			PythonTag:      "py3",
			Sha256:         "def",
			URL:            "https://files.pythonhosted.org/packages/example.whl",
			Version:        "1.2.3",
			WheelTag:       "py3-none-any",
		}},
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
