package releasepublisher

import (
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
)

func TestExpectedForAuthorityChannel(t *testing.T) {
	npm, ok := ExpectedForAuthorityChannel(string(releasechannel.RegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit")
	if !ok {
		t.Fatalf("npm channel did not return expected trusted publisher identity")
	}
	if npm.Provider != "npm" || npm.Registry != releasechannel.NPMRegistryURL || npm.Job != "publish" || npm.Environment != "npm-production" {
		t.Fatalf("npm expected identity = %#v", npm)
	}
	if npm.WorkflowRef != "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3" {
		t.Fatalf("npm workflow ref=%q", npm.WorkflowRef)
	}

	pypi, ok := ExpectedForAuthorityChannel(string(releasechannel.PyPIRegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit")
	if !ok {
		t.Fatalf("pypi channel did not return expected trusted publisher identity")
	}
	if pypi.Provider != "pypi" || pypi.Registry != releasechannel.PyPIRegistryURL || pypi.Job != "publish-pypi" || pypi.Environment != "pypi" {
		t.Fatalf("pypi expected identity = %#v", pypi)
	}

	if _, ok := ExpectedForAuthorityChannel(string(releasechannel.GitHubReleaseArchive), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit"); ok {
		t.Fatalf("github archive should not use trusted publisher identity")
	}
}

func TestFromEnvForAuthorityChannel(t *testing.T) {
	values := map[string]string{
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_ENVIRONMENT":  "npm-production",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_JOB":          "publish",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROJECT":      "agentic-proofkit",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROVIDER":     "npm",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REGISTRY":     releasechannel.NPMRegistryURL,
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REPOSITORY":   "research-engineering/agentic-proofkit",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_WORKFLOW_REF": "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	identity, err := FromEnvForAuthorityChannel(string(releasechannel.RegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit", func(key string) string {
		return values[key]
	})
	if err != nil {
		t.Fatalf("FromEnvForAuthorityChannel() error = %v", err)
	}
	if identity.Provider != "npm" || identity.Environment != "npm-production" {
		t.Fatalf("identity=%#v", identity)
	}
}

func TestFromEnvForAuthorityChannelRejectsMismatchedIdentity(t *testing.T) {
	values := map[string]string{
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_ENVIRONMENT":  "npm-production",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_JOB":          "publish",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROJECT":      "agentic-proofkit",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_PROVIDER":     "npm",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REGISTRY":     releasechannel.NPMRegistryURL,
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_REPOSITORY":   "research-engineering/other",
		"PROOFKIT_NPM_TRUSTED_PUBLISHER_WORKFLOW_REF": "research-engineering/other/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	_, err := FromEnvForAuthorityChannel(string(releasechannel.RegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit", func(key string) string {
		return values[key]
	})
	if err == nil {
		t.Fatalf("FromEnvForAuthorityChannel() admitted wrong repository")
	}
}

func TestFromEnvForAuthorityChannelUsesPyPIPrefix(t *testing.T) {
	values := map[string]string{
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_ENVIRONMENT":  "pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_JOB":          "publish-pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_PROJECT":      "agentic-proofkit",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_PROVIDER":     "pypi",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_REGISTRY":     releasechannel.PyPIRegistryURL,
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_REPOSITORY":   "research-engineering/agentic-proofkit",
		"PROOFKIT_PYPI_TRUSTED_PUBLISHER_WORKFLOW_REF": "research-engineering/agentic-proofkit/.github/workflows/release.yml@refs/tags/v1.2.3",
	}
	identity, err := FromEnvForAuthorityChannel(string(releasechannel.PyPIRegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit", func(key string) string {
		return values[key]
	})
	if err != nil {
		t.Fatalf("FromEnvForAuthorityChannel() error = %v", err)
	}
	if identity.Provider != "pypi" || identity.Environment != "pypi" {
		t.Fatalf("identity=%#v", identity)
	}
}

func TestAdmitForAuthorityChannelRejectsUnsupportedAndWrongTuple(t *testing.T) {
	expected, ok := ExpectedForAuthorityChannel(string(releasechannel.RegistryRelease), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit")
	if !ok {
		t.Fatalf("npm channel did not return expected identity")
	}
	identity := identityFromExpected(expected)
	if _, err := AdmitForAuthorityChannel(identity, string(releasechannel.GitHubReleaseArchive), "agentic-proofkit", "1.2.3", "research-engineering/agentic-proofkit"); err == nil {
		t.Fatalf("AdmitForAuthorityChannel() admitted unsupported channel")
	}
	if _, err := AdmitForAuthorityChannel(identity, string(releasechannel.RegistryRelease), "other-project", "1.2.3", "research-engineering/agentic-proofkit"); err == nil {
		t.Fatalf("AdmitForAuthorityChannel() admitted wrong project")
	}
	if _, err := AdmitForAuthorityChannel(identity, string(releasechannel.RegistryRelease), "agentic-proofkit", "1.2.4", "research-engineering/agentic-proofkit"); err == nil {
		t.Fatalf("AdmitForAuthorityChannel() admitted wrong version")
	}
}

func identityFromExpected(expected trustedpublisher.Expected) trustedpublisher.Identity {
	return trustedpublisher.Identity(expected)
}
