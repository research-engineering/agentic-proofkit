package releasepublisher

import (
	"fmt"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/releasechannel"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/trustedpublisher"
)

const workflowFile = ".github/workflows/release.yml"

func ExpectedForAuthorityChannel(authorityChannel string, projectName string, projectVersion string, repository string) (trustedpublisher.Expected, bool) {
	workflowRef := fmt.Sprintf("%s/%s@refs/tags/v%s", repository, workflowFile, projectVersion)
	switch authorityChannel {
	case string(releasechannel.RegistryRelease):
		return trustedpublisher.Expected{
			Environment: "npm-production",
			Job:         "publish",
			ProjectName: projectName,
			Provider:    "npm",
			Registry:    releasechannel.NPMRegistryURL,
			Repository:  repository,
			WorkflowRef: workflowRef,
		}, true
	case string(releasechannel.PyPIRegistryRelease):
		return trustedpublisher.Expected{
			Environment: "pypi",
			Job:         "publish-pypi",
			ProjectName: projectName,
			Provider:    "pypi",
			Registry:    releasechannel.PyPIRegistryURL,
			Repository:  repository,
			WorkflowRef: workflowRef,
		}, true
	default:
		return trustedpublisher.Expected{}, false
	}
}

func FromEnvForAuthorityChannel(authorityChannel string, projectName string, projectVersion string, repository string, getenv func(string) string) (trustedpublisher.Identity, error) {
	expected, ok := ExpectedForAuthorityChannel(authorityChannel, projectName, projectVersion, repository)
	if !ok {
		return trustedpublisher.Identity{}, fmt.Errorf("%s does not use a trusted publisher identity", authorityChannel)
	}
	return trustedpublisher.FromEnv(envPrefix(authorityChannel), expected, getenv)
}

func AdmitForAuthorityChannel(identity trustedpublisher.Identity, authorityChannel string, projectName string, projectVersion string, repository string) (trustedpublisher.Identity, error) {
	expected, ok := ExpectedForAuthorityChannel(authorityChannel, projectName, projectVersion, repository)
	if !ok {
		return trustedpublisher.Identity{}, fmt.Errorf("%s does not use a trusted publisher identity", authorityChannel)
	}
	return trustedpublisher.Admit(identity, expected, authorityChannel)
}

func envPrefix(authorityChannel string) string {
	switch authorityChannel {
	case string(releasechannel.RegistryRelease):
		return "PROOFKIT_NPM_TRUSTED_PUBLISHER"
	case string(releasechannel.PyPIRegistryRelease):
		return "PROOFKIT_PYPI_TRUSTED_PUBLISHER"
	default:
		return "PROOFKIT_TRUSTED_PUBLISHER"
	}
}
