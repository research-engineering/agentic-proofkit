package releasechannel

import (
	"fmt"
	"sort"
)

type ID string

const (
	GitHubReleaseArchive ID = "github_release_archive"
	PyPIRegistryRelease  ID = "pypi_registry_release"
	PythonWheelCandidate ID = "python_wheel_candidate"
	RegistryRelease      ID = "registry_release"
	TarballPilot         ID = "tarball_pilot"
)

const (
	GitHubPackagesRegistryURL  = "https://npm.pkg.github.com"
	NPMRegistryURL             = "https://registry.npmjs.org"
	PyPIRegistryURL            = "https://pypi.org"
	PyPIRegistryEvidenceSource = "post-publish PyPI JSON API"
)

type Definition struct {
	AuthorityValidator string
	DisplayName        string
	ID                 ID
	Kind               string
	RegistryURL        string
	Role               string
}

var definitions = []Definition{
	{
		AuthorityValidator: "releasepreflight.github-release",
		DisplayName:        "GitHub Release archive",
		ID:                 GitHubReleaseArchive,
		Kind:               "github-release",
		Role:               "archive-provenance",
	},
	{
		AuthorityValidator: "pypiregistry",
		DisplayName:        "PyPI registry release",
		ID:                 PyPIRegistryRelease,
		Kind:               "pypi",
		RegistryURL:        PyPIRegistryURL,
		Role:               "python-uv",
	},
	{
		AuthorityValidator: "pythonpackage",
		DisplayName:        "Python wheel candidate",
		ID:                 PythonWheelCandidate,
		Kind:               "pypi-wheel-candidate",
		Role:               "python-uv-candidate",
	},
	{
		AuthorityValidator: "releaseauthority",
		DisplayName:        "npm registry release",
		ID:                 RegistryRelease,
		Kind:               "public-npm",
		RegistryURL:        NPMRegistryURL,
		Role:               "javascript-typescript-bun",
	},
	{
		AuthorityValidator: "releaseauthority",
		DisplayName:        "npm tarball pilot",
		ID:                 TarballPilot,
		Kind:               "npm-tarball",
		Role:               "local-pilot",
	},
}

func All() []Definition {
	out := append([]Definition{}, definitions...)
	sort.Slice(out, func(left, right int) bool {
		return out[left].ID < out[right].ID
	})
	return out
}

func IDSet() map[string]struct{} {
	out := map[string]struct{}{}
	for _, definition := range definitions {
		out[string(definition.ID)] = struct{}{}
	}
	return out
}

func Lookup(id ID) (Definition, bool) {
	for _, definition := range definitions {
		if definition.ID == id {
			return definition, true
		}
	}
	return Definition{}, false
}

func Must(id ID) Definition {
	definition, ok := Lookup(id)
	if !ok {
		panic(fmt.Sprintf("unknown release channel %q", id))
	}
	return definition
}

func CanonicalID(value string) (string, bool) {
	definition, ok := Lookup(ID(value))
	if !ok {
		return "", false
	}
	return string(definition.ID), true
}
