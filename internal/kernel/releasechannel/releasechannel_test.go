package releasechannel

import "testing"

func TestDefinitionsHaveUniqueCanonicalIDsAndValidators(t *testing.T) {
	seen := map[string]struct{}{}
	for _, definition := range All() {
		if definition.ID == "" || definition.Kind == "" || definition.Role == "" || definition.AuthorityValidator == "" {
			t.Fatalf("definition has incomplete authority metadata: %#v", definition)
		}
		id := string(definition.ID)
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate release channel id %s", definition.ID)
		}
		seen[id] = struct{}{}
		canonical, ok := CanonicalID(id)
		if !ok || canonical != id {
			t.Fatalf("CanonicalID(%q) = %q, %v; want same canonical id", definition.ID, canonical, ok)
		}
	}
}

func TestNonAuthorityLabelsAndLegacyAliasesAreRejected(t *testing.T) {
	for _, value := range []string{
		"github-release",
		"github_release",
		"npm-registry-release",
		"npm_registry_release",
		"npm-tarball-pilot",
		"npm_tarball_pilot",
		"public-npm",
		"pypi",
		"pypi-registry-release",
		"python-wheel-candidate",
		"registry",
	} {
		if _, ok := CanonicalID(value); ok {
			t.Fatalf("non-authority label or alias %q must not canonicalize", value)
		}
	}
}

func TestIDSetContainsOnlyCanonicalAuthorityIDs(t *testing.T) {
	ids := IDSet()
	for _, label := range []string{"github-release", "public-npm", "pypi"} {
		if _, ok := ids[label]; ok {
			t.Fatalf("display label %q must not be admitted as a canonical authority id", label)
		}
	}
	for _, id := range []ID{GitHubReleaseArchive, PyPIRegistryRelease, PythonWheelCandidate, RegistryRelease, TarballPilot} {
		if _, ok := ids[string(id)]; !ok {
			t.Fatalf("canonical authority id %q missing from IDSet", id)
		}
	}
}
