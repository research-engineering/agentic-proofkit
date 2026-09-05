package app

import "testing"

func TestProjectNavigationVersionEdgeRejectsUndeclaredPublicABIDrift(t *testing.T) {
	assertRejectsUndeclaredPublicABIDrift(t, readFrozenProjectNavigationPublicABI(t), readArchivedProjectNavigationContract, verifyCompleteProjectNavigationABIDiff)
}
