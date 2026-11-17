package admit

import "strings"

// RepoFilePathsOverlap compares admitted, nonempty POSIX file paths exactly.
// It does not apply host-dependent aliases or claim filesystem materialization.
func RepoFilePathsOverlap(left, right string) bool {
	return left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}
