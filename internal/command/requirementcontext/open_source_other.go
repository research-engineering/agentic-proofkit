//go:build !(darwin || linux)

package requirementcontext

import "os"

func openCatalogSourceFile(root *os.Root, path string) (*os.File, error) {
	return root.Open(path)
}
