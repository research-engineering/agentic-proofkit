//go:build darwin || linux

package repositorytransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPreparationResidueRejectsSpecialFileWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, nil)
	if err := unix.Mkfifo(filepath.Join(root, journalTemp), 0o600); err != nil {
		t.Fatal(err)
	}
	before := residueTree(t, root)
	got, err := InspectPreparationResidue(context.Background(), root)
	residueAssertError(t, err, ErrResidueIneligible)
	if got != (PreparationResidueObservation{}) || !reflect.DeepEqual(before, residueTree(t, root)) {
		t.Fatal("special file changed or admitted")
	}
}

type residueOwnershipInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info residueOwnershipInfo) Sys() any { return &info.stat }

func TestPreparationResidueRejectsForeignOwnerOperand(t *testing.T) {
	root := t.TempDir()
	residueFixture(t, root, []byte("partial"))
	for _, name := range []string{ControlRoot, ControlDirectory, activeDirectory, journalTemp} {
		info := residueStat(t, root, name)
		stat := *info.Sys().(*syscall.Stat_t)
		stat.Uid = uint32(os.Geteuid()) + 1
		if _, err := residueNodeValue(residueOwnershipInfo{FileInfo: info, stat: stat}, filepath.Base(name), info.IsDir()); !errors.Is(err, ErrResidueIneligible) {
			t.Fatalf("foreign uid operand accepted: %v", err)
		}
	}
}
