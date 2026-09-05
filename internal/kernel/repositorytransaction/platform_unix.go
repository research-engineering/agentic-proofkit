//go:build darwin || linux

package repositorytransaction

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func platformFileIdentity(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("repository filesystem identity is unavailable")
	}
	return fmt.Sprintf("%d:%d", uint64(stat.Dev), uint64(stat.Ino)), nil
}

func platformOwnedByCurrentUser(info os.FileInfo) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("repository filesystem ownership is unavailable")
	}
	return stat.Uid == uint32(os.Geteuid()), nil
}

func platformSameFilesystem(left, right os.FileInfo) (bool, error) {
	l, leftOK := left.Sys().(*syscall.Stat_t)
	r, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK {
		return false, fmt.Errorf("repository filesystem identity is unavailable")
	}
	return l.Dev == r.Dev, nil
}

func openNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
}

func lockDirectory(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrBusy
		}
		return fmt.Errorf("lock repository transaction directory")
	}
	return nil
}

func unlockDirectory(file *os.File) error {
	if err := unix.Flock(int(file.Fd()), unix.LOCK_UN); err != nil {
		return fmt.Errorf("unlock repository transaction directory")
	}
	return nil
}
