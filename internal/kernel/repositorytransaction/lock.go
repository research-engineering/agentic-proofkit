package repositorytransaction

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type transactionLockMode uint8

const (
	transactionWriteLock transactionLockMode = iota
	transactionReadLock
)

func acquireTransactionLock(root *os.Root) (*transactionLock, error) {
	if err := ensureDirectory(root, ControlDirectory, 0o700); err != nil {
		return nil, err
	}
	return lockTransactionDirectory(root, transactionWriteLock)
}

func acquireExistingTransactionLock(root *os.Root) (*transactionLock, bool, error) {
	return acquireExistingLock(root, transactionWriteLock)
}

func acquireExistingLock(root *os.Root, mode transactionLockMode) (*transactionLock, bool, error) {
	exists, err := controlNamespaceExists(root)
	if err != nil || !exists {
		return nil, false, err
	}
	lock, err := lockTransactionDirectory(root, mode)
	return lock, true, err
}

func lockTransactionDirectory(root *os.Root, mode transactionLockMode) (*transactionLock, error) {
	if err := validatePrivateDirectory(root, ControlDirectory, 0o700); err != nil {
		return nil, err
	}
	routeInfo, err := root.Lstat(filepath.FromSlash(ControlDirectory))
	if err != nil || routeInfo.Mode()&os.ModeSymlink != 0 || !routeInfo.IsDir() {
		return nil, fmt.Errorf("repository transaction control directory is unsafe")
	}
	directory, err := root.Open(filepath.FromSlash(ControlDirectory))
	if err != nil {
		return nil, fmt.Errorf("open repository transaction lock")
	}
	handleInfo, err := directory.Stat()
	if err != nil || !os.SameFile(routeInfo, handleInfo) {
		if closeErr := closeReadResource(directory, "transaction lock admission"); closeErr != nil {
			return nil, closeErr
		}
		return nil, fmt.Errorf("repository transaction control directory changed during lock admission")
	}
	if err := lockDirectory(directory, mode); err != nil {
		if closeErr := closeReadResource(directory, "transaction lock admission"); closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	return &transactionLock{directory: directory}, nil
}

func (lock *transactionLock) release() {
	_ = lock.releaseChecked()
}

func (lock *transactionLock) releaseChecked() error {
	if lock == nil || lock.directory == nil {
		return nil
	}
	unlockErr := unlockDirectory(lock.directory)
	closeErr := lock.directory.Close()
	lock.directory = nil
	return errors.Join(unlockErr, closeErr)
}
