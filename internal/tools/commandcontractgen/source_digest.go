package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
)

func digestSourcePath(directory, relative string) (string, error) {
	if !safeRelativePath(relative) {
		return "", errors.New("native source path must be repository-relative")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := sourcePathInfo(root, relative)
	if err != nil {
		return "", err
	}
	paths := []string{}
	if info.IsDir() {
		err = fs.WalkDir(root.FS(), relative, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("native source must not contain symlinks")
			}
			if entry.IsDir() {
				return nil
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") && !strings.HasSuffix(name, "_generated.go") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
	} else {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return "", errors.New("native source contains no admitted Go files")
	}
	hash := sha256.New()
	for _, path := range paths {
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		if err := hashSourceFile(hash, root, path); err != nil {
			return "", err
		}
		hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func sourcePathInfo(root *os.Root, relative string) (os.FileInfo, error) {
	var info os.FileInfo
	path := ""
	for _, part := range strings.Split(relative, "/") {
		if path != "" {
			path += "/"
		}
		path += part
		var err error
		info, err = root.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("native source path must not contain symlinks")
		}
	}
	return info, nil
}

func hashSourceFile(writer io.Writer, root *os.Root, path string) error {
	info, err := sourcePathInfo(root, path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("native source must be a regular file")
	}
	file, err := root.Open(path)
	if err != nil {
		return err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return errors.Join(errors.New("native source changed before reading"), file.Close())
	}
	written, readErr := io.Copy(writer, file)
	final, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return err
	}
	current, err := sourcePathInfo(root, path)
	if err != nil || !os.SameFile(opened, current) || !os.SameFile(opened, final) || written != final.Size() || opened.Size() != final.Size() {
		return errors.New("native source changed while reading")
	}
	return nil
}
