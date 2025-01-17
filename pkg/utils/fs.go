package utils

import (
	"fmt"
	"io"
	"io/fs"
	"k8s.io/client-go/util/homedir"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func Exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return false
	}
	return true
}

func IsFile(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.Mode().IsRegular()
}

func IsDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
}

func Touch(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to touch %v: %w", path, err)
	}
	return f.Close()
}

func CopyFile(src string, dst string) error {
	if !IsFile(src) {
		return fmt.Errorf("%s is not a regular file", src)
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	return CopyFileStream(f, dst)
}

func FsCopyFile(srcFs fs.FS, src, dst string) error {
	src = strings.ReplaceAll(src, string(os.PathSeparator), "/")
	source, err := srcFs.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	sourceFileStat, err := source.Stat()
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	return CopyFileStream(source, dst)
}

func CopyFileStream(src io.Reader, dst string) error {
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, src)
	return err
}

func FsCopyDir(srcFs fs.FS, src string, dst string) error {
	var err error
	var fds []fs.DirEntry

	src = strings.ReplaceAll(src, string(os.PathSeparator), "/")

	if fds, err = fs.ReadDir(srcFs, src); err != nil {
		return err
	}
	if err = os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := filepath.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = FsCopyDir(srcFs, srcfp, dstfp); err != nil {
				return err
			}
		} else {
			if err = FsCopyFile(srcFs, srcfp, dstfp); err != nil {
				return err
			}
		}
	}
	return nil
}

func CopyDir(src string, dst string) error {
	return FsCopyDir(os.DirFS(src), ".", dst)
}

func ExpandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		p = homedir.HomeDir() + p[1:]
	}
	return p
}
