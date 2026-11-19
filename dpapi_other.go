//go:build !windows

package protocol

import "os"

func protectBytes(plain []byte) ([]byte, error) {
	out := make([]byte, len(plain))
	copy(out, plain)
	return out, nil
}

func unprotectBytes(cipher []byte) ([]byte, error) {
	out := make([]byte, len(cipher))
	copy(out, cipher)
	return out, nil
}

func applyRestrictedACL(targetPath string, isDir bool) error {
	mode := os.FileMode(0o600)
	if isDir {
		mode = 0o700
	}
	return os.Chmod(targetPath, mode)
}
