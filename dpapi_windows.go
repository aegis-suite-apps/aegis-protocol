//go:build windows

package protocol

import (
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const cryptProtectLocalMachine = 0x4

func protectBytes(plain []byte) ([]byte, error) {
	return protectBytesWithScope(plain, false)
}

func protectBytesWithScope(plain []byte, machineScope bool) ([]byte, error) {
	if len(plain) == 0 {
		return []byte{}, nil
	}
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if machineScope {
		flags |= cryptProtectLocalMachine
	}
	inBlob := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var outBlob windows.DataBlob
	if err := windows.CryptProtectData(&inBlob, nil, nil, 0, nil, flags, &outBlob); err != nil {
		return nil, fmt.Errorf("dpapi protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	out := make([]byte, outBlob.Size)
	copy(out, unsafe.Slice(outBlob.Data, outBlob.Size))
	return out, nil
}

func unprotectBytes(cipher []byte) ([]byte, error) {
	if len(cipher) == 0 {
		return []byte{}, nil
	}
	inBlob := windows.DataBlob{Size: uint32(len(cipher)), Data: &cipher[0]}
	var outBlob windows.DataBlob
	if err := windows.CryptUnprotectData(&inBlob, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &outBlob); err != nil {
		return nil, fmt.Errorf("dpapi unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))
	out := make([]byte, outBlob.Size)
	copy(out, unsafe.Slice(outBlob.Data, outBlob.Size))
	return out, nil
}

func applyRestrictedACL(targetPath string, isDir bool) error {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return err
	}
	principal := current.Username
	if strings.HasPrefix(current.Uid, "S-") {
		principal = "*" + current.Uid
	}
	perm := ":(F)"
	if isDir {
		perm = ":(OI)(CI)F"
	}
	cmd := exec.Command(
		"icacls.exe",
		targetPath,
		"/inheritance:r",
		"/grant:r", principal+perm,
		"*S-1-5-18"+perm,
		"*S-1-5-32-544"+perm,
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
