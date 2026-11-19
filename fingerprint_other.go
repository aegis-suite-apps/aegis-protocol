//go:build !windows

package protocol

import (
	"os"
	"runtime"
	"strings"
)

func readPosixMachineID() string {
	for _, candidate := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(candidate)
		if err == nil {
			if trimmed := strings.TrimSpace(string(data)); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

// ComputeMachineFingerprint computes a stable 64-char SHA-256 machine fingerprint on non-Windows hosts.
func ComputeMachineFingerprint() string {
	host, _ := os.Hostname()
	canonical := strings.Join([]string{
		"aegis-fp-v2",
		runtime.GOOS,
		normalizeTrait(readPosixMachineID()),
		normalizeTrait(host),
	}, "|")
	return HashFingerprint(canonical)
}
