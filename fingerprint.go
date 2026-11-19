package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type WindowsFingerprintTraits struct {
	MachineGuid        string
	HwProfileGuid      string
	SystemManufacturer string
	SystemProductName  string
	BaseBoardProduct   string
}

func normalizeTrait(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// CanonicalWindowsFingerprint produces the exact canonical string shared with the
// TypeScript SDK before hashing with SHA-256.
func CanonicalWindowsFingerprint(traits WindowsFingerprintTraits) string {
	return strings.Join([]string{
		"aegis-fp-v2",
		"windows",
		normalizeTrait(traits.MachineGuid),
		normalizeTrait(traits.HwProfileGuid),
		normalizeTrait(traits.SystemManufacturer),
		normalizeTrait(traits.SystemProductName),
		normalizeTrait(traits.BaseBoardProduct),
	}, "|")
}

// HashFingerprint returns lowercase 64-character SHA-256 hex of a canonical fingerprint string.
func HashFingerprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
