//go:build windows

package protocol

import "golang.org/x/sys/windows/registry"

func readRegString(path, valueName string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	val, _, err := key.GetStringValue(valueName)
	if err != nil {
		return ""
	}
	return val
}

// ComputeMachineFingerprint computes a stable composite 64-char SHA-256 fingerprint
// using 64-bit Windows Registry hardware/OS traits.
func ComputeMachineFingerprint() string {
	canonical := CanonicalWindowsFingerprint(WindowsFingerprintTraits{
		MachineGuid:        readRegString(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid"),
		HwProfileGuid:      readRegString(`SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001`, "HwProfileGuid"),
		SystemManufacturer: readRegString(`HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"),
		SystemProductName:  readRegString(`HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"),
		BaseBoardProduct:   readRegString(`HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardProduct"),
	})
	return HashFingerprint(canonical)
}
