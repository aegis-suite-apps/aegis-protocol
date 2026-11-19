import child_process from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { sha256Hex } from "./crypto";

export interface WindowsFingerprintTraits {
  machineGuid: string;
  hwProfileGuid: string;
  systemManufacturer: string;
  systemProductName: string;
  baseBoardProduct: string;
}

function normalizeTrait(value: string): string {
  return value.trim().toLowerCase();
}

/**
 * Formats a deterministic canonical Windows fingerprint string matching Go's implementation
 * byte-for-byte so Go and TypeScript agents on the same PC yield the exact same hash.
 */
export function canonicalWindowsFingerprint(traits: WindowsFingerprintTraits): string {
  return [
    "aegis-fp-v2",
    "windows",
    normalizeTrait(traits.machineGuid),
    normalizeTrait(traits.hwProfileGuid),
    normalizeTrait(traits.systemManufacturer),
    normalizeTrait(traits.systemProductName),
    normalizeTrait(traits.baseBoardProduct),
  ].join("|");
}

function readWindowsRegistryValue(keyPath: string, valueName: string): string {
  try {
    const res = child_process.spawnSync(
      "reg.exe",
      ["query", keyPath, "/v", valueName, "/reg:64"],
      { encoding: "utf8", windowsHide: true, timeout: 3000 },
    );
    if (res.status !== 0 || !res.stdout) return "";
    const regex = new RegExp(`^\\s*${valueName}\\s+REG_\\w+\\s+(.+)$`, "im");
    const match = regex.exec(res.stdout);
    return match?.[1]?.trim() ?? "";
  } catch {
    return "";
  }
}

function readPosixMachineId(): string {
  for (const candidate of ["/etc/machine-id", "/var/lib/dbus/machine-id"]) {
    try {
      const value = fs.readFileSync(candidate, "utf8").trim();
      if (value) return value;
    } catch {
      // Try next candidate.
    }
  }
  return "";
}

/** Computes a deterministic 64-character lowercase SHA-256 machine fingerprint. */
export function computeMachineFingerprint(): string {
  if (process.platform === "win32") {
    const canonical = canonicalWindowsFingerprint({
      machineGuid: readWindowsRegistryValue("HKLM\\SOFTWARE\\Microsoft\\Cryptography", "MachineGuid"),
      hwProfileGuid: readWindowsRegistryValue(
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
        "HwProfileGuid",
      ),
      systemManufacturer: readWindowsRegistryValue(
        "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SystemManufacturer",
      ),
      systemProductName: readWindowsRegistryValue(
        "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SystemProductName",
      ),
      baseBoardProduct: readWindowsRegistryValue(
        "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS",
        "BaseBoardProduct",
      ),
    });
    return sha256Hex(canonical);
  }

  const canonical = ["aegis-fp-v2", process.platform, normalizeTrait(readPosixMachineId()), normalizeTrait(os.hostname())].join("|");
  return sha256Hex(canonical);
}
