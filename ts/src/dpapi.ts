import child_process from "node:child_process";
import fs from "node:fs";

const CRYPTPROTECT_UI_FORBIDDEN = 0x01;

type NativeDpapi = {
  protect(plain: Uint8Array): Uint8Array;
  unprotect(cipher: Uint8Array): Uint8Array;
};

let cachedNativeDpapi: NativeDpapi | null | undefined;

function loadBunDpapi(): NativeDpapi | null {
  if (cachedNativeDpapi !== undefined) return cachedNativeDpapi;
  if (process.platform !== "win32" || typeof (globalThis as { Bun?: unknown }).Bun === "undefined") {
    cachedNativeDpapi = null;
    return null;
  }

  try {
    // Dynamic import avoids breaking non-Bun TypeScript consumers (e.g. Cloudflare Workers).
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const ffi = require("bun:ffi") as typeof import("bun:ffi");
    const crypt32 = ffi.dlopen("crypt32.dll", {
      CryptProtectData: {
        args: [
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.u32,
          ffi.FFIType.ptr,
        ],
        returns: ffi.FFIType.bool,
      },
      CryptUnprotectData: {
        args: [
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.ptr,
          ffi.FFIType.u32,
          ffi.FFIType.ptr,
        ],
        returns: ffi.FFIType.bool,
      },
    });
    const kernel32 = ffi.dlopen("kernel32.dll", {
      LocalFree: { args: [ffi.FFIType.u64], returns: ffi.FFIType.u64 },
      RtlMoveMemory: { args: [ffi.FFIType.ptr, ffi.FFIType.u64, ffi.FFIType.u64], returns: ffi.FFIType.void },
    });

    const makeBlob = (bytes: Uint8Array) => {
      const buf = new ArrayBuffer(16);
      const dv = new DataView(buf);
      dv.setUint32(0, bytes.byteLength, true);
      dv.setBigUint64(8, BigInt(ffi.ptr(bytes)), true);
      return { view: new Uint8Array(buf), bytes };
    };

    const readBlob = (blobView: Uint8Array): Uint8Array => {
      const dv = new DataView(blobView.buffer, blobView.byteOffset, 16);
      const size = dv.getUint32(0, true);
      const dataPtr = dv.getBigUint64(8, true);
      if (size === 0 || dataPtr === 0n) {
        return new Uint8Array(0);
      }
      const copy = new Uint8Array(size);
      try {
        kernel32.symbols.RtlMoveMemory(ffi.ptr(copy), dataPtr, BigInt(size));
      } finally {
        kernel32.symbols.LocalFree(dataPtr);
      }
      return copy;
    };

    cachedNativeDpapi = {
      protect(plain: Uint8Array): Uint8Array {
        if (plain.byteLength === 0) return new Uint8Array(0);
        const inBlob = makeBlob(plain);
        const outBlob = new Uint8Array(16);
        const ok = crypt32.symbols.CryptProtectData(
          ffi.ptr(inBlob.view),
          null,
          null,
          null,
          null,
          CRYPTPROTECT_UI_FORBIDDEN,
          ffi.ptr(outBlob),
        );
        if (!ok) throw new Error("Win32 CryptProtectData failed");
        return readBlob(outBlob);
      },
      unprotect(cipher: Uint8Array): Uint8Array {
        if (cipher.byteLength === 0) return new Uint8Array(0);
        const inBlob = makeBlob(cipher);
        const outBlob = new Uint8Array(16);
        const ok = crypt32.symbols.CryptUnprotectData(
          ffi.ptr(inBlob.view),
          null,
          null,
          null,
          null,
          CRYPTPROTECT_UI_FORBIDDEN,
          ffi.ptr(outBlob),
        );
        if (!ok) throw new Error("Win32 CryptUnprotectData failed");
        return readBlob(outBlob);
      },
    };
  } catch {
    cachedNativeDpapi = null;
  }

  return cachedNativeDpapi;
}

function nodeDpapi(mode: "protect" | "unprotect", input: Uint8Array): Uint8Array {
  if (input.byteLength === 0) return new Uint8Array(0);
  const psScript =
    mode === "protect"
      ? "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String(([Console]::In.ReadToEnd()).Trim()); $o=[Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($o))"
      : "Add-Type -AssemblyName System.Security; $b=[Convert]::FromBase64String(([Console]::In.ReadToEnd()).Trim()); try { $o=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser) } catch { $o=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine) }; [Console]::Out.Write([Convert]::ToBase64String($o))";

  for (const shell of ["powershell.exe", "pwsh.exe"]) {
    const res = child_process.spawnSync(
      shell,
      ["-NoProfile", "-NonInteractive", "-Command", psScript],
      {
        input: Buffer.from(input).toString("base64"),
        encoding: "utf8",
        windowsHide: true,
        timeout: 10_000,
      },
    );
    if (!res.error && res.status === 0 && res.stdout.trim()) {
      return new Uint8Array(Buffer.from(res.stdout.trim(), "base64"));
    }
  }
  throw new Error(`Windows DPAPI (${mode}) failed under Node.js runtime`);
}

/** Protects bytes with Windows DPAPI (current user scope). Uses native bun:ffi in Bun and ProtectedData fallback in Node. */
export function protectSecretBytes(plain: Uint8Array): Uint8Array {
  if (process.platform !== "win32") return plain;
  const native = loadBunDpapi();
  return native ? native.protect(plain) : nodeDpapi("protect", plain);
}

/** Unprotects bytes protected with Windows DPAPI. Uses native bun:ffi in Bun and ProtectedData fallback in Node. */
export function unprotectSecretBytes(cipher: Uint8Array): Uint8Array {
  if (process.platform !== "win32") return cipher;
  const native = loadBunDpapi();
  return native ? native.unprotect(cipher) : nodeDpapi("unprotect", cipher);
}

/** Restricts filesystem permissions to the current user (plus Administrators/SYSTEM on Windows). */
export function applyRestrictedPermissions(targetPath: string, isDirectory = false): void {
  if (process.platform !== "win32") {
    try {
      fs.chmodSync(targetPath, isDirectory ? 0o700 : 0o600);
    } catch {
      // Ignore on unsupported filesystems.
    }
    return;
  }

  const currentUser = process.env.USERNAME || "Administrators";
  const grant = isDirectory ? `${currentUser}:(OI)(CI)F` : `${currentUser}:(F)`;
  const systemGrant = isDirectory ? "*S-1-5-18:(OI)(CI)F" : "*S-1-5-18:(F)";
  const adminGrant = isDirectory ? "*S-1-5-32-544:(OI)(CI)F" : "*S-1-5-32-544:(F)";

  child_process.spawnSync(
    "icacls.exe",
    [targetPath, "/inheritance:r", "/grant:r", grant, systemGrant, adminGrant],
    { encoding: "utf8", windowsHide: true },
  );
}
