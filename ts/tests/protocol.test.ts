import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vectors from "../../vectors/golden-vectors.json";
import {
  AegisAgent,
  AgentClient,
  AgentStore,
  canonicalWindowsFingerprint,
  computeMachineFingerprint,
  evaluateAccess,
  importPublicKeyBase64,
  importPublicKeyPem,
  normalizeBaseUrl,
  protectSecretBytes,
  sha256Hex,
  unprotectSecretBytes,
  verifyLease,
} from "../src/index";

describe("aegis-protocol v2 TypeScript", () => {
  test("canonical Windows fingerprint matches golden vector", () => {
    const canonical = canonicalWindowsFingerprint(vectors.windows_traits);
    expect(canonical).toBe(vectors.canonical_fingerprint);
    expect(sha256Hex(canonical)).toBe(vectors.fingerprint_hash);
    expect(computeMachineFingerprint()).toMatch(/^[0-9a-f]{64}$/);
  });

  test("verifies golden Ed25519 JWT via both Base64 SPKI and PEM public keys", async () => {
    const keyB64 = await importPublicKeyBase64(vectors.spki_base64);
    const keyPem = await importPublicKeyPem(vectors.public_pem);
    const now = new Date((vectors.iat + 60) * 1000);

    const c1 = await verifyLease(vectors.tokens.active_backup, {
      issuer: vectors.issuer,
      publicKeys: { [vectors.key_id]: keyB64 },
      installId: vectors.install_id,
      machineFingerprintHash: vectors.fingerprint_hash,
      now,
    });
    expect(c1.product).toBe("aegis-backup");
    expect(c1.enforcement).toBe("strict_rfm");

    const c2 = await verifyLease(vectors.tokens.active_backup, {
      issuer: vectors.issuer,
      publicKeys: { [vectors.key_id]: keyPem },
      installId: vectors.install_id,
      machineFingerprintHash: vectors.fingerprint_hash,
      now,
    });
    expect(c2.lease_nonce).toBe("nonce-0001-abcd");
  });

  test("rejects wrong audience and wrong fingerprint", async () => {
    const key = await importPublicKeyBase64(vectors.spki_base64);
    const now = new Date((vectors.iat + 60) * 1000);

    await expect(
      verifyLease(vectors.tokens.wrong_audience, {
        issuer: vectors.issuer,
        publicKeys: { [vectors.key_id]: key },
        installId: vectors.install_id,
        machineFingerprintHash: vectors.fingerprint_hash,
        now,
      }),
    ).rejects.toThrow();

    await expect(
      verifyLease(vectors.tokens.active_backup, {
        issuer: vectors.issuer,
        publicKeys: { [vectors.key_id]: key },
        installId: vectors.install_id,
        machineFingerprintHash: "0".repeat(64),
        now,
      }),
    ).rejects.toThrow(/fingerprint/i);
  });

  test("Guard evaluates ALLOW -> GRACE -> RFM, preserving restore in strict_rfm and soft gate in advisory", async () => {
    const key = await importPublicKeyBase64(vectors.spki_base64);
    const activeClaims = await verifyLease(vectors.tokens.active_backup, {
      issuer: vectors.issuer,
      publicKeys: { [vectors.key_id]: key },
      installId: vectors.install_id,
      now: new Date((vectors.iat + 60) * 1000),
    });

    // Day 1: ALLOW
    const dAllow = evaluateAccess({
      hasEnrollment: true,
      claims: activeClaims,
      now: new Date((vectors.iat + 86400) * 1000),
    });
    expect(dAllow.state).toBe("ALLOW");
    expect(dAllow.allowed).toBe(true);

    // Day 5 (past 3d cache, within 10d grace): GRACE
    const dGrace = evaluateAccess({
      hasEnrollment: true,
      claims: activeClaims,
      now: new Date((vectors.iat + 5 * 86400) * 1000),
    });
    expect(dGrace.state).toBe("GRACE");
    expect(dGrace.allowed).toBe(true);

    // Day 12 (past grace): RFM blocks backup but allows restore
    const dRfmBackup = evaluateAccess({
      hasEnrollment: true,
      claims: activeClaims,
      now: new Date((vectors.iat + 12 * 86400) * 1000),
      rfmAllowed: false,
    });
    expect(dRfmBackup.state).toBe("RFM");
    expect(dRfmBackup.allowed).toBe(false);

    const dRfmRestore = evaluateAccess({
      hasEnrollment: true,
      claims: activeClaims,
      now: new Date((vectors.iat + 12 * 86400) * 1000),
      rfmAllowed: true,
    });
    expect(dRfmRestore.state).toBe("RFM");
    expect(dRfmRestore.allowed).toBe(true);

    // Clock rollback: system time goes backwards, monotonic security clamps forward
    const dRollback = evaluateAccess({
      hasEnrollment: true,
      claims: activeClaims,
      security: {
        last_lease_issued_at: vectors.iat,
        last_server_time: vectors.iat + 12 * 86400,
        last_lease_nonce: "nonce-0001-abcd",
      },
      now: new Date((vectors.iat + 60) * 1000),
      rfmAllowed: false,
    });
    expect(dRollback.clockRollbackDetected).toBe(true);
    expect(dRollback.state).toBe("RFM");
    expect(dRollback.allowed).toBe(false);

    // Advisory mode (aegis-shell): allows opening with consent even when expired
    const shellClaims = await verifyLease(vectors.tokens.advisory_shell_expired, {
      issuer: vectors.issuer,
      publicKeys: { [vectors.key_id]: key },
      installId: vectors.install_id,
      now: new Date((vectors.iat + 300) * 1000),
    });
    const dShell = evaluateAccess({
      hasEnrollment: true,
      claims: shellClaims,
      now: new Date((vectors.iat + 300) * 1000),
    });
    expect(dShell.state).toBe("RFM");
    expect(dShell.allowed).toBe(true);
    expect(dShell.requiresConsent).toBe(true);
  });

  test("DPAPI round-trip and AgentStore enroll + offline checkAccess + revoke purge", async () => {
    const raw = new TextEncoder().encode("tok-secret-roundtrip");
    const cipher = protectSecretBytes(raw);
    expect(new TextDecoder().decode(unprotectSecretBytes(cipher))).toBe("tok-secret-roundtrip");

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "aegis-proto-test-"));
    try {
      const store = new AgentStore(dir);
      const key = await importPublicKeyBase64(vectors.spki_base64);
      const fp = vectors.fingerprint_hash;

      let step = 0;
      const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
        const u = String(url);
        step += 1;
        if (u.endsWith("/api/v2/agent/enroll")) {
          expect((init?.headers as Record<string, string>).authorization).toBe("Bearer CODE-123");
          return new Response(
            JSON.stringify({
              protocol_version: 2,
              install_id: vectors.install_id,
              installation_token: "install-secret-token-012345",
              lease_token: vectors.tokens.active_backup,
              config: {
                worker_base_url: vectors.issuer,
                product: "aegis-backup",
                app_name: "AegisBA Enterprise",
                app_target: "",
                equipment_name: "PC-TEST",
                contact_name: "Soporte TI",
                ticket_url: `${vectors.issuer}/help`,
                protocol_version: 2,
              },
            }),
            { status: 201 },
          );
        }
        if (u.endsWith("/api/v2/agent/lease")) {
          if (step === 2) {
            return new Response(JSON.stringify({ lease_token: vectors.tokens.suspended_backup }), { status: 200 });
          }
          return new Response(
            JSON.stringify({ error: { code: "installation_revoked", message: "Revocada" } }),
            { status: 403 },
          );
        }
        return new Response("not found", { status: 404 });
      }) as typeof fetch;

      const agent = new AegisAgent({
        store,
        product: "aegis-backup",
        appVersion: "4.0.0",
        publicKeys: { [vectors.key_id]: key },
        issuer: vectors.issuer,
        client: new AgentClient({ fetchImpl: fakeFetch }),
        fingerprintProvider: () => fp,
      });

      await agent.enroll(vectors.issuer, "CODE-123");
      expect(store.loadEnrollment()?.installationToken).toBe("install-secret-token-012345");

      // Refresh returns suspended -> RFM blocks backup but allows restore
      const suspendedDecision = await agent.checkAccess({
        capability: "backup",
        rfmAllowed: false,
        now: new Date((vectors.iat + 200) * 1000),
      });
      expect(suspendedDecision.state).toBe("RFM");
      expect(suspendedDecision.allowed).toBe(false);

      // Refresh returns 403 installation_revoked -> purges local token
      const revokedDecision = await agent.checkAccess({
        capability: "backup",
        rfmAllowed: false,
        now: new Date((vectors.iat + 300) * 1000),
      });
      expect(revokedDecision.state).toBe("REVOKED");
      expect(store.loadEnrollment()).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("rejects plain HTTP outside localhost", () => {
    expect(() => normalizeBaseUrl("http://rd.tonyml.com")).toThrow();
    expect(normalizeBaseUrl("http://localhost:8787/foo")).toBe("http://localhost:8787");
    expect(normalizeBaseUrl("https://rd.tonyml.com/fleet")).toBe("https://rd.tonyml.com");
  });

  test("loads canonical RD default public keys and issuer", async () => {
    const keys = await import("../src/index").then((m) => m.defaultPublicKeys());
    const { DEFAULT_ISSUER, DEFAULT_PUBLIC_KEY_ID } = await import("../src/index");
    expect(DEFAULT_ISSUER).toBe("https://rd.tonyml.com");
    expect(keys[DEFAULT_PUBLIC_KEY_ID]).toBeDefined();
  });
});
