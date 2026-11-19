import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { exportPKCS8, exportSPKI, generateKeyPair, SignJWT } from "jose";
import { canonicalWindowsFingerprint } from "../ts/src/fingerprint";
import { importPrivateKeyPem, sha256Hex, signLease } from "../ts/src/crypto";
import { PROTOCOL_VERSION } from "../ts/src/schema";

const outFile = path.resolve(import.meta.dir, "golden-vectors.json");

async function main() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicPem = await exportSPKI(publicKey);
  const privatePem = await exportPKCS8(privateKey);
  const spkiBase64 = publicPem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s+/g, "");

  const signingKey = await importPrivateKeyPem(privatePem);
  const keyId = "ed25519-test-2026";
  const issuer = "https://rd.example.test";
  const installId = "11111111-2222-4333-8444-555555555555";

  const sampleTraits = {
    machineGuid: "c3cd57cb-885d-4679-8587-ae6cea50dcd9",
    hwProfileGuid: "{0a7ed18c-7ff1-11f1-9cf0-806e6f6e6963}",
    systemManufacturer: "LENOVO",
    systemProductName: "20LS0009LM",
    baseBoardProduct: "20LS0009LM",
  };
  const canonicalFp = canonicalWindowsFingerprint(sampleTraits);
  const fingerprintHash = sha256Hex(canonicalFp);

  const iat = 1795000000; // 2026-11-18T...
  const serverTime = new Date(iat * 1000).toISOString();
  const cacheUntil = new Date((iat + 3 * 86400) * 1000).toISOString();
  const graceUntil = new Date((iat + 10 * 86400) * 1000).toISOString();
  const exp = iat + 10 * 86400;

  const activeBackupJwt = await signLease({
    privateKey: signingKey,
    keyId,
    claims: {
      iss: issuer,
      sub: installId,
      jti: "jti-active-1",
      iat,
      nbf: iat,
      exp,
      protocol_version: PROTOCOL_VERSION,
      server_time: serverTime,
      cache_until: cacheUntil,
      grace_until: graceUntil,
      product: "aegis-backup",
      app_name: "AegisBA Enterprise",
      machine_fingerprint_hash: fingerprintHash,
      lease_nonce: "nonce-0001-abcd",
      enforcement: "strict_rfm",
      license: {
        status: "active",
        plan: "annual",
        valid_until: new Date((iat + 365 * 86400) * 1000).toISOString(),
        grace_days: 7,
        entitlements: ["backup", "r2_sync", "schedule"],
      },
      contact: { name: "Soporte TI", ticket_url: `${issuer}/help` },
      notices: [],
    },
  });

  const suspendedBackupJwt = await signLease({
    privateKey: signingKey,
    keyId,
    claims: {
      iss: issuer,
      sub: installId,
      jti: "jti-susp-2",
      iat: iat + 100,
      nbf: iat + 100,
      exp: exp + 100,
      protocol_version: PROTOCOL_VERSION,
      server_time: new Date((iat + 100) * 1000).toISOString(),
      cache_until: new Date((iat + 100 + 3 * 86400) * 1000).toISOString(),
      grace_until: new Date((iat + 100 + 10 * 86400) * 1000).toISOString(),
      product: "aegis-backup",
      app_name: "AegisBA Enterprise",
      machine_fingerprint_hash: fingerprintHash,
      lease_nonce: "nonce-0002-efgh",
      enforcement: "strict_rfm",
      license: {
        status: "suspended",
        plan: "monthly",
        valid_until: new Date((iat + 30 * 86400) * 1000).toISOString(),
        grace_days: 7,
        entitlements: ["backup"],
      },
      contact: { name: "Soporte TI", ticket_url: `${issuer}/help` },
      notices: [],
    },
  });

  const advisoryShellExpiredJwt = await signLease({
    privateKey: signingKey,
    keyId,
    claims: {
      iss: issuer,
      sub: installId,
      jti: "jti-shell-3",
      iat: iat + 200,
      nbf: iat + 200,
      exp: exp + 200,
      protocol_version: PROTOCOL_VERSION,
      server_time: new Date((iat + 200) * 1000).toISOString(),
      cache_until: new Date((iat + 200 + 3 * 86400) * 1000).toISOString(),
      grace_until: new Date((iat + 200 + 10 * 86400) * 1000).toISOString(),
      product: "aegis-shell",
      app_name: "SIDC",
      machine_fingerprint_hash: fingerprintHash,
      lease_nonce: "nonce-0003-ijkl",
      enforcement: "advisory",
      license: {
        status: "expired",
        plan: "perpetual",
        valid_until: null,
        grace_days: 14,
        entitlements: ["launch"],
      },
      contact: { name: "Soporte TI", ticket_url: `${issuer}/help` },
      notices: [
        {
          id: "expired-cycle-1",
          severity: "critical",
          frequency: "each_open_after_expiry",
          title: "Mantenimiento de SIDC",
          message: "El mantenimiento está vencido. Contacta con Soporte TI.",
          closable: false,
          requires_consent: true,
          countdown_seconds: 5,
        },
      ],
    },
  });

  // Deliberately wrong audience (reproduces old v1 bug to prove Go+TS reject it).
  const wrongAudienceJwt = await new SignJWT({
    protocol_version: PROTOCOL_VERSION,
    server_time: serverTime,
    cache_until: cacheUntil,
    grace_until: graceUntil,
    product: "aegis-backup",
    app_name: "AegisBA Enterprise",
    machine_fingerprint_hash: fingerprintHash,
    lease_nonce: "nonce-bad-aud",
    enforcement: "strict_rfm",
    license: {
      status: "active",
      plan: "annual",
      valid_until: null,
      grace_days: 7,
      entitlements: ["backup"],
    },
    contact: { name: "Soporte TI", ticket_url: `${issuer}/help` },
    notices: [],
  })
    .setProtectedHeader({ alg: "EdDSA", kid: keyId, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(installId)
    .setSubject(installId)
    .setJti("jti-wrong-aud")
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .setExpirationTime(exp)
    .sign(signingKey);

  const vectors = {
    key_id: keyId,
    issuer,
    install_id: installId,
    spki_base64: spkiBase64,
    public_pem: publicPem,
    windows_traits: sampleTraits,
    canonical_fingerprint: canonicalFp,
    fingerprint_hash: fingerprintHash,
    iat,
    tokens: {
      active_backup: activeBackupJwt,
      suspended_backup: suspendedBackupJwt,
      advisory_shell_expired: advisoryShellExpiredJwt,
      wrong_audience: wrongAudienceJwt,
    },
    generated_id: crypto.randomUUID(),
  };

  fs.writeFileSync(outFile, JSON.stringify(vectors, null, 2) + "\n", "utf8");
  console.log("Generated golden vectors at", outFile);
}

await main();
