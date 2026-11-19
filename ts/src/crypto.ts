import crypto from "node:crypto";
import { errors, importPKCS8, importSPKI, jwtVerify, SignJWT, type CryptoKey, type JWTPayload } from "jose";
import { AGENT_JWT_AUDIENCE, leaseClaimsSchema, type LeaseClaims } from "./schema";

/** Computes lowercase SHA-256 hex digest of UTF-8 text or raw bytes. */
export function sha256Hex(input: string | Uint8Array): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/** Constant-time string comparison for fixed-format hashes and tokens. */
export function timingSafeEqualText(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Imports an Ed25519 SPKI public key encoded as base64 DER (rd-clave-publica.md format). */
export async function importPublicKeyBase64(spkiBase64: string): Promise<CryptoKey> {
  const trimmed = spkiBase64.trim();
  const lines = trimmed.match(/.{1,64}/g)?.join("\n") ?? trimmed;
  const pem = `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
  return importSPKI(pem, "EdDSA");
}

/** Imports an Ed25519 SPKI public key in PEM format. */
export async function importPublicKeyPem(pem: string): Promise<CryptoKey> {
  return importSPKI(pem.trim(), "EdDSA");
}

/** Imports an Ed25519 PKCS#8 private key in PEM format. */
export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return importPKCS8(pem.trim(), "EdDSA");
}

export interface SignLeaseOptions {
  privateKey: CryptoKey;
  keyId: string;
  claims: Omit<LeaseClaims, "aud">;
}

/** Signs a protocol v2 LeaseClaims JWT using Ed25519 (EdDSA). */
export async function signLease(options: SignLeaseOptions): Promise<string> {
  const payload: LeaseClaims = leaseClaimsSchema.parse({
    ...options.claims,
    aud: AGENT_JWT_AUDIENCE,
  });

  const { iss, aud, sub, jti, iat, nbf, exp, ...rest } = payload;

  return new SignJWT(rest)
    .setProtectedHeader({ alg: "EdDSA", kid: options.keyId, typ: "JWT" })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setJti(jti)
    .setIssuedAt(iat)
    .setNotBefore(nbf)
    .setExpirationTime(exp)
    .sign(options.privateKey);
}

export interface VerifyLeaseOptions {
  issuer: string;
  publicKeys: Record<string, CryptoKey>;
  installId: string;
  machineFingerprintHash?: string;
  now?: Date;
  clockSkewSeconds?: number;
}

/**
 * Verifies cryptographic Ed25519 signature, issuer, audience, subject, and optional
 * hardware fingerprint. Does NOT enforce expiration on its own so the Guard state
 * machine can classify GRACE vs RFM using monotonic local time.
 */
export async function verifyLease(token: string, options: VerifyLeaseOptions): Promise<LeaseClaims> {
  const clockSkew = options.clockSkewSeconds ?? 10;
  const nowSeconds = Math.floor((options.now ?? new Date()).getTime() / 1000);

  let rawPayload: JWTPayload;
  try {
    const verified = await jwtVerify(
      token,
      async (protectedHeader) => {
        if (protectedHeader.alg !== "EdDSA") {
          throw new Error(`Unexpected JWT algorithm: ${String(protectedHeader.alg)}`);
        }
        const kid = protectedHeader.kid;
        if (!kid || !options.publicKeys[kid]) {
          throw new Error(`Unknown or missing key id: ${String(kid)}`);
        }
        return options.publicKeys[kid];
      },
      {
        issuer: options.issuer,
        audience: AGENT_JWT_AUDIENCE,
        algorithms: ["EdDSA"],
        currentDate: new Date(nowSeconds * 1000),
        clockTolerance: clockSkew,
        requiredClaims: ["iss", "aud", "sub", "jti", "iat", "nbf", "exp"],
      },
    );
    rawPayload = verified.payload;
  } catch (err: unknown) {
    // jose verifies Ed25519 signature, iss, aud, and requiredClaims BEFORE checking exp.
    // Returning an expired-yet-authentic payload lets the Guard classify GRACE vs RFM offline.
    if (err instanceof errors.JWTExpired) {
      rawPayload = err.payload;
    } else {
      throw err;
    }
  }

  const claims = leaseClaimsSchema.parse(rawPayload);

  if (claims.sub.toLowerCase() !== options.installId.toLowerCase()) {
    throw new Error("Lease subject does not match installation id");
  }
  if (claims.nbf > nowSeconds + clockSkew) {
    throw new Error("Lease token is not active yet");
  }
  if (
    options.machineFingerprintHash &&
    !timingSafeEqualText(claims.machine_fingerprint_hash, options.machineFingerprintHash)
  ) {
    throw new Error("Machine fingerprint mismatch");
  }

  return claims;
}
