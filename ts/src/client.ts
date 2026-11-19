import crypto from "node:crypto";
import os from "node:os";
import type { CryptoKey } from "jose";
import { verifyLease } from "./crypto";
import { computeMachineFingerprint } from "./fingerprint";
import { evaluateAccess, type AccessDecision } from "./guard";
import {
  enrollRequestSchema,
  enrollResponseSchema,
  leaseRequestSchema,
  leaseResponseSchema,
  telemetryBatchSchema,
  updateManifestSchema,
  type EnrollResponse,
  type LeaseClaims,
  type ProductId,
  type TelemetryEvent,
  type TelemetryEventType,
  type UpdateManifest,
} from "./schema";
import { AgentStore } from "./store";

export class ProtocolHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(`HTTP ${status} (${code}): ${message}`);
    this.name = "ProtocolHttpError";
  }
}

export function normalizeBaseUrl(rawUrl: string): string {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new Error(`Invalid Aegis RD URL: ${rawUrl}`);
  }
  const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new Error("Aegis RD URL must use https (http only allowed for localhost)");
  }
  return `${url.protocol}//${url.host}`;
}

async function parseErrorResponse(res: Response): Promise<ProtocolHttpError> {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text) as { error?: { code?: string; message?: string } };
    const code = parsed.error?.code || "http_error";
    const msg = parsed.error?.message || text || res.statusText;
    return new ProtocolHttpError(res.status, code, msg);
  } catch {
    return new ProtocolHttpError(res.status, "http_error", text || res.statusText);
  }
}

export function defaultOsArch(): string {
  const platform = process.platform === "win32" ? "windows" : process.platform;
  const arch = process.arch === "x64" ? "amd64" : process.arch;
  return `${platform}/${arch}`;
}

export interface AgentClientOptions {
  fetchImpl?: typeof fetch;
}

export class AgentClient {
  private readonly fetchImpl: typeof fetch;

  constructor(options: AgentClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async enroll(
    baseUrl: string,
    enrollmentCode: string,
    input: {
      product: ProductId;
      appVersion: string;
      hostname?: string;
      osArch?: string;
      machineFingerprint?: string;
      appTarget?: string;
    },
  ): Promise<EnrollResponse> {
    const base = normalizeBaseUrl(baseUrl);
    const code = enrollmentCode.trim();
    if (!code) throw new Error("Enrollment code is required");

    const body = enrollRequestSchema.parse({
      product: input.product,
      app_version: input.appVersion,
      hostname: input.hostname ?? os.hostname(),
      os_arch: input.osArch ?? defaultOsArch(),
      machine_fingerprint: input.machineFingerprint ?? computeMachineFingerprint(),
      app_target: input.appTarget ?? "",
    });

    const res = await this.fetchImpl(`${base}/api/v2/agent/enroll`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${code}`,
      },
      body: JSON.stringify(body),
    });

    if (res.status !== 201) {
      throw await parseErrorResponse(res);
    }

    return enrollResponseSchema.parse(await res.json());
  }

  async refreshLease(
    baseUrl: string,
    installationToken: string,
    input: {
      installId: string;
      appVersion: string;
      hostname?: string;
      osArch?: string;
      machineFingerprint?: string;
      leaseNonce?: string;
    },
  ): Promise<string> {
    const base = normalizeBaseUrl(baseUrl);
    const body = leaseRequestSchema.parse({
      install_id: input.installId,
      app_version: input.appVersion,
      hostname: input.hostname ?? os.hostname(),
      os_arch: input.osArch ?? defaultOsArch(),
      machine_fingerprint: input.machineFingerprint ?? computeMachineFingerprint(),
      lease_nonce: input.leaseNonce ?? "",
    });

    const res = await this.fetchImpl(`${base}/api/v2/agent/lease`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${installationToken}`,
      },
      body: JSON.stringify(body),
    });

    if (res.status !== 200) {
      throw await parseErrorResponse(res);
    }

    return leaseResponseSchema.parse(await res.json()).lease_token;
  }

  async sendEvents(baseUrl: string, installationToken: string, events: TelemetryEvent[]): Promise<void> {
    const base = normalizeBaseUrl(baseUrl);
    const body = telemetryBatchSchema.parse({ events });

    const res = await this.fetchImpl(`${base}/api/v2/agent/events`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${installationToken}`,
      },
      body: JSON.stringify(body),
    });

    if (res.status !== 202 && res.status !== 200) {
      throw await parseErrorResponse(res);
    }
  }

  async checkUpdates(
    baseUrl: string,
    installationToken: string,
    currentVersion: string,
    channel: "stable" | "beta" = "stable",
  ): Promise<UpdateManifest> {
    const base = normalizeBaseUrl(baseUrl);
    const params = new URLSearchParams({ version: currentVersion, channel });
    const res = await this.fetchImpl(`${base}/api/v2/agent/updates?${params.toString()}`, {
      method: "GET",
      headers: {
        authorization: `Bearer ${installationToken}`,
      },
    });
    if (res.status !== 200) {
      throw await parseErrorResponse(res);
    }
    return updateManifestSchema.parse(await res.json());
  }
}

export interface AgentOptions {
  store: AgentStore;
  product: ProductId;
  appVersion: string;
  publicKeys: Record<string, CryptoKey>;
  issuer?: string;
  client?: AgentClient;
  fingerprintProvider?: () => string;
}

/** High-level coordinator combining local DPAPI store, Ed25519 lease verification, sync, and Guard checks. */
export class AegisAgent {
  private readonly client: AgentClient;
  private readonly fingerprintProvider: () => string;

  constructor(private readonly options: AgentOptions) {
    this.client = options.client ?? new AgentClient();
    this.fingerprintProvider = options.fingerprintProvider ?? computeMachineFingerprint;
  }

  async enroll(baseUrl: string, code: string, appTarget = ""): Promise<EnrollResponse> {
    const fp = this.fingerprintProvider();
    const res = await this.client.enroll(baseUrl, code, {
      product: this.options.product,
      appVersion: this.options.appVersion,
      machineFingerprint: fp,
      appTarget,
    });
    try {
      normalizeBaseUrl(res.config.worker_base_url);
    } catch {
      res.config.worker_base_url = normalizeBaseUrl(baseUrl);
    }
    const issuer = this.options.issuer ?? res.config.worker_base_url;
    const claims = await verifyLease(res.lease_token, {
      issuer,
      publicKeys: this.options.publicKeys,
      installId: res.install_id,
      machineFingerprintHash: fp,
    });
    this.options.store.saveEnrollment(res.install_id, res.installation_token, res.config);
    this.options.store.saveLease(res.lease_token, claims);
    return res;
  }

  async checkAccess(params: { capability: string; rfmAllowed?: boolean; refreshOnline?: boolean; now?: Date }): Promise<AccessDecision> {
    const enrolled = this.options.store.loadEnrollment();
    if (!enrolled) {
      return evaluateAccess({ hasEnrollment: false, claims: null, rfmAllowed: params.rfmAllowed, now: params.now });
    }

    const fp = this.fingerprintProvider();
    const issuer = this.options.issuer ?? enrolled.config.worker_base_url;
    let security = this.options.store.loadSecurityMetadata();
    let revoked = false;
    let fingerprintMismatch = false;

    if (params.refreshOnline !== false) {
      try {
        const freshJwt = await this.client.refreshLease(enrolled.config.worker_base_url, enrolled.installationToken, {
          installId: enrolled.installId,
          appVersion: this.options.appVersion,
          machineFingerprint: fp,
          leaseNonce: security.last_lease_nonce,
        });
        const freshClaims = await verifyLease(freshJwt, {
          issuer,
          publicKeys: this.options.publicKeys,
          installId: enrolled.installId,
          machineFingerprintHash: fp,
          now: params.now,
        });
        security = this.options.store.saveLease(freshJwt, freshClaims);
      } catch (err) {
        if (err instanceof ProtocolHttpError) {
          if (err.status === 403 && err.code === "installation_revoked") {
            this.options.store.clearRevokedCredentials();
            revoked = true;
          } else if (err.status === 403 && err.code === "fingerprint_mismatch") {
            fingerprintMismatch = true;
          }
        }
        // Network failures fall through to cached Ed25519 lease verification + grace window.
      }
    }

    if (revoked || fingerprintMismatch) {
      return evaluateAccess({
        hasEnrollment: true,
        claims: null,
        security,
        now: params.now,
        rfmAllowed: params.rfmAllowed,
        revoked,
        fingerprintMismatch,
      });
    }

    const cachedJwt = this.options.store.loadLeaseToken();
    if (!cachedJwt) {
      return evaluateAccess({ hasEnrollment: false, claims: null, security, now: params.now, rfmAllowed: params.rfmAllowed });
    }

    let claims: LeaseClaims | null = null;
    try {
      claims = await verifyLease(cachedJwt, {
        issuer,
        publicKeys: this.options.publicKeys,
        installId: enrolled.installId,
        machineFingerprintHash: fp,
        now: params.now,
      });
    } catch (err) {
      if (err instanceof Error && err.message.includes("fingerprint mismatch")) {
        fingerprintMismatch = true;
      }
    }

    return evaluateAccess({
      hasEnrollment: true,
      claims,
      security,
      now: params.now,
      rfmAllowed: params.rfmAllowed,
      fingerprintMismatch,
    });
  }

  async trackEvent(type: TelemetryEventType, payload: Record<string, unknown> = {}): Promise<void> {
    const enrolled = this.options.store.loadEnrollment();
    if (!enrolled) return;
    await this.client.sendEvents(enrolled.config.worker_base_url, enrolled.installationToken, [
      {
        event_id: crypto.randomUUID(),
        occurred_at: new Date().toISOString(),
        type,
        app_version: this.options.appVersion,
        payload,
      },
    ]);
  }
}
