import fs from "node:fs";
import path from "node:path";
import { applyRestrictedPermissions, protectSecretBytes, unprotectSecretBytes } from "./dpapi";
import { advanceSecurityMetadata, EMPTY_SECURITY_METADATA, type SecurityMetadata } from "./guard";
import { agentConfigSchema, type AgentConfig, type LeaseClaims } from "./schema";

export interface StoredEnrollment {
  config: AgentConfig;
  installId: string;
  installationToken: string;
}

/**
 * Atomic, DPAPI-protected local store for Protocol v2 credentials, signed lease cache,
 * and monotonic anti-rollback security metadata.
 */
export class AgentStore {
  constructor(public readonly stateDir: string) {}

  private get tokenPath(): string {
    return path.join(this.stateDir, "token.dpapi");
  }

  private get agentPath(): string {
    return path.join(this.stateDir, "agent.json");
  }

  private get leasePath(): string {
    return path.join(this.stateDir, "lease.jwt");
  }

  private get securityPath(): string {
    return path.join(this.stateDir, "security.json");
  }

  ensureDir(): void {
    if (!fs.existsSync(this.stateDir)) {
      fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
      applyRestrictedPermissions(this.stateDir, true);
    }
  }

  private atomicWrite(targetPath: string, data: Uint8Array | string): void {
    this.ensureDir();
    const tmp = path.join(this.stateDir, `.${path.basename(targetPath)}.tmp.${process.pid}`);
    fs.writeFileSync(tmp, data, { mode: 0o600 });
    fs.renameSync(tmp, targetPath);
    applyRestrictedPermissions(targetPath, false);
  }

  saveEnrollment(installId: string, installationToken: string, config: AgentConfig): void {
    const parsedConfig = agentConfigSchema.parse(config);
    const cipher = protectSecretBytes(new TextEncoder().encode(installationToken));
    this.atomicWrite(this.tokenPath, cipher);
    this.atomicWrite(
      this.agentPath,
      JSON.stringify({ install_id: installId, ...parsedConfig }, null, 2) + "\n",
    );
  }

  loadEnrollment(): StoredEnrollment | null {
    if (!fs.existsSync(this.agentPath) || !fs.existsSync(this.tokenPath)) {
      return null;
    }
    const rawAgent = JSON.parse(fs.readFileSync(this.agentPath, "utf8")) as { install_id?: string } & Record<string, unknown>;
    if (!rawAgent.install_id) throw new Error("agent.json missing install_id");
    const config = agentConfigSchema.parse(rawAgent);
    const cipher = fs.readFileSync(this.tokenPath);
    const installationToken = new TextDecoder().decode(unprotectSecretBytes(cipher)).trim();
    if (!installationToken) throw new Error("token.dpapi decrypted to empty token");
    return {
      installId: rawAgent.install_id,
      installationToken,
      config,
    };
  }

  saveLease(leaseJwt: string, claims: LeaseClaims): SecurityMetadata {
    const current = this.loadSecurityMetadata();
    const next = advanceSecurityMetadata(current, claims);
    this.atomicWrite(this.leasePath, leaseJwt);
    this.atomicWrite(this.securityPath, JSON.stringify(next, null, 2) + "\n");
    return next;
  }

  loadLeaseToken(): string | null {
    if (!fs.existsSync(this.leasePath)) return null;
    const content = fs.readFileSync(this.leasePath, "utf8").trim();
    return content || null;
  }

  loadSecurityMetadata(): SecurityMetadata {
    if (!fs.existsSync(this.securityPath)) {
      return { ...EMPTY_SECURITY_METADATA };
    }
    const raw = JSON.parse(fs.readFileSync(this.securityPath, "utf8")) as Partial<SecurityMetadata>;
    return {
      last_lease_issued_at: Number(raw.last_lease_issued_at ?? 0),
      last_server_time: Number(raw.last_server_time ?? 0),
      last_lease_nonce: String(raw.last_lease_nonce ?? ""),
    };
  }

  /** Clears local installation token and cached lease (used when server revokes installation). */
  clearRevokedCredentials(): void {
    for (const file of [this.tokenPath, this.leasePath]) {
      if (fs.existsSync(file)) {
        fs.rmSync(file, { force: true });
      }
    }
  }
}
