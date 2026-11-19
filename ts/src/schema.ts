import { z } from "zod";

export const PROTOCOL_VERSION = 2 as const;
export const AGENT_JWT_AUDIENCE = "aegis-suite/agent-v2" as const;
export const DEFAULT_CACHE_MAX_AGE_SECONDS = 72 * 60 * 60; // 3 days
export const DEFAULT_OFFLINE_GRACE_DAYS = 7;

export const productIds = [
  "aegis-backup",
  "aegis-vault",
  "aegis-gate",
  "aegis-setup",
  "aegis-shell",
] as const;
export type ProductId = (typeof productIds)[number];

export const enforcementModes = ["advisory", "strict_rfm", "strict"] as const;
export type EnforcementMode = (typeof enforcementModes)[number];

export const licensePlans = ["trial", "monthly", "annual", "perpetual"] as const;
export type LicensePlan = (typeof licensePlans)[number];

export const licenseStatuses = ["active", "suspended", "expired", "revoked"] as const;
export type LicenseStatus = (typeof licenseStatuses)[number];

export const accessStates = [
  "ALLOW",
  "GRACE",
  "RFM",
  "REQUIRE_ENROLL",
  "REVOKED",
  "FINGERPRINT_MISMATCH",
] as const;
export type AccessState = (typeof accessStates)[number];

export const noticeSchema = z.object({
  id: z.string().min(1),
  severity: z.enum(["info", "warning", "critical"]),
  frequency: z.enum(["once_in_final_14_days", "daily_in_final_7_days", "each_open_after_expiry"]),
  title: z.string().min(1),
  message: z.string().min(1),
  closable: z.boolean(),
  requires_consent: z.boolean(),
  countdown_seconds: z.number().int().min(0).max(120),
});
export type Notice = z.infer<typeof noticeSchema>;

export const supportLinkSchema = z.object({
  label: z.string().min(1),
  url: z.string().min(1),
  kind: z.string().optional(),
});

export const supportChannelSchema = z.object({
  type: z.string().min(1),
  value: z.string().min(1),
  label: z.string().optional(),
});

export const shellConfigSchema = z.object({
  revision: z.string().min(1),
  support: z.object({
    title: z.string().min(1),
    area_name: z.string().min(1),
    description: z.string().optional(),
    temporary_notice: z.string().optional(),
    channels: z.array(supportChannelSchema),
    links: z.array(supportLinkSchema),
  }),
});
export type ShellConfig = z.infer<typeof shellConfigSchema>;

export const contactSchema = z.object({
  name: z.string().min(1),
  ticket_url: z.string().min(1),
});
export type Contact = z.infer<typeof contactSchema>;

export const licenseClaimSchema = z.object({
  status: z.enum(licenseStatuses),
  plan: z.enum(licensePlans),
  valid_until: z.string().datetime().nullable(),
  grace_days: z.number().int().min(0).max(90),
  entitlements: z.array(z.string().min(1)),
});
export type LicenseClaim = z.infer<typeof licenseClaimSchema>;

export const fingerprintHashSchema = z.string().regex(/^[0-9a-f]{64}$/, "must be 64-char lowercase SHA-256 hex");

export const leaseClaimsSchema = z.object({
  iss: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  sub: z.string().min(1),
  jti: z.string().min(1),
  iat: z.number().int().positive(),
  nbf: z.number().int().positive(),
  exp: z.number().int().positive(),
  protocol_version: z.literal(PROTOCOL_VERSION),
  server_time: z.string().datetime(),
  cache_until: z.string().datetime(),
  grace_until: z.string().datetime(),
  product: z.enum(productIds),
  app_name: z.string().min(1).max(120),
  machine_fingerprint_hash: fingerprintHashSchema,
  lease_nonce: z.string().min(8).max(128),
  enforcement: z.enum(enforcementModes),
  license: licenseClaimSchema,
  contact: contactSchema,
  notices: z.array(noticeSchema),
  required_terms_version: z.string().optional(),
  terms_url: z.string().url().optional(),
  privacy_url: z.string().url().optional(),
  config: shellConfigSchema.optional(),
});
export type LeaseClaims = z.infer<typeof leaseClaimsSchema>;

export const enrollRequestSchema = z.object({
  product: z.enum(productIds),
  app_version: z.string().min(1).max(50),
  hostname: z.string().min(1).max(200),
  os_arch: z.string().min(1).max(60),
  machine_fingerprint: fingerprintHashSchema,
  app_target: z.string().max(260).default(""),
});
export type EnrollRequest = z.infer<typeof enrollRequestSchema>;

export const agentConfigSchema = z.object({
  worker_base_url: z.string().url(),
  product: z.enum(productIds),
  app_name: z.string().min(1).max(120),
  app_target: z.string().max(260),
  equipment_name: z.string().min(1).max(200),
  contact_name: z.string().min(1),
  ticket_url: z.string().min(1),
  protocol_version: z.literal(PROTOCOL_VERSION),
});
export type AgentConfig = z.infer<typeof agentConfigSchema>;

export const enrollResponseSchema = z.object({
  protocol_version: z.literal(PROTOCOL_VERSION),
  install_id: z.string().min(1),
  installation_token: z.string().min(16),
  lease_token: z.string().min(20),
  config: agentConfigSchema,
});
export type EnrollResponse = z.infer<typeof enrollResponseSchema>;

export const leaseRequestSchema = z.object({
  install_id: z.string().min(1),
  app_version: z.string().min(1).max(50),
  hostname: z.string().min(1).max(200),
  os_arch: z.string().min(1).max(60),
  machine_fingerprint: fingerprintHashSchema,
  lease_nonce: z.string().max(128).default(""),
});
export type LeaseRequest = z.infer<typeof leaseRequestSchema>;

export const leaseResponseSchema = z.object({
  lease_token: z.string().min(20),
});
export type LeaseResponse = z.infer<typeof leaseResponseSchema>;

export const telemetryEventType = z.enum([
  "agent.enrolled",
  "agent.lease_refreshed",
  "agent.guard_denied",
  "agent.clock_rollback",
  "agent.fingerprint_mismatch",
  "backup.run",
  "vault.heartbeat",
  "setup.provision",
  "shell.launch",
  "gate.exec",
]);
export type TelemetryEventType = z.infer<typeof telemetryEventType>;

export const telemetryEventSchema = z.object({
  event_id: z.string().min(1).max(100),
  occurred_at: z.string().datetime(),
  type: telemetryEventType,
  app_version: z.string().min(1).max(50),
  payload: z.record(z.string(), z.unknown()).default({}),
});
export type TelemetryEvent = z.infer<typeof telemetryEventSchema>;

export const telemetryBatchSchema = z.object({
  events: z.array(telemetryEventSchema).min(1).max(50),
});
export type TelemetryBatch = z.infer<typeof telemetryBatchSchema>;

export const updateManifestSchema = z.object({
  product: z.enum(productIds),
  channel: z.enum(["stable", "beta"]),
  version: z.string().min(1),
  download_url: z.string().url().nullable(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable(),
  published_at: z.string().datetime().nullable(),
  update_available: z.boolean(),
});
export type UpdateManifest = z.infer<typeof updateManifestSchema>;
