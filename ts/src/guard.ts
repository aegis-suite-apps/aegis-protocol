import type { AccessState, EnforcementMode, LeaseClaims, Notice } from "./schema";

export interface SecurityMetadata {
  last_lease_issued_at: number;
  last_server_time: number;
  last_lease_nonce: string;
}

export const EMPTY_SECURITY_METADATA: SecurityMetadata = {
  last_lease_issued_at: 0,
  last_server_time: 0,
  last_lease_nonce: "",
};

export interface EvaluateAccessInput {
  hasEnrollment: boolean;
  claims: LeaseClaims | null;
  security?: SecurityMetadata;
  now?: Date;
  rfmAllowed?: boolean;
  revoked?: boolean;
  fingerprintMismatch?: boolean;
}

export interface AccessDecision {
  state: AccessState;
  allowed: boolean;
  requiresConsent: boolean;
  rfmMode: boolean;
  clockRollbackDetected: boolean;
  effectiveNow: string;
  reason: string;
  notices: Notice[];
}

function decisionForState(
  state: AccessState,
  enforcement: EnforcementMode,
  rfmAllowed: boolean,
  reason: string,
  effectiveNow: Date,
  clockRollbackDetected: boolean,
  notices: Notice[],
): AccessDecision {
  const hasConsentNotice = notices.some((n) => n.requires_consent);

  switch (state) {
    case "ALLOW":
    case "GRACE":
      return {
        state,
        allowed: true,
        requiresConsent: hasConsentNotice,
        rfmMode: false,
        clockRollbackDetected,
        effectiveNow: effectiveNow.toISOString(),
        reason,
        notices,
      };
    case "RFM": {
      if (enforcement === "advisory") {
        return {
          state,
          allowed: true,
          requiresConsent: true,
          rfmMode: true,
          clockRollbackDetected,
          effectiveNow: effectiveNow.toISOString(),
          reason,
          notices,
        };
      }
      if (enforcement === "strict_rfm") {
        return {
          state,
          allowed: rfmAllowed,
          requiresConsent: false,
          rfmMode: true,
          clockRollbackDetected,
          effectiveNow: effectiveNow.toISOString(),
          reason,
          notices,
        };
      }
      return {
        state,
        allowed: false,
        requiresConsent: false,
        rfmMode: true,
        clockRollbackDetected,
        effectiveNow: effectiveNow.toISOString(),
        reason,
        notices,
      };
    }
    case "REVOKED":
      return {
        state,
        allowed: enforcement === "advisory",
        requiresConsent: enforcement === "advisory",
        rfmMode: false,
        clockRollbackDetected,
        effectiveNow: effectiveNow.toISOString(),
        reason,
        notices,
      };
    case "REQUIRE_ENROLL":
    case "FINGERPRINT_MISMATCH":
      return {
        state,
        allowed: false,
        requiresConsent: false,
        rfmMode: false,
        clockRollbackDetected,
        effectiveNow: effectiveNow.toISOString(),
        reason,
        notices,
      };
  }
}

/** Computes monotonic effective time, clamping forward if OS clock was rolled back past last_server_time. */
export function resolveEffectiveTime(now: Date, security: SecurityMetadata): { effectiveNow: Date; rollback: boolean } {
  const nowSec = Math.floor(now.getTime() / 1000);
  const rollback = security.last_server_time > 0 && nowSec + 300 < security.last_server_time;
  if (security.last_server_time > nowSec) {
    return { effectiveNow: new Date(security.last_server_time * 1000), rollback };
  }
  return { effectiveNow: now, rollback };
}

/** Updates monotonic security metadata after verifying a newly received lease token. */
export function advanceSecurityMetadata(current: SecurityMetadata, claims: LeaseClaims): SecurityMetadata {
  if (current.last_lease_issued_at > claims.iat) {
    throw new Error("Signed lease rollback detected");
  }
  const serverTimeSec = Math.floor(Date.parse(claims.server_time) / 1000);
  return {
    last_lease_issued_at: Math.max(current.last_lease_issued_at, claims.iat),
    last_server_time: Math.max(current.last_server_time, serverTimeSec),
    last_lease_nonce: claims.lease_nonce,
  };
}

/** Evaluates offline/online access state according to Protocol v2 rules. */
export function evaluateAccess(input: EvaluateAccessInput): AccessDecision {
  const now = input.now ?? new Date();
  const security = input.security ?? EMPTY_SECURITY_METADATA;
  const { effectiveNow, rollback } = resolveEffectiveTime(now, security);
  const enforcement: EnforcementMode = input.claims?.enforcement ?? "strict_rfm";
  const rfmAllowed = Boolean(input.rfmAllowed);
  const notices = input.claims?.notices ?? [];

  if (input.revoked) {
    return decisionForState(
      "REVOKED",
      enforcement,
      rfmAllowed,
      "Instalación revocada por el administrador.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  if (input.fingerprintMismatch) {
    return decisionForState(
      "FINGERPRINT_MISMATCH",
      enforcement,
      rfmAllowed,
      "La credencial pertenece a otro equipo distinto.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  if (!input.hasEnrollment || !input.claims) {
    return decisionForState(
      "REQUIRE_ENROLL",
      enforcement,
      rfmAllowed,
      "Este equipo no está enrolado en Aegis RD.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  const claims = input.claims;

  if (security.last_lease_issued_at > claims.iat) {
    return decisionForState(
      "REQUIRE_ENROLL",
      enforcement,
      rfmAllowed,
      "Se detectó un retroceso de versión en el lease firmado.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  if (claims.license.status === "revoked") {
    return decisionForState(
      "REVOKED",
      enforcement,
      rfmAllowed,
      "La licencia de esta instalación fue revocada.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  if (claims.license.status === "suspended") {
    return decisionForState(
      "RFM",
      enforcement,
      rfmAllowed,
      "La licencia está suspendida temporalmente.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  if (claims.license.status === "expired") {
    return decisionForState(
      "RFM",
      enforcement,
      rfmAllowed,
      "La licencia ha vencido.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  const effectiveMs = effectiveNow.getTime();
  if (claims.license.valid_until !== null && effectiveMs > Date.parse(claims.license.valid_until)) {
    return decisionForState(
      "RFM",
      enforcement,
      rfmAllowed,
      "La vigencia de la licencia expiró.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  const cacheUntilMs = Date.parse(claims.cache_until);
  const graceUntilMs = Math.min(Date.parse(claims.grace_until), claims.exp * 1000);

  if (effectiveMs <= cacheUntilMs) {
    return decisionForState("ALLOW", enforcement, rfmAllowed, "Licencia vigente.", effectiveNow, rollback, notices);
  }

  if (effectiveMs <= graceUntilMs) {
    return decisionForState(
      "GRACE",
      enforcement,
      rfmAllowed,
      "Operando en período de gracia offline; sincronice con Aegis RD pronto.",
      effectiveNow,
      rollback,
      notices,
    );
  }

  return decisionForState(
    "RFM",
    enforcement,
    rfmAllowed,
    "Venció el período de gracia offline sin sincronizar con Aegis RD.",
    effectiveNow,
    rollback,
    notices,
  );
}
