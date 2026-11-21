// Package protocol implements Aegis Protocol v2: mandatory machine enrollment,
// Ed25519 signed offline leases, hardware fingerprinting, monotonic clock rollback
// protection, RFM/advisory access guards, and typed telemetry.
package protocol

import "time"

const (
	ProtocolVersion  = 2
	AgentJWTAudience = "aegis-suite/agent-v2"
)

type ProductID string

const (
	ProductBackup ProductID = "aegis-backup"
	ProductVault  ProductID = "aegis-vault"
	ProductGate   ProductID = "aegis-gate"
	ProductSetup  ProductID = "aegis-setup"
	ProductLaunch ProductID = "aegis-launch"
)

type EnforcementMode string

const (
	EnforcementAdvisory  EnforcementMode = "advisory"
	EnforcementStrictRFM EnforcementMode = "strict_rfm"
	EnforcementStrict    EnforcementMode = "strict"
)

type LicensePlan string

const (
	PlanTrial     LicensePlan = "trial"
	PlanMonthly   LicensePlan = "monthly"
	PlanAnnual    LicensePlan = "annual"
	PlanPerpetual LicensePlan = "perpetual"
)

type LicenseStatus string

const (
	LicenseActive    LicenseStatus = "active"
	LicenseSuspended LicenseStatus = "suspended"
	LicenseExpired   LicenseStatus = "expired"
	LicenseRevoked   LicenseStatus = "revoked"
)

type AccessState string

const (
	StateAllow               AccessState = "ALLOW"
	StateGrace               AccessState = "GRACE"
	StateRFM                 AccessState = "RFM"
	StateRequireEnroll       AccessState = "REQUIRE_ENROLL"
	StateRevoked             AccessState = "REVOKED"
	StateFingerprintMismatch AccessState = "FINGERPRINT_MISMATCH"
)

type Notice struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Frequency        string `json:"frequency"`
	Title            string `json:"title"`
	Message          string `json:"message"`
	Closable         bool   `json:"closable"`
	RequiresConsent  bool   `json:"requires_consent"`
	CountdownSeconds int    `json:"countdown_seconds"`
}

// SupportLinkKind identifica el propósito de un enlace de soporte. Los clientes
// eligen enlaces por Kind, nunca por el texto visible.
type SupportLinkKind string

const (
	LinkTicket  SupportLinkKind = "ticket"
	LinkDocs    SupportLinkKind = "docs"
	LinkTerms   SupportLinkKind = "terms"
	LinkPrivacy SupportLinkKind = "privacy"
	LinkCustom  SupportLinkKind = "custom"
)

type SupportLink struct {
	Kind  SupportLinkKind `json:"kind"`
	Label string          `json:"label"`
	URL   string          `json:"url"`
}

type SupportChannel struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Label string `json:"label,omitempty"`
}

type ShellConfig struct {
	Revision string `json:"revision"`
	Support  struct {
		Title           string           `json:"title"`
		AreaName        string           `json:"area_name"`
		Description     string           `json:"description,omitempty"`
		TemporaryNotice string           `json:"temporary_notice,omitempty"`
		Channels        []SupportChannel `json:"channels"`
		Links           []SupportLink    `json:"links"`
	} `json:"support"`
}

type Contact struct {
	Name string `json:"name"`
}

type LicenseClaim struct {
	Status       LicenseStatus `json:"status"`
	Plan         LicensePlan   `json:"plan"`
	ValidUntil   *string       `json:"valid_until"`
	GraceDays    int           `json:"grace_days"`
	Entitlements []string      `json:"entitlements"`
}

type LeaseClaims struct {
	Issuer                 string          `json:"iss"`
	Audience               []string        `json:"aud"`
	Subject                string          `json:"sub"`
	ID                     string          `json:"jti"`
	IssuedAt               int64           `json:"iat"`
	NotBefore              int64           `json:"nbf"`
	ExpiresAt              int64           `json:"exp"`
	ProtocolVersion        int             `json:"protocol_version"`
	ServerTime             string          `json:"server_time"`
	CacheUntil             string          `json:"cache_until"`
	GraceUntil             string          `json:"grace_until"`
	Product                ProductID       `json:"product"`
	AppName                string          `json:"app_name"`
	MachineFingerprintHash string          `json:"machine_fingerprint_hash"`
	LeaseNonce             string          `json:"lease_nonce"`
	Enforcement            EnforcementMode `json:"enforcement"`
	License                LicenseClaim    `json:"license"`
	Contact                Contact         `json:"contact"`
	Notices                []Notice        `json:"notices"`
	RequiredTermsVersion   string          `json:"required_terms_version,omitempty"`
	TermsURL               string          `json:"terms_url,omitempty"`
	PrivacyURL             string          `json:"privacy_url,omitempty"`
	Config                 *ShellConfig    `json:"config,omitempty"`
}

type AgentConfig struct {
	WorkerBaseURL   string    `json:"worker_base_url"`
	Product         ProductID `json:"product"`
	AppName         string    `json:"app_name"`
	AppTarget       string    `json:"app_target"`
	EquipmentName   string    `json:"equipment_name"`
	ContactName     string    `json:"contact_name"`
	ProtocolVersion int       `json:"protocol_version"`
}

type EnrollRequest struct {
	Product            ProductID `json:"product"`
	AppVersion         string    `json:"app_version"`
	Hostname           string    `json:"hostname"`
	OSArch             string    `json:"os_arch"`
	MachineFingerprint string    `json:"machine_fingerprint"`
	AppTarget          string    `json:"app_target"`
}

type EnrollResponse struct {
	ProtocolVersion   int         `json:"protocol_version"`
	InstallID         string      `json:"install_id"`
	InstallationToken string      `json:"installation_token"`
	LeaseToken        string      `json:"lease_token"`
	Config            AgentConfig `json:"config"`
}

type LeaseRequest struct {
	InstallID          string `json:"install_id"`
	AppVersion         string `json:"app_version"`
	Hostname           string `json:"hostname"`
	OSArch             string `json:"os_arch"`
	MachineFingerprint string `json:"machine_fingerprint"`
	LeaseNonce         string `json:"lease_nonce"`
}

type LeaseResponse struct {
	LeaseToken string `json:"lease_token"`
}

type TelemetryEvent struct {
	EventID    string         `json:"event_id"`
	OccurredAt string         `json:"occurred_at"`
	Type       string         `json:"type"`
	AppVersion string         `json:"app_version"`
	Payload    map[string]any `json:"payload"`
}

type UpdateManifest struct {
	Product         ProductID `json:"product"`
	Channel         string    `json:"channel"`
	Version         string    `json:"version"`
	DownloadURL     *string   `json:"download_url"`
	SHA256          *string   `json:"sha256"`
	PublishedAt     *string   `json:"published_at"`
	UpdateAvailable bool      `json:"update_available"`
}

type SecurityMetadata struct {
	LastLeaseIssuedAt int64  `json:"last_lease_issued_at"`
	LastServerTime    int64  `json:"last_server_time"`
	LastLeaseNonce    string `json:"last_lease_nonce"`
}

type AccessInput struct {
	HasEnrollment       bool
	Claims              *LeaseClaims
	Security            SecurityMetadata
	Now                 time.Time
	RFMAllowed          bool
	Revoked             bool
	FingerprintMismatch bool
}

type AccessDecision struct {
	State                 AccessState `json:"state"`
	Allowed               bool        `json:"allowed"`
	RequiresConsent       bool        `json:"requires_consent"`
	RFMMode               bool        `json:"rfm_mode"`
	ClockRollbackDetected bool        `json:"clock_rollback_detected"`
	EffectiveNow          string      `json:"effective_now"`
	Reason                string      `json:"reason"`
	Notices               []Notice    `json:"notices"`
}

// ResolveEffectiveTime clamps wall-clock backwards drift against the highest
// verified server timestamp recorded locally.
func ResolveEffectiveTime(now time.Time, security SecurityMetadata) (time.Time, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowSec := now.Unix()
	rollback := security.LastServerTime > 0 && nowSec+300 < security.LastServerTime
	if security.LastServerTime > nowSec {
		return time.Unix(security.LastServerTime, 0).UTC(), rollback
	}
	return now.UTC(), rollback
}

// EvaluateAccess classifies the current execution state (ALLOW, GRACE, RFM,
// REQUIRE_ENROLL, REVOKED, FINGERPRINT_MISMATCH) according to Protocol v2.
func EvaluateAccess(in AccessInput) AccessDecision {
	effectiveNow, rollback := ResolveEffectiveTime(in.Now, in.Security)
	enforcement := EnforcementStrictRFM
	var notices []Notice
	if in.Claims != nil {
		if in.Claims.Enforcement != "" {
			enforcement = in.Claims.Enforcement
		}
		notices = in.Claims.Notices
	}
	if notices == nil {
		notices = []Notice{}
	}

	if in.Revoked {
		return buildDecision(StateRevoked, enforcement, in.RFMAllowed, "Instalación revocada por el administrador.", effectiveNow, rollback, notices)
	}
	if in.FingerprintMismatch {
		return buildDecision(StateFingerprintMismatch, enforcement, in.RFMAllowed, "La credencial pertenece a otro equipo distinto.", effectiveNow, rollback, notices)
	}
	if !in.HasEnrollment || in.Claims == nil {
		return buildDecision(StateRequireEnroll, enforcement, in.RFMAllowed, "Este equipo no está enrolado en Aegis RD.", effectiveNow, rollback, notices)
	}

	claims := in.Claims
	if in.Security.LastLeaseIssuedAt > claims.IssuedAt {
		return buildDecision(StateRequireEnroll, enforcement, in.RFMAllowed, "Se detectó un retroceso de versión en el lease firmado.", effectiveNow, rollback, notices)
	}

	switch claims.License.Status {
	case LicenseRevoked:
		return buildDecision(StateRevoked, enforcement, in.RFMAllowed, "La licencia de esta instalación fue revocada.", effectiveNow, rollback, notices)
	case LicenseSuspended:
		return buildDecision(StateRFM, enforcement, in.RFMAllowed, "La licencia está suspendida temporalmente.", effectiveNow, rollback, notices)
	case LicenseExpired:
		return buildDecision(StateRFM, enforcement, in.RFMAllowed, "La licencia ha vencido.", effectiveNow, rollback, notices)
	}

	if claims.License.ValidUntil != nil && *claims.License.ValidUntil != "" {
		validUntil, err := time.Parse(time.RFC3339, *claims.License.ValidUntil)
		if err != nil || effectiveNow.After(validUntil) {
			return buildDecision(StateRFM, enforcement, in.RFMAllowed, "La vigencia de la licencia expiró.", effectiveNow, rollback, notices)
		}
	}

	cacheUntil, errCache := time.Parse(time.RFC3339, claims.CacheUntil)
	graceUntil, errGrace := time.Parse(time.RFC3339, claims.GraceUntil)
	if errCache != nil || errGrace != nil {
		return buildDecision(StateRFM, enforcement, in.RFMAllowed, "Lease con marcas de tiempo inválidas.", effectiveNow, rollback, notices)
	}
	expTime := time.Unix(claims.ExpiresAt, 0).UTC()
	if expTime.Before(graceUntil) {
		graceUntil = expTime
	}

	if !effectiveNow.After(cacheUntil) {
		return buildDecision(StateAllow, enforcement, in.RFMAllowed, "Licencia vigente.", effectiveNow, rollback, notices)
	}
	if !effectiveNow.After(graceUntil) {
		return buildDecision(StateGrace, enforcement, in.RFMAllowed, "Operando en período de gracia offline; sincronice con Aegis RD pronto.", effectiveNow, rollback, notices)
	}
	return buildDecision(StateRFM, enforcement, in.RFMAllowed, "Venció el período de gracia offline sin sincronizar con Aegis RD.", effectiveNow, rollback, notices)
}

func buildDecision(
	state AccessState,
	enforcement EnforcementMode,
	rfmAllowed bool,
	reason string,
	effectiveNow time.Time,
	rollback bool,
	notices []Notice,
) AccessDecision {
	hasConsentNotice := false
	for _, n := range notices {
		if n.RequiresConsent {
			hasConsentNotice = true
			break
		}
	}

	dec := AccessDecision{
		State:                 state,
		ClockRollbackDetected: rollback,
		EffectiveNow:          effectiveNow.Format(time.RFC3339),
		Reason:                reason,
		Notices:               notices,
	}

	switch state {
	case StateAllow, StateGrace:
		dec.Allowed = true
		dec.RequiresConsent = hasConsentNotice
	case StateRFM:
		dec.RFMMode = true
		switch enforcement {
		case EnforcementAdvisory:
			dec.Allowed = true
			dec.RequiresConsent = true
		case EnforcementStrictRFM:
			dec.Allowed = rfmAllowed
		default:
			dec.Allowed = false
		}
	case StateRevoked:
		if enforcement == EnforcementAdvisory {
			dec.Allowed = true
			dec.RequiresConsent = true
		}
	case StateRequireEnroll, StateFingerprintMismatch:
		dec.Allowed = false
	}
	return dec
}
