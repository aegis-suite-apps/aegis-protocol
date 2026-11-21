package protocol_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

type goldenVectors struct {
	KeyID                string `json:"key_id"`
	Issuer               string `json:"issuer"`
	InstallID            string `json:"install_id"`
	SPKIBase64           string `json:"spki_base64"`
	PublicPEM            string `json:"public_pem"`
	CanonicalFingerprint string `json:"canonical_fingerprint"`
	FingerprintHash      string `json:"fingerprint_hash"`
	IAT                  int64  `json:"iat"`
	WindowsTraits        struct {
		MachineGuid        string `json:"machineGuid"`
		HwProfileGuid      string `json:"hwProfileGuid"`
		SystemManufacturer string `json:"systemManufacturer"`
		SystemProductName  string `json:"systemProductName"`
		BaseBoardProduct   string `json:"baseBoardProduct"`
	} `json:"windows_traits"`
	Tokens struct {
		ActiveBackup         string `json:"active_backup"`
		SuspendedBackup      string `json:"suspended_backup"`
		AdvisoryShellExpired string `json:"advisory_shell_expired"`
		WrongAudience        string `json:"wrong_audience"`
	} `json:"tokens"`
}

func loadVectors(t *testing.T) goldenVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vectors", "golden-vectors.json"))
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var v goldenVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse golden vectors: %v", err)
	}
	return v
}

func TestCanonicalFingerprintMatchesGoldenVector(t *testing.T) {
	v := loadVectors(t)
	canonical := protocol.CanonicalWindowsFingerprint(protocol.WindowsFingerprintTraits{
		MachineGuid:        v.WindowsTraits.MachineGuid,
		HwProfileGuid:      v.WindowsTraits.HwProfileGuid,
		SystemManufacturer: v.WindowsTraits.SystemManufacturer,
		SystemProductName:  v.WindowsTraits.SystemProductName,
		BaseBoardProduct:   v.WindowsTraits.BaseBoardProduct,
	})
	if canonical != v.CanonicalFingerprint {
		t.Fatalf("canonical mismatch:\n got: %q\nwant: %q", canonical, v.CanonicalFingerprint)
	}
	if got := protocol.HashFingerprint(canonical); got != v.FingerprintHash {
		t.Fatalf("hash mismatch: got %q want %q", got, v.FingerprintHash)
	}
	if fp := protocol.ComputeMachineFingerprint(); len(fp) != 64 {
		t.Fatalf("unexpected live fingerprint length: %q", fp)
	}
}

func TestVerifyGoldenVectorsCrossLanguage(t *testing.T) {
	v := loadVectors(t)
	pubB64, err := protocol.ParsePublicKeyBase64(v.SPKIBase64)
	if err != nil {
		t.Fatalf("ParsePublicKeyBase64: %v", err)
	}
	pubPEM, err := protocol.ParsePublicKeyPEM(v.PublicPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}
	verifier := protocol.NewVerifier(v.Issuer, map[string]ed25519.PublicKey{v.KeyID: pubB64})
	verifierPEM := protocol.NewVerifier(v.Issuer, map[string]ed25519.PublicKey{v.KeyID: pubPEM})
	now := time.Unix(v.IAT+60, 0).UTC()

	c1, err := verifier.VerifyLease(v.Tokens.ActiveBackup, v.InstallID, v.FingerprintHash, now)
	if err != nil {
		t.Fatalf("VerifyLease b64 failed: %v", err)
	}
	c2, err := verifierPEM.VerifyLease(v.Tokens.ActiveBackup, v.InstallID, v.FingerprintHash, now)
	if err != nil {
		t.Fatalf("VerifyLease pem failed: %v", err)
	}
	if c1.Product != protocol.ProductBackup || c2.LeaseNonce != "nonce-0001-abcd" {
		t.Fatalf("unexpected claims: %+v / %+v", c1, c2)
	}

	if _, err := verifier.VerifyLease(v.Tokens.WrongAudience, v.InstallID, v.FingerprintHash, now); err != protocol.ErrAudienceMismatch {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
	if _, err := verifier.VerifyLease(v.Tokens.ActiveBackup, v.InstallID, "0000000000000000000000000000000000000000000000000000000000000000", now); err != protocol.ErrFingerprintMismatch {
		t.Fatalf("expected ErrFingerprintMismatch, got %v", err)
	}
}

func TestGuardTransitionsAndClockRollback(t *testing.T) {
	v := loadVectors(t)
	pub, err := protocol.ParsePublicKeyBase64(v.SPKIBase64)
	if err != nil {
		t.Fatal(err)
	}
	verifier := protocol.NewVerifier(v.Issuer, map[string]ed25519.PublicKey{v.KeyID: pub})
	claims, err := verifier.VerifyLease(v.Tokens.ActiveBackup, v.InstallID, v.FingerprintHash, time.Unix(v.IAT+60, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}

	allow := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Now:           time.Unix(v.IAT+86400, 0).UTC(),
	})
	if allow.State != protocol.StateAllow || !allow.Allowed {
		t.Fatalf("expected ALLOW, got %+v", allow)
	}

	grace := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Now:           time.Unix(v.IAT+5*86400, 0).UTC(),
	})
	if grace.State != protocol.StateGrace || !grace.Allowed {
		t.Fatalf("expected GRACE, got %+v", grace)
	}

	rfmBackup := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Now:           time.Unix(v.IAT+12*86400, 0).UTC(),
		RFMAllowed:    false,
	})
	if rfmBackup.State != protocol.StateRFM || rfmBackup.Allowed {
		t.Fatalf("expected RFM deny backup, got %+v", rfmBackup)
	}

	rfmRestore := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Now:           time.Unix(v.IAT+12*86400, 0).UTC(),
		RFMAllowed:    true,
	})
	if rfmRestore.State != protocol.StateRFM || !rfmRestore.Allowed {
		t.Fatalf("expected RFM allow restore, got %+v", rfmRestore)
	}

	rollback := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Security: protocol.SecurityMetadata{
			LastLeaseIssuedAt: v.IAT,
			LastServerTime:    v.IAT + 12*86400,
		},
		Now: time.Unix(v.IAT+60, 0).UTC(),
	})
	if !rollback.ClockRollbackDetected || rollback.State != protocol.StateRFM || rollback.Allowed {
		t.Fatalf("expected clock rollback lock, got %+v", rollback)
	}

	shellClaims, err := verifier.VerifyLease(v.Tokens.AdvisoryShellExpired, v.InstallID, v.FingerprintHash, time.Unix(v.IAT+300, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	shellDec := protocol.EvaluateAccess(protocol.AccessInput{
		HasEnrollment: true,
		Claims:        &shellClaims,
		Now:           time.Unix(v.IAT+300, 0).UTC(),
	})
	if shellDec.State != protocol.StateRFM || !shellDec.Allowed || !shellDec.RequiresConsent {
		t.Fatalf("expected advisory shell consent allow, got %+v", shellDec)
	}
}

func TestAgentEnrollRefreshAndRevokeRoundTrip(t *testing.T) {
	v := loadVectors(t)
	pub, err := protocol.ParsePublicKeyBase64(v.SPKIBase64)
	if err != nil {
		t.Fatal(err)
	}

	step := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agent/enroll":
			if r.Header.Get("authorization") != "Bearer CODE-GO" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
				ProtocolVersion:   2,
				InstallID:         v.InstallID,
				InstallationToken: "go-secret-token-123456",
				LeaseToken:        v.Tokens.ActiveBackup,
				Config: protocol.AgentConfig{
					WorkerBaseURL:   srv.URL,
					Product:         protocol.ProductBackup,
					AppName:         "AegisBA Enterprise",
					EquipmentName:   "PC-GO",
					ContactName:     "Soporte TI",
					ProtocolVersion: 2,
				},
			})
		case "/api/v2/agent/lease":
			step++
			if step == 1 {
				_ = json.NewEncoder(w).Encode(protocol.LeaseResponse{LeaseToken: v.Tokens.SuspendedBackup})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"installation_revoked","message":"Revocada"}}`))
		case "/api/v2/agent/events":
			w.WriteHeader(http.StatusAccepted)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := protocol.NewStore(t.TempDir())
	agent := protocol.NewAgent(protocol.AgentOptions{
		Store:         store,
		Product:       protocol.ProductBackup,
		AppVersion:    "4.0.0",
		Keys:          protocol.NewVerifier(v.Issuer, map[string]ed25519.PublicKey{v.KeyID: pub}),
		FingerprintFn: func() string { return v.FingerprintHash },
	})

	ctx := context.Background()
	if _, err := agent.Enroll(ctx, srv.URL, "CODE-GO", ""); err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if err := agent.TrackEvent(ctx, "backup.run", map[string]any{"outcome": "ok"}); err != nil {
		t.Fatalf("TrackEvent failed: %v", err)
	}

	susp := agent.CheckAccess(ctx, protocol.CheckOptions{
		Capability:    "backup",
		RFMAllowed:    false,
		RefreshOnline: true,
		Now:           time.Unix(v.IAT+200, 0).UTC(),
	})
	if susp.State != protocol.StateRFM || susp.Allowed {
		t.Fatalf("expected RFM deny on suspended lease, got %+v", susp)
	}

	rev := agent.CheckAccess(ctx, protocol.CheckOptions{
		Capability:    "backup",
		RFMAllowed:    false,
		RefreshOnline: true,
		Now:           time.Unix(v.IAT+300, 0).UTC(),
	})
	if rev.State != protocol.StateRevoked || rev.Allowed {
		t.Fatalf("expected REVOKED, got %+v", rev)
	}
	if _, err := store.LoadEnrollment(); err != protocol.ErrNotEnrolled {
		t.Fatalf("expected credentials purged after revoke, got %v", err)
	}
}

func TestDefaultVerifierLoadsCanonicalKey(t *testing.T) {
	v, err := protocol.DefaultVerifier(protocol.DefaultIssuer)
	if err != nil {
		t.Fatalf("DefaultVerifier failed: %v", err)
	}
	if v.Issuer != "https://rd.tonyml.com" {
		t.Fatalf("unexpected default issuer: %q", v.Issuer)
	}
	if _, ok := v.Keys[protocol.DefaultPublicKeyID]; !ok {
		t.Fatalf("expected canonical key %q in verifier", protocol.DefaultPublicKeyID)
	}
}

func TestMachineStoreRoundTrip(t *testing.T) {
	store := protocol.NewMachineStore(t.TempDir())
	if !store.MachineScope {
		t.Fatal("expected MachineScope=true")
	}
	cfg := protocol.AgentConfig{
		WorkerBaseURL:   "https://rd.tonyml.com",
		Product:         protocol.ProductBackup,
		AppName:         "AegisBA Enterprise",
		EquipmentName:   "SRV-01",
		ProtocolVersion: 2,
	}
	if err := store.SaveEnrollment("inst-m1", "tok-machine-secret", cfg); err != nil {
		t.Fatalf("SaveEnrollment failed: %v", err)
	}
	got, err := store.LoadEnrollment()
	if err != nil {
		t.Fatalf("LoadEnrollment failed: %v", err)
	}
	if got.InstallID != "inst-m1" || got.InstallationToken != "tok-machine-secret" {
		t.Fatalf("unexpected enrollment loaded: %+v", got)
	}
}
