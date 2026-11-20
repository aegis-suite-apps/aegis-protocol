package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

type enrollTestHarness struct {
	server *httptest.Server
	pubB64 string
	fp     string
}

func newEnrollTestHarness(t *testing.T) enrollTestHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(der)
	fp := strings.Repeat("a", 64)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/agent/enroll":
			if r.Header.Get("authorization") != "Bearer CODE-OK" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"code":"invalid_code","message":"Bad code"}}`))
				return
			}
			now := time.Now().UTC()
			tok, signErr := protocol.SignLease(protocol.LeaseClaims{
				Issuer:                 srv.URL,
				Audience:               []string{protocol.AgentJWTAudience},
				Subject:                "inst-enroll-1",
				ID:                     "jti-enroll-1",
				IssuedAt:               now.Unix(),
				NotBefore:              now.Unix() - 5,
				ExpiresAt:              now.Add(72 * time.Hour).Unix(),
				ProtocolVersion:        2,
				ServerTime:             now.Format(time.RFC3339),
				CacheUntil:             now.Add(24 * time.Hour).Format(time.RFC3339),
				GraceUntil:             now.Add(72 * time.Hour).Format(time.RFC3339),
				Product:                protocol.ProductBackup,
				AppName:                "AegisBA Enterprise",
				MachineFingerprintHash: fp,
				LeaseNonce:             "nonce-enroll-1",
				Enforcement:            protocol.EnforcementStrictRFM,
				License:                protocol.LicenseClaim{Status: protocol.LicenseActive, Plan: protocol.PlanAnnual},
			}, "kid-test", priv)
			if signErr != nil {
				t.Fatal(signErr)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
				ProtocolVersion:   2,
				InstallID:         "inst-enroll-1",
				InstallationToken: "tok-secret-never-print",
				LeaseToken:        tok,
				Config: protocol.AgentConfig{
					WorkerBaseURL:   srv.URL,
					Product:         protocol.ProductBackup,
					AppName:         "AegisBA Enterprise",
					EquipmentName:   "SRV-TEST-01",
					ProtocolVersion: 2,
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	return enrollTestHarness{
		server: srv,
		pubB64: pubB64,
		fp:     fp,
	}
}

func TestRunRejectsInvalidFlags(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--product", "unknown"}, &out, &errBuf, runtimeDeps{})
	if code != exitInternal {
		t.Fatalf("expected exit %d, got %d (%s)", exitInternal, code, out.String())
	}

	out.Reset()
	code = run([]string{"--product", "aegis-backup", "--code", "LEAK"}, &out, &errBuf, runtimeDeps{})
	if code != exitInternal {
		t.Fatalf("expected --code to be rejected with exit %d, got %d", exitInternal, code)
	}
}

func TestRunSuccessMachineScopeAndSkipIfEnrolled(t *testing.T) {
	h := newEnrollTestHarness(t)
	stateDir := t.TempDir()

	var out, errBuf bytes.Buffer
	promptCalls := 0
	code := run([]string{
		"--product", "aegis-backup",
		"--state-dir", stateDir,
		"--url", h.server.URL,
		"--key-id", "kid-test",
		"--public-key-b64", h.pubB64,
		"--machine-dpapi",
	}, &out, &errBuf, runtimeDeps{
		fingerprintFn: func() string { return h.fp },
		prompt: func(ctx context.Context, params enrollDialogParams, onSubmit enrollSubmitFn) (enrollOutput, error) {
			promptCalls++
			if params.ProductID != protocol.ProductBackup || params.ProductName != "AegisBA Enterprise" {
				t.Fatalf("unexpected dialog params: %+v", params)
			}
			return onSubmit(ctx, params.InitialURL, "CODE-OK")
		},
	})
	if code != exitOK {
		t.Fatalf("expected exit 0, got %d: %s", code, out.String())
	}
	if promptCalls != 1 {
		t.Fatalf("expected 1 prompt call, got %d", promptCalls)
	}
	rawOut := out.String()
	if strings.Contains(rawOut, "CODE-OK") || strings.Contains(rawOut, "tok-secret-never-print") {
		t.Fatalf("stdout leaked secret material: %s", rawOut)
	}

	var parsed enrollOutput
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json output: %v (%s)", err, rawOut)
	}
	if !parsed.OK || parsed.Status != "enrolled" || parsed.InstallID != "inst-enroll-1" || parsed.Plan != "annual" {
		t.Fatalf("unexpected enrollOutput: %+v", parsed)
	}

	// Verify state persisted cleanly and readable by Store.
	loaded, err := protocol.NewMachineStore(stateDir).LoadEnrollment()
	if err != nil {
		t.Fatalf("LoadEnrollment failed: %v", err)
	}
	if loaded.InstallID != "inst-enroll-1" || loaded.InstallationToken != "tok-secret-never-print" {
		t.Fatalf("unexpected stored enrollment: %+v", loaded)
	}

	// Second run with --skip-if-enrolled MUST bypass dialog and return already_enrolled.
	out.Reset()
	code2 := run([]string{
		"--product", "aegis-backup",
		"--state-dir", stateDir,
		"--url", h.server.URL,
		"--key-id", "kid-test",
		"--public-key-b64", h.pubB64,
		"--skip-if-enrolled",
	}, &out, &errBuf, runtimeDeps{
		fingerprintFn: func() string { return h.fp },
		prompt: func(context.Context, enrollDialogParams, enrollSubmitFn) (enrollOutput, error) {
			t.Fatal("dialog should not be opened when already enrolled")
			return enrollOutput{}, nil
		},
	})
	if code2 != exitOK {
		t.Fatalf("expected exit 0 on skip-if-enrolled, got %d: %s", code2, out.String())
	}
	if !strings.Contains(out.String(), `"already_enrolled"`) {
		t.Fatalf("expected already_enrolled status, got: %s", out.String())
	}
}

func TestRunExitCodeClassification(t *testing.T) {
	h := newEnrollTestHarness(t)
	stateDir := t.TempDir()

	// 1. User cancelled
	var out, errBuf bytes.Buffer
	code := run([]string{
		"--product", "aegis-vault",
		"--state-dir", stateDir,
	}, &out, &errBuf, runtimeDeps{
		prompt: func(context.Context, enrollDialogParams, enrollSubmitFn) (enrollOutput, error) {
			return enrollOutput{}, errCancelled
		},
	})
	if code != exitCancelled || !strings.Contains(out.String(), `"cancelled"`) {
		t.Fatalf("expected exitCancelled (1), got %d: %s", code, out.String())
	}

	// 2. Invalid enrollment code (401)
	out.Reset()
	code = run([]string{
		"--product", "aegis-backup",
		"--state-dir", stateDir,
		"--url", h.server.URL,
		"--key-id", "kid-test",
		"--public-key-b64", h.pubB64,
	}, &out, &errBuf, runtimeDeps{
		fingerprintFn: func() string { return h.fp },
		prompt: func(ctx context.Context, params enrollDialogParams, onSubmit enrollSubmitFn) (enrollOutput, error) {
			return onSubmit(ctx, params.InitialURL, "WRONG-CODE")
		},
	})
	if code != exitInvalidCode {
		t.Fatalf("expected exitInvalidCode (2), got %d: %s", code, out.String())
	}

	// 3. Unreachable server (network error)
	out.Reset()
	code = run([]string{
		"--product", "aegis-backup",
		"--state-dir", stateDir,
		"--url", "http://127.0.0.1:1",
	}, &out, &errBuf, runtimeDeps{
		fingerprintFn: func() string { return h.fp },
		prompt: func(ctx context.Context, params enrollDialogParams, onSubmit enrollSubmitFn) (enrollOutput, error) {
			return onSubmit(ctx, params.InitialURL, "CODE-OK")
		},
	})
	if code != exitNetwork {
		t.Fatalf("expected exitNetwork (3), got %d: %s", code, out.String())
	}

	// 4. Generic internal error
	if got := classifyEnrollError(errors.New("disk full")); got != exitInternal {
		t.Fatalf("expected exitInternal (4), got %d", got)
	}
}
