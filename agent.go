package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

type AgentOptions struct {
	Store         Store
	Product       ProductID
	AppVersion    string
	Keys          Verifier
	Client        *Client
	FingerprintFn func() string
}

// Agent coordinates enrollment, Ed25519 lease verification, offline fallback,
// monotonic anti-rollback storage, and telemetry reporting.
type Agent struct {
	store         Store
	product       ProductID
	appVersion    string
	keys          Verifier
	client        *Client
	fingerprintFn func() string
}

func NewAgent(opts AgentOptions) *Agent {
	c := opts.Client
	if c == nil {
		c = NewClient()
	}
	fp := opts.FingerprintFn
	if fp == nil {
		fp = ComputeMachineFingerprint
	}
	return &Agent{
		store:         opts.Store,
		product:       opts.Product,
		appVersion:    opts.AppVersion,
		keys:          opts.Keys,
		client:        c,
		fingerprintFn: fp,
	}
}

func (a *Agent) Enroll(ctx context.Context, baseURL, code, appTarget string) (EnrollResponse, error) {
	fp := a.fingerprintFn()
	res, err := a.client.Enroll(ctx, baseURL, code, EnrollRequest{
		Product:            a.product,
		AppVersion:         a.appVersion,
		MachineFingerprint: fp,
		AppTarget:          appTarget,
	})
	if err != nil {
		return EnrollResponse{}, err
	}
	if _, normErr := NormalizeBaseURL(res.Config.WorkerBaseURL); normErr != nil {
		if normBase, err := NormalizeBaseURL(baseURL); err == nil {
			res.Config.WorkerBaseURL = normBase
		}
	}

	verifier := a.keys
	if verifier.Issuer == "" {
		verifier.Issuer = res.Config.WorkerBaseURL
	}
	claims, err := verifier.VerifyLease(res.LeaseToken, res.InstallID, fp, time.Now().UTC())
	if err != nil {
		return EnrollResponse{}, err
	}
	if err := a.store.SaveEnrollment(res.InstallID, res.InstallationToken, res.Config); err != nil {
		return EnrollResponse{}, err
	}
	if _, err := a.store.SaveLease(res.LeaseToken, claims); err != nil {
		return EnrollResponse{}, err
	}
	return res, nil
}

type CheckOptions struct {
	Capability    string
	RFMAllowed    bool
	RefreshOnline bool
	Now           time.Time
}

func (a *Agent) CheckAccess(ctx context.Context, opts CheckOptions) AccessDecision {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	enrolled, err := a.store.LoadEnrollment()
	if err != nil {
		return EvaluateAccess(AccessInput{
			HasEnrollment: false,
			Now:           now,
			RFMAllowed:    opts.RFMAllowed,
		})
	}

	fp := a.fingerprintFn()
	verifier := a.keys
	if verifier.Issuer == "" {
		verifier.Issuer = enrolled.Config.WorkerBaseURL
	}
	security, _ := a.store.LoadSecurityMetadata()
	revoked := false
	fpMismatch := false

	if opts.RefreshOnline {
		freshJWT, refreshErr := a.client.RefreshLease(ctx, enrolled.Config.WorkerBaseURL, enrolled.InstallationToken, LeaseRequest{
			InstallID:          enrolled.InstallID,
			AppVersion:         a.appVersion,
			MachineFingerprint: fp,
			LeaseNonce:         security.LastLeaseNonce,
		})
		if refreshErr == nil {
			if claims, verifyErr := verifier.VerifyLease(freshJWT, enrolled.InstallID, fp, now); verifyErr == nil {
				if nextSec, saveErr := a.store.SaveLease(freshJWT, claims); saveErr == nil {
					security = nextSec
				}
			} else if errors.Is(verifyErr, ErrFingerprintMismatch) {
				fpMismatch = true
			}
		} else {
			var httpErr *HTTPError
			if errors.As(refreshErr, &httpErr) && httpErr.Status == 403 {
				switch httpErr.Code {
				case "installation_revoked":
					a.store.ClearRevokedCredentials()
					revoked = true
				case "fingerprint_mismatch":
					fpMismatch = true
				}
			}
		}
	}

	if revoked || fpMismatch {
		return EvaluateAccess(AccessInput{
			HasEnrollment:       true,
			Security:            security,
			Now:                 now,
			RFMAllowed:          opts.RFMAllowed,
			Revoked:             revoked,
			FingerprintMismatch: fpMismatch,
		})
	}

	cachedJWT, err := a.store.LoadLeaseToken()
	if err != nil {
		return EvaluateAccess(AccessInput{
			HasEnrollment: false,
			Security:      security,
			Now:           now,
			RFMAllowed:    opts.RFMAllowed,
		})
	}

	claims, verifyErr := verifier.VerifyLease(cachedJWT, enrolled.InstallID, fp, now)
	if verifyErr != nil {
		if errors.Is(verifyErr, ErrFingerprintMismatch) {
			return EvaluateAccess(AccessInput{
				HasEnrollment:       true,
				Security:            security,
				Now:                 now,
				RFMAllowed:          opts.RFMAllowed,
				FingerprintMismatch: true,
			})
		}
		return EvaluateAccess(AccessInput{
			HasEnrollment: false,
			Security:      security,
			Now:           now,
			RFMAllowed:    opts.RFMAllowed,
		})
	}

	return EvaluateAccess(AccessInput{
		HasEnrollment: true,
		Claims:        &claims,
		Security:      security,
		Now:           now,
		RFMAllowed:    opts.RFMAllowed,
	})
}

func (a *Agent) TrackEvent(ctx context.Context, eventType string, payload map[string]any) error {
	enrolled, err := a.store.LoadEnrollment()
	if err != nil {
		return err
	}
	if payload == nil {
		payload = map[string]any{}
	}
	return a.client.SendEvents(ctx, enrolled.Config.WorkerBaseURL, enrolled.InstallationToken, []TelemetryEvent{
		{
			EventID:    randomHex(16),
			OccurredAt: time.Now().UTC().Format(time.RFC3339),
			Type:       eventType,
			AppVersion: a.appVersion,
			Payload:    payload,
		},
	})
}

func randomHex(bytesLen int) string {
	b := make([]byte, bytesLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
