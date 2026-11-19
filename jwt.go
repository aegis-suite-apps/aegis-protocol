package protocol

import (
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrFingerprintMismatch = errors.New("machine fingerprint mismatch")
	ErrAudienceMismatch    = errors.New("lease audience does not match")
	ErrSubjectMismatch     = errors.New("lease subject does not match installation")
)

type jwtClaimsWire struct {
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
	jwt.RegisteredClaims
}

// Verifier validates Ed25519-signed Protocol v2 JWT leases.
type Verifier struct {
	Issuer string
	Keys   map[string]ed25519.PublicKey
}

// NewVerifier creates a lease verifier for a specific issuer and key map.
func NewVerifier(issuer string, keys map[string]ed25519.PublicKey) Verifier {
	return Verifier{Issuer: issuer, Keys: keys}
}

// ParsePublicKeyBase64 decodes an Ed25519 SPKI DER public key encoded as base64.
func ParsePublicKeyBase64(spkiBase64 string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(spkiBase64))
	if err != nil {
		return nil, fmt.Errorf("decode base64 public key: %w", err)
	}
	return parseSPKIDER(der)
}

// ParsePublicKeyPEM decodes an Ed25519 SPKI public key in PEM format.
func ParsePublicKeyPEM(pemText string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("public key PEM is empty")
	}
	return parseSPKIDER(block.Bytes)
}

func parseSPKIDER(der []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return key, nil
}

// VerifyLease verifies cryptographic Ed25519 signature, issuer, audience, subject,
// nbf, and optional machine fingerprint. Expiration is left to EvaluateAccess so
// GRACE vs RFM transitions can be classified offline using monotonic time.
func (v Verifier) VerifyLease(tokenString, installID, machineFingerprint string, now time.Time) (LeaseClaims, error) {
	if v.Issuer == "" || len(v.Keys) == 0 {
		return LeaseClaims{}, errors.New("lease verifier is not configured")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	wire := &jwtClaimsWire{}
	tok, err := jwt.ParseWithClaims(tokenString, wire, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodEdDSA {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("missing key id")
		}
		key, ok := v.Keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id %q", kid)
		}
		return key, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || tok == nil || !tok.Valid {
		if err == nil {
			err = errors.New("invalid token")
		}
		return LeaseClaims{}, fmt.Errorf("verify lease token: %w", err)
	}

	if wire.Issuer != v.Issuer {
		return LeaseClaims{}, fmt.Errorf("lease issuer mismatch: got %q", wire.Issuer)
	}
	if !containsAudience(wire.Audience, AgentJWTAudience) {
		return LeaseClaims{}, ErrAudienceMismatch
	}
	if !strings.EqualFold(wire.Subject, installID) {
		return LeaseClaims{}, ErrSubjectMismatch
	}
	if wire.ProtocolVersion != ProtocolVersion {
		return LeaseClaims{}, fmt.Errorf("unsupported protocol version %d", wire.ProtocolVersion)
	}
	if wire.IssuedAt == nil || wire.NotBefore == nil || wire.ExpiresAt == nil {
		return LeaseClaims{}, errors.New("missing required JWT time claims")
	}
	if wire.NotBefore.Time.After(now.Add(10 * time.Second)) {
		return LeaseClaims{}, errors.New("lease token is not active yet")
	}
	if machineFingerprint != "" && !constantTimeEqual(wire.MachineFingerprintHash, machineFingerprint) {
		return LeaseClaims{}, ErrFingerprintMismatch
	}

	notices := wire.Notices
	if notices == nil {
		notices = []Notice{}
	}

	return LeaseClaims{
		Issuer:                 wire.Issuer,
		Audience:               []string(wire.Audience),
		Subject:                wire.Subject,
		ID:                     wire.ID,
		IssuedAt:               wire.IssuedAt.Unix(),
		NotBefore:              wire.NotBefore.Unix(),
		ExpiresAt:              wire.ExpiresAt.Unix(),
		ProtocolVersion:        wire.ProtocolVersion,
		ServerTime:             wire.ServerTime,
		CacheUntil:             wire.CacheUntil,
		GraceUntil:             wire.GraceUntil,
		Product:                wire.Product,
		AppName:                wire.AppName,
		MachineFingerprintHash: wire.MachineFingerprintHash,
		LeaseNonce:             wire.LeaseNonce,
		Enforcement:            wire.Enforcement,
		License:                wire.License,
		Contact:                wire.Contact,
		Notices:                notices,
		RequiredTermsVersion:   wire.RequiredTermsVersion,
		TermsURL:               wire.TermsURL,
		PrivacyURL:             wire.PrivacyURL,
		Config:                 wire.Config,
	}, nil
}

func containsAudience(audience jwt.ClaimStrings, expected string) bool {
	for _, value := range audience {
		if value == expected {
			return true
		}
	}
	return false
}

// SignLease signs a LeaseClaims payload using Ed25519 (EdDSA) for testing and local harnesses.
func SignLease(claims LeaseClaims, keyID string, priv ed25519.PrivateKey) (string, error) {
	if keyID == "" {
		return "", errors.New("keyID is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid Ed25519 private key")
	}
	wire := jwtClaimsWire{
		ProtocolVersion:        claims.ProtocolVersion,
		ServerTime:             claims.ServerTime,
		CacheUntil:             claims.CacheUntil,
		GraceUntil:             claims.GraceUntil,
		Product:                claims.Product,
		AppName:                claims.AppName,
		MachineFingerprintHash: claims.MachineFingerprintHash,
		LeaseNonce:             claims.LeaseNonce,
		Enforcement:            claims.Enforcement,
		License:                claims.License,
		Contact:                claims.Contact,
		Notices:                claims.Notices,
		RequiredTermsVersion:   claims.RequiredTermsVersion,
		TermsURL:               claims.TermsURL,
		PrivacyURL:             claims.PrivacyURL,
		Config:                 claims.Config,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  jwt.ClaimStrings(claims.Audience),
			ID:        claims.ID,
			IssuedAt:  jwt.NewNumericDate(time.Unix(claims.IssuedAt, 0).UTC()),
			NotBefore: jwt.NewNumericDate(time.Unix(claims.NotBefore, 0).UTC()),
			ExpiresAt: jwt.NewNumericDate(time.Unix(claims.ExpiresAt, 0).UTC()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, wire)
	tok.Header["kid"] = keyID
	return tok.SignedString(priv)
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
