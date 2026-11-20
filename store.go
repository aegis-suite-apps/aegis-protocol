package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrNotEnrolled = errors.New("equipment is not enrolled in Aegis RD")
var ErrPolicyRollback = errors.New("signed lease rollback detected")

type StoredEnrollment struct {
	InstallID         string      `json:"install_id"`
	InstallationToken string      `json:"-"`
	Config            AgentConfig `json:"-"`
}

type agentDiskFile struct {
	InstallID       string    `json:"install_id"`
	WorkerBaseURL   string    `json:"worker_base_url"`
	Product         ProductID `json:"product"`
	AppName         string    `json:"app_name"`
	AppTarget       string    `json:"app_target"`
	EquipmentName   string    `json:"equipment_name"`
	ContactName     string    `json:"contact_name"`
	TicketURL       string    `json:"ticket_url"`
	ProtocolVersion int       `json:"protocol_version"`
}

// Store persists Protocol v2 credentials (DPAPI-protected on Windows), lease JWT cache,
// and monotonic anti-rollback security metadata in a state directory.
type Store struct {
	Dir          string
	MachineScope bool
}

func NewStore(dir string) Store {
	return Store{Dir: dir}
}

// NewMachineStore returns a Store using machine-scoped Windows DPAPI
// (CRYPTPROTECT_LOCAL_MACHINE) so services and scheduled tasks share the token.
func NewMachineStore(dir string) Store {
	return Store{Dir: dir, MachineScope: true}
}

func (s Store) tokenPath() string    { return filepath.Join(s.Dir, "token.dpapi") }
func (s Store) agentPath() string    { return filepath.Join(s.Dir, "agent.json") }
func (s Store) leasePath() string    { return filepath.Join(s.Dir, "lease.jwt") }
func (s Store) securityPath() string { return filepath.Join(s.Dir, "security.json") }

func (s Store) EnsureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	_ = applyRestrictedACL(s.Dir, true)
	return nil
}

func (s Store) atomicWrite(target string, data []byte) error {
	if err := s.EnsureDir(); err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, fmt.Sprintf(".%s.tmp.%d", filepath.Base(target), os.Getpid()))
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = applyRestrictedACL(target, false)
	return nil
}

func (s Store) SaveEnrollment(installID, installationToken string, cfg AgentConfig) error {
	if strings.TrimSpace(installID) == "" || strings.TrimSpace(installationToken) == "" {
		return errors.New("install_id and installation_token are required")
	}
	cipher, err := protectBytesWithScope([]byte(installationToken), s.MachineScope)
	if err != nil {
		return err
	}
	if err := s.atomicWrite(s.tokenPath(), cipher); err != nil {
		return err
	}
	disk := agentDiskFile{
		InstallID:       installID,
		WorkerBaseURL:   cfg.WorkerBaseURL,
		Product:         cfg.Product,
		AppName:         cfg.AppName,
		AppTarget:       cfg.AppTarget,
		EquipmentName:   cfg.EquipmentName,
		ContactName:     cfg.ContactName,
		TicketURL:       cfg.TicketURL,
		ProtocolVersion: cfg.ProtocolVersion,
	}
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	return s.atomicWrite(s.agentPath(), append(raw, '\n'))
}

func (s Store) LoadEnrollment() (StoredEnrollment, error) {
	agentData, err := os.ReadFile(s.agentPath())
	if errors.Is(err, os.ErrNotExist) {
		return StoredEnrollment{}, ErrNotEnrolled
	}
	if err != nil {
		return StoredEnrollment{}, err
	}
	cipher, err := os.ReadFile(s.tokenPath())
	if errors.Is(err, os.ErrNotExist) {
		return StoredEnrollment{}, ErrNotEnrolled
	}
	if err != nil {
		return StoredEnrollment{}, err
	}

	var disk agentDiskFile
	if err := json.Unmarshal(agentData, &disk); err != nil {
		return StoredEnrollment{}, fmt.Errorf("parse agent.json: %w", err)
	}
	plain, err := unprotectBytes(cipher)
	if err != nil {
		return StoredEnrollment{}, fmt.Errorf("unprotect token.dpapi: %w", err)
	}
	token := strings.TrimSpace(string(plain))
	if disk.InstallID == "" || disk.WorkerBaseURL == "" || token == "" {
		return StoredEnrollment{}, errors.New("incomplete enrollment state on disk")
	}

	return StoredEnrollment{
		InstallID:         disk.InstallID,
		InstallationToken: token,
		Config: AgentConfig{
			WorkerBaseURL:   disk.WorkerBaseURL,
			Product:         disk.Product,
			AppName:         disk.AppName,
			AppTarget:       disk.AppTarget,
			EquipmentName:   disk.EquipmentName,
			ContactName:     disk.ContactName,
			TicketURL:       disk.TicketURL,
			ProtocolVersion: disk.ProtocolVersion,
		},
	}, nil
}

func (s Store) LoadSecurityMetadata() (SecurityMetadata, error) {
	data, err := os.ReadFile(s.securityPath())
	if errors.Is(err, os.ErrNotExist) {
		return SecurityMetadata{}, nil
	}
	if err != nil {
		return SecurityMetadata{}, err
	}
	var sec SecurityMetadata
	if err := json.Unmarshal(data, &sec); err != nil {
		return SecurityMetadata{}, err
	}
	return sec, nil
}

func (s Store) SaveLease(leaseJWT string, claims LeaseClaims) (SecurityMetadata, error) {
	sec, err := s.LoadSecurityMetadata()
	if err != nil {
		return SecurityMetadata{}, err
	}
	if sec.LastLeaseIssuedAt > claims.IssuedAt {
		return SecurityMetadata{}, ErrPolicyRollback
	}
	next := SecurityMetadata{
		LastLeaseIssuedAt: maxInt64(sec.LastLeaseIssuedAt, claims.IssuedAt),
		LastLeaseNonce:    claims.LeaseNonce,
	}
	if serverTime, parseErr := parseServerTimeUnix(claims.ServerTime); parseErr == nil {
		next.LastServerTime = maxInt64(sec.LastServerTime, serverTime)
	} else {
		next.LastServerTime = sec.LastServerTime
	}

	if err := s.atomicWrite(s.leasePath(), []byte(leaseJWT)); err != nil {
		return SecurityMetadata{}, err
	}
	rawSec, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return SecurityMetadata{}, err
	}
	if err := s.atomicWrite(s.securityPath(), append(rawSec, '\n')); err != nil {
		return SecurityMetadata{}, err
	}
	return next, nil
}

func (s Store) LoadLeaseToken() (string, error) {
	data, err := os.ReadFile(s.leasePath())
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotEnrolled
	}
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", ErrNotEnrolled
	}
	return tok, nil
}

func (s Store) ClearRevokedCredentials() {
	for _, target := range []string{s.tokenPath(), s.leasePath()} {
		_ = os.Remove(target)
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
