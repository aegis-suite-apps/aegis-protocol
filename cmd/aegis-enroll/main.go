package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

// Overridable via -ldflags at build time; defaults to canonical AegisRD key in protocol package.
var (
	DefaultPublicKeyID     = protocol.DefaultPublicKeyID
	DefaultPublicKeyBase64 = protocol.DefaultPublicKeyBase64
)

const (
	exitOK          = 0
	exitCancelled   = 1
	exitInvalidCode = 2
	exitNetwork     = 3
	exitInternal    = 4
)

var errCancelled = errors.New("enrollment cancelled by user")

type enrollOutput struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	Product   string `json:"product,omitempty"`
	InstallID string `json:"install_id,omitempty"`
	Equipment string `json:"equipment,omitempty"`
	BaseURL   string `json:"base_url,omitempty"`
	Plan      string `json:"plan,omitempty"`
	Error     string `json:"error,omitempty"`
}

type enrollDialogParams struct {
	ProductID   protocol.ProductID
	ProductName string
	Hostname    string
	InitialURL  string
}

type enrollSubmitFn func(ctx context.Context, rdURL, code string) (enrollOutput, error)

type promptEnrollFn func(ctx context.Context, params enrollDialogParams, onSubmit enrollSubmitFn) (enrollOutput, error)

type runtimeDeps struct {
	prompt        promptEnrollFn
	client        *protocol.Client
	fingerprintFn func() string
}

var productDisplayNames = map[protocol.ProductID]string{
	protocol.ProductBackup: "AegisBA Enterprise",
	protocol.ProductVault:  "Aegis Vault",
	protocol.ProductGate:   "Aegis Gate",
	protocol.ProductSetup:  "Aegis Setup",
	protocol.ProductShell:  "AegisDesk Shell",
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr, runtimeDeps{
		prompt: showEnrollDialog,
	})
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer, deps runtimeDeps) int {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		writeJSON(stdout, enrollOutput{
			OK:     false,
			Status: "error",
			Error:  err.Error(),
		})
		return exitInternal
	}

	productName := productDisplayNames[cfg.product]
	store := buildStore(cfg.stateDir, cfg.machineDPAPI)
	verifier, err := buildVerifier(cfg.issuer, cfg.keyID, cfg.keyB64)
	if err != nil {
		writeJSON(stdout, enrollOutput{
			OK:      false,
			Status:  "error",
			Product: string(cfg.product),
			Error:   err.Error(),
		})
		return exitInternal
	}

	agent := protocol.NewAgent(protocol.AgentOptions{
		Store:         store,
		Product:       cfg.product,
		AppVersion:    cfg.version,
		Keys:          verifier,
		Client:        deps.client,
		FingerprintFn: deps.fingerprintFn,
	})

	if cfg.skipIfEnrolled {
		if out, ok := checkExistingEnrollment(store, agent, verifier, cfg.product, deps.fingerprintFn); ok {
			writeJSON(stdout, out)
			return exitOK
		}
	}

	if deps.prompt == nil {
		writeJSON(stdout, enrollOutput{
			OK:      false,
			Status:  "error",
			Product: string(cfg.product),
			Error:   "interactive dialog handler is not configured",
		})
		return exitInternal
	}

	hostname, _ := os.Hostname()
	if strings.TrimSpace(hostname) == "" {
		hostname = "EQUIPO-LOCAL"
	}

	onSubmit := func(ctx context.Context, rdURL, enrollCode string) (enrollOutput, error) {
		normURL, normErr := protocol.NormalizeBaseURL(rdURL)
		if normErr != nil {
			return enrollOutput{}, normErr
		}
		trimmedCode := strings.TrimSpace(enrollCode)
		if trimmedCode == "" {
			return enrollOutput{}, errors.New("el código de enrolamiento es obligatorio")
		}

		reqCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
		defer cancel()

		submitAgent := agent
		if strings.TrimSpace(cfg.issuer) == "" {
			submitVerifier, vErr := buildVerifier(normURL, cfg.keyID, cfg.keyB64)
			if vErr != nil {
				return enrollOutput{}, vErr
			}
			submitAgent = protocol.NewAgent(protocol.AgentOptions{
				Store:         store,
				Product:       cfg.product,
				AppVersion:    cfg.version,
				Keys:          submitVerifier,
				Client:        deps.client,
				FingerprintFn: deps.fingerprintFn,
			})
		}

		res, err := submitAgent.Enroll(reqCtx, normURL, trimmedCode, cfg.target)
		if err != nil {
			return enrollOutput{}, err
		}

		plan := extractPlan(res.LeaseToken, res.InstallID, normURL, cfg.issuer, cfg.keyID, cfg.keyB64)
		return enrollOutput{
			OK:        true,
			Status:    "enrolled",
			Product:   string(cfg.product),
			InstallID: res.InstallID,
			Equipment: res.Config.EquipmentName,
			BaseURL:   res.Config.WorkerBaseURL,
			Plan:      plan,
		}, nil
	}

	out, err := deps.prompt(context.Background(), enrollDialogParams{
		ProductID:   cfg.product,
		ProductName: productName,
		Hostname:    hostname,
		InitialURL:  cfg.rdURL,
	}, onSubmit)
	if err != nil {
		status := "error"
		if errors.Is(err, errCancelled) {
			status = "cancelled"
		}
		writeJSON(stdout, enrollOutput{
			OK:      false,
			Status:  status,
			Product: string(cfg.product),
			Error:   err.Error(),
		})
		return classifyEnrollError(err)
	}

	writeJSON(stdout, out)
	return exitOK
}

type parsedFlags struct {
	product        protocol.ProductID
	stateDir       string
	rdURL          string
	version        string
	target         string
	issuer         string
	keyID          string
	keyB64         string
	machineDPAPI   bool
	skipIfEnrolled bool
	timeout        time.Duration
}

func parseFlags(args []string, stderr io.Writer) (parsedFlags, error) {
	fs := flag.NewFlagSet("aegis-enroll", flag.ContinueOnError)
	if stderr == nil {
		stderr = io.Discard
	}
	fs.SetOutput(stderr)

	var rawProduct string
	var cfg parsedFlags
	fs.StringVar(&rawProduct, "product", "", "Product ID (aegis-backup, aegis-vault, aegis-gate, aegis-setup, aegis-shell)")
	fs.StringVar(&cfg.stateDir, "state-dir", "", "Directory where RD credentials and lease cache are stored")
	fs.StringVar(&cfg.rdURL, "url", protocol.DefaultIssuer, "Aegis RD base URL")
	fs.StringVar(&cfg.version, "version", "0.3.0", "Caller application version")
	fs.StringVar(&cfg.target, "target", "", "Optional app target label")
	fs.StringVar(&cfg.issuer, "issuer", "", "Expected JWT issuer override (defaults to RD URL)")
	fs.StringVar(&cfg.keyID, "key-id", DefaultPublicKeyID, "Ed25519 key id override")
	fs.StringVar(&cfg.keyB64, "public-key-b64", "", "Ed25519 SPKI base64 public key override")
	fs.BoolVar(&cfg.machineDPAPI, "machine-dpapi", false, "Use machine-scoped Windows DPAPI (CRYPTPROTECT_LOCAL_MACHINE)")
	fs.BoolVar(&cfg.skipIfEnrolled, "skip-if-enrolled", false, "Exit 0 without UI if state-dir already holds a valid enrollment")
	fs.DurationVar(&cfg.timeout, "timeout", 30*time.Second, "HTTP request timeout")

	if err := fs.Parse(args); err != nil {
		return parsedFlags{}, err
	}
	if fs.NArg() > 0 {
		return parsedFlags{}, fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	cfg.product = protocol.ProductID(strings.TrimSpace(rawProduct))
	if _, ok := productDisplayNames[cfg.product]; !ok {
		return parsedFlags{}, fmt.Errorf("invalid or missing --product %q", rawProduct)
	}
	cfg.stateDir = strings.TrimSpace(cfg.stateDir)
	if cfg.stateDir == "" {
		return parsedFlags{}, errors.New("--state-dir is required")
	}
	if strings.TrimSpace(cfg.rdURL) == "" {
		cfg.rdURL = protocol.DefaultIssuer
	}
	if _, err := protocol.NormalizeBaseURL(cfg.rdURL); err != nil {
		return parsedFlags{}, err
	}
	if cfg.timeout <= 0 {
		cfg.timeout = 30 * time.Second
	}
	return cfg, nil
}

func buildStore(stateDir string, machineDPAPI bool) protocol.Store {
	if machineDPAPI {
		return protocol.NewMachineStore(stateDir)
	}
	return protocol.NewStore(stateDir)
}

func buildVerifier(issuer, keyID, keyB64 string) (protocol.Verifier, error) {
	if strings.TrimSpace(keyB64) == "" {
		keyB64 = os.Getenv("AEGIS_PUBLIC_KEY_B64")
	}
	if strings.TrimSpace(keyB64) == "" {
		keyB64 = DefaultPublicKeyBase64
	}
	if strings.TrimSpace(keyID) == "" {
		keyID = DefaultPublicKeyID
	}
	return protocol.NewVerifierWithOverride(issuer, keyID, keyB64)
}

func checkExistingEnrollment(
	store protocol.Store,
	agent *protocol.Agent,
	verifier protocol.Verifier,
	expectedProduct protocol.ProductID,
	fpFn func() string,
) (enrollOutput, bool) {
	enrolled, err := store.LoadEnrollment()
	if err != nil {
		return enrollOutput{}, false
	}
	if enrolled.Config.Product != "" && enrolled.Config.Product != expectedProduct {
		return enrollOutput{}, false
	}
	dec := agent.CheckAccess(context.Background(), protocol.CheckOptions{
		Capability:    "enroll_check",
		RFMAllowed:    true,
		RefreshOnline: false,
	})
	switch dec.State {
	case protocol.StateRequireEnroll, protocol.StateRevoked, protocol.StateFingerprintMismatch:
		return enrollOutput{}, false
	}
	fp := ""
	if fpFn != nil {
		fp = fpFn()
	}
	plan := ""
	if leaseJWT, lErr := store.LoadLeaseToken(); lErr == nil {
		v := verifier
		if v.Issuer == "" {
			v.Issuer = enrolled.Config.WorkerBaseURL
		}
		if claims, cErr := v.VerifyLease(leaseJWT, enrolled.InstallID, fp, time.Now().UTC()); cErr == nil {
			plan = string(claims.License.Plan)
		}
	}
	return enrollOutput{
		OK:        true,
		Status:    "already_enrolled",
		Product:   string(expectedProduct),
		InstallID: enrolled.InstallID,
		Equipment: enrolled.Config.EquipmentName,
		BaseURL:   enrolled.Config.WorkerBaseURL,
		Plan:      plan,
	}, true
}

func extractPlan(leaseJWT, installID, normURL, issuerOverride, keyID, keyB64 string) string {
	iss := strings.TrimSpace(issuerOverride)
	if iss == "" {
		iss = normURL
	}
	v, err := buildVerifier(iss, keyID, keyB64)
	if err != nil {
		return ""
	}
	claims, err := v.VerifyLease(leaseJWT, installID, "", time.Now().UTC())
	if err != nil {
		return ""
	}
	return string(claims.License.Plan)
}

func classifyEnrollError(err error) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, errCancelled) {
		return exitCancelled
	}
	var httpErr *protocol.HTTPError
	if errors.As(err, &httpErr) {
		if httpErr.Status >= 500 {
			return exitNetwork
		}
		if httpErr.Status >= 400 && httpErr.Status < 500 {
			return exitInvalidCode
		}
	}
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return exitNetwork
	}
	if strings.Contains(err.Error(), "invalid Aegis RD URL") || strings.Contains(err.Error(), "must use https") {
		return exitNetwork
	}
	return exitInternal
}

func formatFriendlyError(err error) string {
	if err == nil {
		return ""
	}
	var httpErr *protocol.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.Code {
		case "invalid_code", "enrollment_code_invalid", "enrollment_code_expired", "enrollment_code_used":
			return "Código inválido, vencido o ya utilizado. Generá uno nuevo en Aegis RD."
		case "product_mismatch":
			return "Este código corresponde a otro producto en Aegis RD."
		default:
			if httpErr.Status == 401 || httpErr.Status == 404 {
				return "Código inválido o vencido. Verificalo e intentá de nuevo."
			}
			if httpErr.Message != "" {
				return fmt.Sprintf("Aegis RD rechazó la solicitud (%d): %s", httpErr.Status, httpErr.Message)
			}
			return fmt.Sprintf("Aegis RD devolvió error HTTP %d.", httpErr.Status)
		}
	}
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return "No se pudo conectar con Aegis RD. Revisá la URL e internet."
	}
	return err.Error()
}

func writeJSON(w io.Writer, out enrollOutput) {
	if w == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(out)
}
