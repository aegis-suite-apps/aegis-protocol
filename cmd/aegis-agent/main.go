package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

// Overridable via -ldflags at build time; defaults to AegisRD key from docs/rd-clave-publica.md.
var (
	DefaultPublicKeyID     = "ed25519-2026-11"
	DefaultPublicKeyBase64 = "MCowBQYDK2VwAyEA1MjofyyH5wOd+0dNGX3icuS+DrmCfETdKug8t0OiqTA="
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "fingerprint":
		writeJSON(map[string]string{"machine_fingerprint": protocol.ComputeMachineFingerprint()})
	case "enroll":
		runEnroll(args)
	case "guard":
		runGuard(args)
	case "event":
		runEvent(args)
	case "status":
		runStatus(args)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: aegis-agent <fingerprint|enroll|guard|event|status> [flags]")
}

func buildVerifier(issuer, keyID, keyB64 string) (protocol.Verifier, error) {
	if keyB64 == "" {
		keyB64 = os.Getenv("AEGIS_PUBLIC_KEY_B64")
	}
	if keyB64 == "" {
		keyB64 = DefaultPublicKeyBase64
	}
	if keyID == "" {
		keyID = DefaultPublicKeyID
	}
	pub, err := protocol.ParsePublicKeyBase64(keyB64)
	if err != nil {
		return protocol.Verifier{}, err
	}
	return protocol.NewVerifier(issuer, map[string]ed25519.PublicKey{keyID: pub}), nil
}

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "State directory")
	rdURL := fs.String("url", "", "Aegis RD base URL")
	code := fs.String("code", "", "One-time enrollment code")
	product := fs.String("product", "", "Product ID")
	version := fs.String("version", "0.1.0", "App version")
	target := fs.String("target", "", "Optional app target")
	issuer := fs.String("issuer", "", "Expected JWT issuer (defaults to RD URL)")
	keyID := fs.String("key-id", DefaultPublicKeyID, "Ed25519 key id")
	keyB64 := fs.String("public-key-b64", "", "Ed25519 SPKI base64 public key")
	_ = fs.Parse(args)

	if *stateDir == "" || *rdURL == "" || *code == "" || *product == "" {
		die("missing required flags: --state-dir, --url, --code, --product")
	}
	verifier, err := buildVerifier(*issuer, *keyID, *keyB64)
	if err != nil {
		die(err.Error())
	}
	agent := protocol.NewAgent(protocol.AgentOptions{
		Store:      protocol.NewStore(*stateDir),
		Product:    protocol.ProductID(*product),
		AppVersion: *version,
		Keys:       verifier,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := agent.Enroll(ctx, *rdURL, *code, *target)
	if err != nil {
		die(err.Error())
	}
	writeJSON(map[string]any{
		"ok":         true,
		"install_id": res.InstallID,
		"product":    res.Config.Product,
		"base_url":   res.Config.WorkerBaseURL,
	})
}

func runGuard(args []string) {
	fs := flag.NewFlagSet("guard", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "State directory")
	product := fs.String("product", "", "Product ID")
	version := fs.String("version", "0.1.0", "App version")
	capability := fs.String("capability", "run", "Requested capability")
	rfmAllowed := fs.Bool("rfm-allowed", false, "Whether capability is allowed under RFM")
	offline := fs.Bool("offline", false, "Skip online lease refresh")
	issuer := fs.String("issuer", "", "Expected JWT issuer")
	keyID := fs.String("key-id", DefaultPublicKeyID, "Ed25519 key id")
	keyB64 := fs.String("public-key-b64", "", "Ed25519 SPKI base64 public key")
	_ = fs.Parse(args)

	if *stateDir == "" || *product == "" {
		die("missing required flags: --state-dir, --product")
	}
	verifier, err := buildVerifier(*issuer, *keyID, *keyB64)
	if err != nil {
		die(err.Error())
	}
	agent := protocol.NewAgent(protocol.AgentOptions{
		Store:      protocol.NewStore(*stateDir),
		Product:    protocol.ProductID(*product),
		AppVersion: *version,
		Keys:       verifier,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dec := agent.CheckAccess(ctx, protocol.CheckOptions{
		Capability:    *capability,
		RFMAllowed:    *rfmAllowed,
		RefreshOnline: !*offline,
	})
	writeJSON(dec)
	if !dec.Allowed {
		os.Exit(3)
	}
}

func runEvent(args []string) {
	fs := flag.NewFlagSet("event", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "State directory")
	product := fs.String("product", "", "Product ID")
	version := fs.String("version", "0.1.0", "App version")
	eventType := fs.String("type", "", "Telemetry event type")
	payloadJSON := fs.String("payload", "{}", "JSON payload object")
	_ = fs.Parse(args)

	if *stateDir == "" || *eventType == "" {
		die("missing required flags: --state-dir, --type")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(*payloadJSON), &payload); err != nil {
		die("invalid --payload json: " + err.Error())
	}
	agent := protocol.NewAgent(protocol.AgentOptions{
		Store:      protocol.NewStore(*stateDir),
		Product:    protocol.ProductID(*product),
		AppVersion: *version,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := agent.TrackEvent(ctx, *eventType, payload); err != nil {
		die(err.Error())
	}
	writeJSON(map[string]any{"ok": true})
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "State directory")
	_ = fs.Parse(args)
	if *stateDir == "" {
		die("missing required flag: --state-dir")
	}
	store := protocol.NewStore(*stateDir)
	enr, err := store.LoadEnrollment()
	if err != nil {
		writeJSON(map[string]any{"enrolled": false, "error": err.Error()})
		os.Exit(1)
	}
	sec, _ := store.LoadSecurityMetadata()
	writeJSON(map[string]any{
		"enrolled":         true,
		"install_id":       enr.InstallID,
		"product":          enr.Config.Product,
		"base_url":         enr.Config.WorkerBaseURL,
		"last_lease_nonce": sec.LastLeaseNonce,
	})
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func die(msg string) {
	writeJSON(map[string]any{"ok": false, "error": msg})
	os.Exit(1)
}
