package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrEnrollNotFound  = errors.New("aegis-enroll executable not found")
	ErrEnrollCancelled = errors.New("enrollment cancelled by user")
)

type EnrollUIOptions struct {
	Product        ProductID
	StateDir       string
	BaseURL        string
	Target         string
	AppVersion     string
	MachineDPAPI   bool
	SkipIfEnrolled bool
	ExeDir         string
}

type EnrollUIResult struct {
	OK        bool   `json:"ok"`
	Status    string `json:"status"`
	Product   string `json:"product,omitempty"`
	InstallID string `json:"install_id,omitempty"`
	Equipment string `json:"equipment,omitempty"`
	BaseURL   string `json:"base_url,omitempty"`
	Plan      string `json:"plan,omitempty"`
	Error     string `json:"error,omitempty"`
}

func enrollBinaryName() string {
	if runtime.GOOS == "windows" {
		return "aegis-enroll.exe"
	}
	return "aegis-enroll"
}

// ResolveEnrollExecutable locates aegis-enroll next to exeDir, next to the running
// binary, inside a local bin/ folder, or on PATH.
func ResolveEnrollExecutable(exeDir string) (string, error) {
	name := enrollBinaryName()
	var candidates []string
	if strings.TrimSpace(exeDir) != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, name),
			filepath.Join(exeDir, "bin", name),
		)
	}
	if self, err := os.Executable(); err == nil {
		selfDir := filepath.Dir(self)
		candidates = append(candidates,
			filepath.Join(selfDir, name),
			filepath.Join(selfDir, "bin", name),
		)
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c, nil
		}
	}
	if found, err := exec.LookPath(name); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("%w (%s)", ErrEnrollNotFound, name)
}

// BuildEnrollArgs constructs the CLI argument list for aegis-enroll without ever passing secrets.
func BuildEnrollArgs(opts EnrollUIOptions) ([]string, error) {
	if strings.TrimSpace(string(opts.Product)) == "" {
		return nil, errors.New("product is required")
	}
	if strings.TrimSpace(opts.StateDir) == "" {
		return nil, errors.New("stateDir is required")
	}
	args := []string{
		"--product", string(opts.Product),
		"--state-dir", opts.StateDir,
	}
	if strings.TrimSpace(opts.BaseURL) != "" {
		args = append(args, "--url", strings.TrimSpace(opts.BaseURL))
	}
	if strings.TrimSpace(opts.Target) != "" {
		args = append(args, "--target", strings.TrimSpace(opts.Target))
	}
	if strings.TrimSpace(opts.AppVersion) != "" {
		args = append(args, "--version", strings.TrimSpace(opts.AppVersion))
	}
	if opts.MachineDPAPI {
		args = append(args, "--machine-dpapi")
	}
	if opts.SkipIfEnrolled {
		args = append(args, "--skip-if-enrolled")
	}
	return args, nil
}

// LaunchEnrollUI runs aegis-enroll synchronously and decodes its structured JSON result.
func LaunchEnrollUI(ctx context.Context, opts EnrollUIOptions) (EnrollUIResult, error) {
	exe, err := ResolveEnrollExecutable(opts.ExeDir)
	if err != nil {
		return EnrollUIResult{}, err
	}
	args, err := BuildEnrollArgs(opts)
	if err != nil {
		return EnrollUIResult{}, err
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var res EnrollUIResult
	rawOut := strings.TrimSpace(stdout.String())
	if rawOut != "" {
		_ = json.Unmarshal([]byte(rawOut), &res)
	}

	if runErr == nil {
		if !res.OK {
			res.OK = true
		}
		return res, nil
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 1 {
		return res, ErrEnrollCancelled
	}
	if res.Error != "" {
		return res, fmt.Errorf("aegis-enroll: %s", res.Error)
	}
	if errText := strings.TrimSpace(stderr.String()); errText != "" {
		return res, fmt.Errorf("aegis-enroll: %s (%w)", errText, runErr)
	}
	return res, runErr
}
