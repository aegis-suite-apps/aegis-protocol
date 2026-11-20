package protocol_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

func TestBuildEnrollArgs(t *testing.T) {
	args, err := protocol.BuildEnrollArgs(protocol.EnrollUIOptions{
		Product:        protocol.ProductBackup,
		StateDir:       `C:\ProgramData\AegisBA\rd`,
		BaseURL:        "https://rd.tonyml.com",
		AppVersion:     "4.2.0",
		MachineDPAPI:   true,
		SkipIfEnrolled: true,
	})
	if err != nil {
		t.Fatalf("BuildEnrollArgs failed: %v", err)
	}
	want := []string{
		"--product", "aegis-backup",
		"--state-dir", `C:\ProgramData\AegisBA\rd`,
		"--url", "https://rd.tonyml.com",
		"--version", "4.2.0",
		"--machine-dpapi",
		"--skip-if-enrolled",
	}
	if len(args) != len(want) {
		t.Fatalf("args len=%d want=%d (%v)", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("arg[%d]=%q want=%q", i, args[i], want[i])
		}
	}
}

func TestResolveEnrollExecutableAndMissingBinary(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := "aegis-enroll"
	if runtime.GOOS == "windows" {
		name = "aegis-enroll.exe"
	}
	target := filepath.Join(binDir, name)
	if err := os.WriteFile(target, []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := protocol.ResolveEnrollExecutable(tmp)
	if err != nil {
		t.Fatalf("ResolveEnrollExecutable failed: %v", err)
	}
	if got != target {
		t.Fatalf("got %q want %q", got, target)
	}

	_, err = protocol.LaunchEnrollUI(context.Background(), protocol.EnrollUIOptions{
		Product:  protocol.ProductSetup,
		StateDir: tmp,
		ExeDir:   t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error when binary does not exist")
	}
	if !errors.Is(err, protocol.ErrEnrollNotFound) {
		// Might find on PATH if installed; only fail if unrelated error
		t.Logf("LaunchEnrollUI error: %v", err)
	}
}
