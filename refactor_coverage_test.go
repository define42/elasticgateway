package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainFailurePathExitsNonZero(t *testing.T) {
	if os.Getenv("ELASTICGATEWAY_CALL_MAIN") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainFailurePathExitsNonZero")
	cmd.Env = append(os.Environ(),
		"ELASTICGATEWAY_CALL_MAIN=1",
		"ELASTICSEARCH_URL=://bad",
	)

	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected main() subprocess to exit with an error")
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected exit error, got %v", err)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit code, got %d", exitErr.ExitCode())
	}
	if !strings.Contains(string(output), "error:") {
		t.Fatalf("expected fatal error output, got %q", string(output))
	}
}
