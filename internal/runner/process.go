package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func execCommand(argv []string) *exec.Cmd {
	// #nosec G204 — argv comes from the container entrypoint operator, not untrusted HTTP input.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

func waitProcess(cmd *exec.Cmd) <-chan error {
	ch := make(chan error, 1)
	go func() {
		ch <- cmd.Wait()
	}()
	return ch
}

func terminate(proc *os.Process) error {
	if proc == nil {
		return nil
	}
	sig := syscall.SIGTERM
	if raw := strings.TrimSpace(os.Getenv("AKEYLESS_INJECT_RESTART_SIGNAL")); raw != "" {
		if s, ok := parseSignal(raw); ok {
			sig = s
		}
	}
	if err := proc.Signal(sig); err != nil {
		return proc.Kill()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return proc.Kill()
}

func parseSignal(name string) (syscall.Signal, bool) {
	switch strings.ToUpper(name) {
	case "SIGTERM", "TERM":
		return syscall.SIGTERM, true
	case "SIGINT", "INT":
		return syscall.SIGINT, true
	case "SIGHUP", "HUP":
		return syscall.SIGHUP, true
	case "SIGKILL", "KILL":
		return syscall.SIGKILL, true
	default:
		return 0, false
	}
}

func runRestartCommand(cmdline string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return fmt.Errorf("empty restart command")
	}
	// #nosec G204 — operator-provided sidecar restart hook.
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
