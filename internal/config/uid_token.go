package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	EnvUIDToken     = "AKEYLESS_UID_TOKEN"
	EnvUIDTokenFile = "AKEYLESS_UID_TOKEN_FILE"
)

// DefaultUIDTokenFilePath matches akeyless uid-auto-rotate defaults.
func DefaultUIDTokenFilePath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "akeyless", "uid_rotator", "uid-token")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".akeyless", "uid_rotator", "uid-token")
}

// ResolveUIDToken returns a Universal Identity token from env or from a file on disk.
// The file is re-read on every call so uid-auto-rotate updates are picked up.
func ResolveUIDToken() (string, error) {
	if v := strings.TrimSpace(os.Getenv(EnvUIDToken)); v != "" {
		return v, nil
	}
	path := strings.TrimSpace(os.Getenv(EnvUIDTokenFile))
	if path == "" {
		path = DefaultUIDTokenFilePath()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read UID token from %q: %w (set %s or %s)", path, err, EnvUIDToken, EnvUIDTokenFile)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("UID token file %q is empty", path)
	}
	return token, nil
}

func normalizeAccessType(at string) string {
	switch strings.ToLower(strings.TrimSpace(at)) {
	case "uid", "universal_identity", "universal-identity":
		return "universal_identity"
	default:
		return strings.TrimSpace(at)
	}
}
