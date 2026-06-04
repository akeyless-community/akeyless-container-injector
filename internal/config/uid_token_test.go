package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUIDTokenFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uid-token")
	if err := os.WriteFile(path, []byte("  my-uid-token  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvUIDToken, "")
	t.Setenv(EnvUIDTokenFile, path)

	got, err := ResolveUIDToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != "my-uid-token" {
		t.Fatalf("token = %q", got)
	}
}

func TestValidateUniversalIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "uid-token")
	if err := os.WriteFile(path, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvUIDToken, "")
	t.Setenv(EnvUIDTokenFile, path)
	t.Setenv(EnvAccessType, "uid")

	a := LoadAuth()
	if a.AccessType != "universal_identity" {
		t.Fatalf("access type = %q", a.AccessType)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}
