package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSpecDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inject.yaml")
	if err := os.WriteFile(path, []byte(`
secrets:
  - path: /foo/bar
    env: FOO
`), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.SecretDir != "/akeyless/secrets" {
		t.Fatalf("secret_dir = %q", spec.SecretDir)
	}
	if spec.Refresh.OnChange != OnChangeRestart {
		t.Fatalf("on_change = %q, want restart", spec.Refresh.OnChange)
	}
	if spec.Refresh.Interval != "30s" {
		t.Fatalf("interval = %q", spec.Refresh.Interval)
	}
}

func TestLoadSpecCertificateDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inject.yaml")
	if err := os.WriteFile(path, []byte(`
secrets:
  - path: /pki/cert
    type: certificate
`), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	sec := spec.Secrets[0]
	if sec.File != "tls.crt" || sec.KeyFile != "tls.key" {
		t.Fatalf("files = %q / %q", sec.File, sec.KeyFile)
	}
}

func TestLoadSpecFileOnlyDefaultsToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inject.yaml")
	if err := os.WriteFile(path, []byte(`
secrets:
  - path: /foo/bar
    file: bar
`), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := LoadSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Refresh.OnChange != OnChangeFile {
		t.Fatalf("on_change = %q, want file", spec.Refresh.OnChange)
	}
}
