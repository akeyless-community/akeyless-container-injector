package inject

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/akeyless-community/akeyless-container-injector/internal/akeyless"
	"github.com/akeyless-community/akeyless-container-injector/internal/config"
)

type Result struct {
	Env         map[string]string
	Fingerprints map[string]string // secret path -> fingerprint
}

func Apply(spec config.Spec, materials map[string]akeyless.Material) (Result, error) {
	res := Result{
		Env:          make(map[string]string),
		Fingerprints: make(map[string]string),
	}
	if err := os.MkdirAll(spec.SecretDir, 0o700); err != nil {
		return Result{}, err
	}
	for _, target := range spec.Secrets {
		path := normalizePath(target.Path)
		mat, ok := materials[path]
		if !ok {
			return Result{}, fmt.Errorf("missing material for %q", path)
		}
		res.Fingerprints[path] = mat.Fingerprint
		if target.Env != "" {
			if target.Type == config.TypeCertificate && mat.CertPEM != "" {
				res.Env[target.Env] = mat.CertPEM
			} else {
				res.Env[target.Env] = mat.Value
			}
		}
		if target.KeyEnv != "" && mat.KeyPEM != "" {
			res.Env[target.KeyEnv] = mat.KeyPEM
		}
		if target.File != "" {
			content := mat.Value
			if target.Type == config.TypeCertificate && mat.CertPEM != "" {
				content = mat.CertPEM
			}
			dest := filepath.Join(spec.SecretDir, filepath.Base(target.File))
			if err := writeSecretFile(dest, content); err != nil {
				return Result{}, err
			}
		}
		if target.KeyFile != "" && mat.KeyPEM != "" {
			dest := filepath.Join(spec.SecretDir, filepath.Base(target.KeyFile))
			if err := writeSecretFile(dest, mat.KeyPEM); err != nil {
				return Result{}, err
			}
		}
	}
	return res, nil
}

func SetProcessEnv(env map[string]string) {
	for k, v := range env {
		_ = os.Setenv(k, v)
	}
}

func writeSecretFile(path, value string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
