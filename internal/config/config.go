package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	EnvGatewayURL    = "AKEYLESS_GATEWAY_URL"
	EnvURL           = "AKEYLESS_URL"
	EnvAccessID      = "AKEYLESS_ACCESS_ID"
	EnvAccessKey     = "AKEYLESS_ACCESS_KEY"
	EnvAccessType    = "AKEYLESS_ACCESS_TYPE"
	EnvToken         = "AKEYLESS_TOKEN"
	EnvSpecFile      = "AKEYLESS_INJECT_SPEC"
	EnvSecretDir     = "AKEYLESS_SECRET_DIR"
	EnvRefresh       = "AKEYLESS_INJECT_REFRESH_INTERVAL"
	EnvOnChange      = "AKEYLESS_INJECT_ON_CHANGE"
	EnvRestartSignal = "AKEYLESS_INJECT_RESTART_SIGNAL"
	EnvIgnoreCache   = "AKEYLESS_IGNORE_CACHE"
)

// IgnoreCacheEnabled returns true if the target or global env requests bypassing the gateway cache.
func IgnoreCacheEnabled(t SecretTarget) bool {
	if t.IgnoreCache {
		return true
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvIgnoreCache)))
	return v == "true" || v == "1" || v == "yes"
}

type SecretType string

const (
	TypeStatic      SecretType = "static"
	TypeDynamic     SecretType = "dynamic"
	TypeRotated     SecretType = "rotated"
	TypeCertificate SecretType = "certificate"
)

type OnChangeAction string

const (
	OnChangeRestart OnChangeAction = "restart"
	OnChangeFile    OnChangeAction = "file"
)

// Spec describes secrets to inject and refresh behavior (mirrors K8s injector concepts).
type Spec struct {
	SecretDir string         `yaml:"secret_dir"`
	Refresh   RefreshConfig  `yaml:"refresh"`
	Secrets   []SecretTarget `yaml:"secrets"`
}

type RefreshConfig struct {
	Interval string         `yaml:"interval"`
	OnChange OnChangeAction `yaml:"on_change"`
}

type SecretTarget struct {
	Path   string     `yaml:"path"`
	Type   SecretType `yaml:"type"`
	Env    string     `yaml:"env"`
	KeyEnv string     `yaml:"key_env"` // certificate: private key as env
	File   string     `yaml:"file"`
	KeyFile string    `yaml:"key_file"` // certificate: private key PEM path under secret_dir
	Host   string     `yaml:"host"`   // rotated secrets
	Args   []string   `yaml:"args"`   // dynamic secrets
	Timeout int64     `yaml:"timeout"` // dynamic secrets (seconds)

	// certificate-only (get-certificate-value)
	Version        int32  `yaml:"version"`
	IgnoreCache    bool   `yaml:"ignore_cache"`
	CertIssuerName string `yaml:"cert_issuer_name"`
	IssuanceToken  string `yaml:"issuance_token"`
	DisplayID      string `yaml:"display_id"`
}

type Auth struct {
	GatewayURL string
	AccessID   string
	AccessKey  string
	AccessType string
	Token      string
	UIDToken   string // inline UID token (optional; file/env resolved in client per auth)
}

func LoadSpec(path string) (Spec, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, err
	}
	var spec Spec
	if err := yaml.Unmarshal(b, &spec); err != nil {
		return Spec{}, fmt.Errorf("parse spec: %w", err)
	}
	if err := spec.validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func (s *Spec) validate() error {
	if s.SecretDir == "" {
		s.SecretDir = "/akeyless/secrets"
	}
	if s.Refresh.Interval == "" {
		s.Refresh.Interval = "30s"
	}
	if s.Refresh.OnChange == "" {
		s.Refresh.OnChange = inferOnChange(s.Secrets)
	}
	if s.Refresh.OnChange != OnChangeRestart && s.Refresh.OnChange != OnChangeFile {
		return fmt.Errorf("refresh.on_change must be %q or %q", OnChangeRestart, OnChangeFile)
	}
	if len(s.Secrets) == 0 {
		return fmt.Errorf("spec must declare at least one secret")
	}
	for i, sec := range s.Secrets {
		if strings.TrimSpace(sec.Path) == "" {
			return fmt.Errorf("secrets[%d].path is required", i)
		}
		if sec.Type == "" {
			sec.Type = TypeStatic
			s.Secrets[i].Type = TypeStatic
		}
		switch sec.Type {
		case TypeStatic, TypeDynamic, TypeRotated, TypeCertificate:
		default:
			return fmt.Errorf("secrets[%d].type %q is invalid", i, sec.Type)
		}
		if sec.Type == TypeCertificate {
			if sec.File == "" {
				s.Secrets[i].File = "tls.crt"
			}
			if sec.KeyFile == "" {
				s.Secrets[i].KeyFile = "tls.key"
			}
			continue
		}
		if sec.Env == "" && sec.File == "" {
			base := strings.TrimPrefix(normalizePath(sec.Path), "/")
			base = strings.ReplaceAll(base, "/", "_")
			s.Secrets[i].File = base
		}
	}
	return nil
}

func inferOnChange(secrets []SecretTarget) OnChangeAction {
	for _, s := range secrets {
		if s.Env != "" {
			return OnChangeRestart
		}
	}
	return OnChangeFile
}

func (s Spec) RefreshInterval() (time.Duration, error) {
	return time.ParseDuration(strings.TrimSpace(s.Refresh.Interval))
}

func LoadAuth() Auth {
	gw := strings.TrimSpace(os.Getenv(EnvGatewayURL))
	if gw == "" {
		gw = strings.TrimSpace(os.Getenv(EnvURL))
	}
	if gw == "" {
		gw = "https://api.akeyless.io"
	}
	at := normalizeAccessType(os.Getenv(EnvAccessType))
	if at == "" {
		at = "access_key"
	}
	return Auth{
		GatewayURL: gw,
		AccessID:   strings.TrimSpace(os.Getenv(EnvAccessID)),
		AccessKey:  os.Getenv(EnvAccessKey),
		AccessType: at,
		Token:      strings.TrimSpace(os.Getenv(EnvToken)),
		UIDToken:   strings.TrimSpace(os.Getenv(EnvUIDToken)),
	}
}

func (a Auth) Validate() error {
	if a.Token != "" {
		return nil
	}
	switch a.AccessType {
	case "universal_identity":
		if _, err := ResolveUIDToken(); err != nil {
			return err
		}
		return nil
	case "access_key":
		if a.AccessID == "" {
			return fmt.Errorf("%s is required for access_key auth", EnvAccessID)
		}
		if a.AccessKey == "" {
			return fmt.Errorf("%s is required for access_key auth", EnvAccessKey)
		}
		return nil
	case "aws_iam", "azure_ad", "gcp", "jwt", "k8s":
		if a.AccessID == "" {
			return fmt.Errorf("%s is required for %s auth", EnvAccessID, a.AccessType)
		}
		return nil
	default:
		return fmt.Errorf("unsupported %s %q (use access_key, universal_identity, aws_iam, azure_ad, gcp)", EnvAccessType, a.AccessType)
	}
}

func SpecPath(flag string) (string, error) {
	p := strings.TrimSpace(flag)
	if p == "" {
		p = strings.TrimSpace(os.Getenv(EnvSpecFile))
	}
	if p == "" {
		return "", fmt.Errorf("spec file required (--spec or %s)", EnvSpecFile)
	}
	return p, nil
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
