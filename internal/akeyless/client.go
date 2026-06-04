package akeyless

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cloudid "github.com/akeylesslabs/akeyless-go-cloud-id"
	akeyless "github.com/akeylesslabs/akeyless-go/v5"

	"github.com/akeyless-community/akeyless-container-injector/internal/config"
)

type Client struct {
	api   *akeyless.V2ApiService
	token string
	auth  config.Auth
}

type Material struct {
	Path        string
	Value       string
	Fingerprint string
	CertPEM     string
	KeyPEM      string
}

func NewClient(auth config.Auth) (*Client, error) {
	cfg := akeyless.NewConfiguration()
	cfg.Servers = akeyless.ServerConfigurations{{URL: strings.TrimSuffix(auth.GatewayURL, "/")}}
	return &Client{
		api:  akeyless.NewAPIClient(cfg).V2Api,
		auth: auth,
	}, nil
}

func (c *Client) Authenticate(ctx context.Context) error {
	if c.auth.Token != "" {
		c.token = c.auth.Token
		return nil
	}
	body := akeyless.NewAuth()
	switch c.auth.AccessType {
	case "universal_identity":
		uidToken, err := config.ResolveUIDToken()
		if err != nil {
			return err
		}
		body.SetAccessType("universal_identity")
		body.SetUidToken(uidToken)
	case "access_key":
		body.SetAccessId(c.auth.AccessID)
		body.SetAccessType("access_key")
		body.SetAccessKey(c.auth.AccessKey)
	case "aws_iam":
		body.SetAccessId(c.auth.AccessID)
		cid, err := cloudid.GetCloudId()
		if err != nil {
			return fmt.Errorf("aws cloud id: %w", err)
		}
		body.SetAccessType("aws_iam")
		body.SetCloudId(cid)
	case "azure_ad":
		body.SetAccessId(c.auth.AccessID)
		cid, err := cloudid.GetCloudId()
		if err != nil {
			return fmt.Errorf("azure cloud id: %w", err)
		}
		body.SetAccessType("azure_ad")
		body.SetCloudId(cid)
	case "gcp":
		body.SetAccessId(c.auth.AccessID)
		cid, err := cloudid.GetCloudId()
		if err != nil {
			return fmt.Errorf("gcp cloud id: %w", err)
		}
		body.SetAccessType("gcp")
		body.SetCloudId(cid)
	default:
		return fmt.Errorf("auth type %q is not implemented yet", c.auth.AccessType)
	}
	out, _, err := c.api.Auth(ctx).Body(*body).Execute()
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	if out == nil || out.GetToken() == "" {
		return fmt.Errorf("auth returned empty token")
	}
	c.token = out.GetToken()
	return nil
}

func (c *Client) Fetch(ctx context.Context, target config.SecretTarget) (Material, error) {
	path := normalizePath(target.Path)
	var (
		value string
		err   error
	)
	switch target.Type {
	case config.TypeStatic:
		value, err = c.static(ctx, path, target)
	case config.TypeDynamic:
		value, err = c.dynamic(ctx, path, target)
	case config.TypeRotated:
		value, err = c.rotated(ctx, path, target)
	case config.TypeCertificate:
		return c.certificate(ctx, path, target)
	default:
		return Material{}, fmt.Errorf("unknown secret type %q", target.Type)
	}
	if err != nil {
		return Material{}, err
	}
	return Material{
		Path:        path,
		Value:       value,
		Fingerprint: fingerprint(value),
	}, nil
}

func (c *Client) certificate(ctx context.Context, path string, t config.SecretTarget) (Material, error) {
	body := akeyless.NewGetCertificateValue()
	body.SetToken(c.token)
	body.SetName(path)
	if t.Version > 0 {
		body.SetVersion(t.Version)
	}
	if config.IgnoreCacheEnabled(t) {
		body.SetIgnoreCache("true")
	}
	if iss := strings.TrimSpace(t.CertIssuerName); iss != "" {
		body.SetCertIssuerName(iss)
	}
	if tok := strings.TrimSpace(t.IssuanceToken); tok != "" {
		body.SetIssuanceToken(tok)
	}
	if id := strings.TrimSpace(t.DisplayID); id != "" {
		body.SetDisplayId(id)
	}
	out, _, err := c.api.GetCertificateValue(ctx).Body(*body).Execute()
	if err != nil {
		return Material{}, err
	}
	if out == nil {
		return Material{}, fmt.Errorf("empty certificate response for %q", path)
	}
	certPEM := strings.TrimSpace(out.GetCertificatePem())
	keyPEM := strings.TrimSpace(out.GetPrivateKeyPem())
	if certPEM == "" && keyPEM == "" {
		return Material{}, fmt.Errorf("certificate %q returned no PEM data", path)
	}
	fp := fingerprint(certPEM + "\n" + keyPEM)
	return Material{
		Path:        path,
		Value:       certPEM,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: fp,
	}, nil
}

func (c *Client) static(ctx context.Context, path string, t config.SecretTarget) (string, error) {
	req := akeyless.NewGetSecretValue([]string{path})
	req.SetToken(c.token)
	if config.IgnoreCacheEnabled(t) {
		req.SetIgnoreCache("true")
	}
	resp, _, err := c.api.GetSecretValue(ctx).Body(*req).Execute()
	if err != nil {
		return "", err
	}
	if v, ok := resp[path]; ok {
		return stringify(v)
	}
	for _, v := range resp {
		s, err := stringify(v)
		if err == nil && strings.TrimSpace(s) != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("no value for %q", path)
}

func (c *Client) dynamic(ctx context.Context, path string, t config.SecretTarget) (string, error) {
	body := akeyless.NewGetDynamicSecretValue(path)
	body.SetToken(c.token)
	if t.Timeout > 0 {
		body.SetTimeout(t.Timeout)
	}
	if len(t.Args) > 0 {
		body.SetArgs(t.Args)
	}
	resp, _, err := c.api.GetDynamicSecretValue(ctx).Body(*body).Execute()
	if err != nil {
		return "", err
	}
	return mapJSON(resp)
}

func (c *Client) rotated(ctx context.Context, path string, t config.SecretTarget) (string, error) {
	body := akeyless.NewGetRotatedSecretValue(path)
	body.SetToken(c.token)
	host := strings.TrimSpace(t.Host)
	if host == "" {
		host = strings.TrimSpace(os.Getenv("AKEYLESS_ROTATED_SECRET_HOST"))
	}
	if host != "" {
		body.SetHost(host)
	}
	resp, _, err := c.api.GetRotatedSecretValue(ctx).Body(*body).Execute()
	if err != nil {
		return "", err
	}
	return mapJSON(resp)
}

func stringify(v interface{}) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case nil:
		return "", fmt.Errorf("nil value")
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

func mapJSON(resp map[string]interface{}) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("empty API response")
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}
