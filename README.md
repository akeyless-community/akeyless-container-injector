# Akeyless Container Injector

Inject secrets from [Akeyless](https://www.akeyless.io/) into **Docker** and **Podman** containers at runtime — similar to the [Kubernetes Secrets Injector](https://docs.akeyless.io/docs/akeyless-kubernetes-secrets-injector), without a mutating webhook.

Your application stays **Akeyless-unaware**: declare paths in a YAML spec; the agent fetches values and exposes them as files and/or environment variables.

## Features

| Capability | Support |
|------------|---------|
| Static secrets | Yes |
| Dynamic secrets | Yes (`timeout`, `args`) |
| Rotated secrets | Yes (`host` or `AKEYLESS_ROTATED_SECRET_HOST`) |
| Certificates | Yes (cert + key PEM files) |
| Auth: API key | Yes |
| Auth: Universal Identity | Yes (token file or env) |
| Auth: AWS / Azure / GCP | Yes |
| Refresh + file update | Yes (`on_change: file`) |
| Refresh + process restart | Yes (`on_change: restart`) |

## Quick start

### 1. Build

```bash
git clone https://github.com/akeyless-community/akeyless-container-injector.git
cd akeyless-container-injector
make build
```

### 2. Create a spec (`inject.yaml`)

```yaml
secret_dir: /akeyless/secrets

refresh:
  interval: 30s
  on_change: restart   # or "file"

secrets:
  - path: /my-app/db-password
    type: static
    env: DB_PASSWORD
    file: db-password
```

### 3. Set credentials (never commit these)

```bash
export AKEYLESS_ACCESS_ID="your-access-id"
export AKEYLESS_ACCESS_KEY="your-access-key"
export AKEYLESS_GATEWAY_URL="https://your-gateway.example.com"
```

For self-hosted gateways, use the **base URL** (e.g. `https://gw.example.com:8081`) — not `/api/v1` unless your gateway requires it.

See [`.env.example`](./.env.example) for a template.

### 4. Run your app

**One-shot fetch (init-container style):**

```bash
akeyless-inject init --spec inject.yaml
./your-app
```

**Supervisor with automatic restart on secret change:**

```bash
akeyless-inject run --spec inject.yaml -- ./your-app
```

## Commands

| Command | Purpose |
|---------|---------|
| `akeyless-inject init --spec FILE` | Fetch secrets once; write files + set env in current process |
| `akeyless-inject run --spec FILE -- CMD` | Inject, run `CMD`, poll for changes, restart on change |
| `akeyless-inject watch --spec FILE` | Poll and update files (`on_change: file`) |
| `akeyless-inject watch --spec FILE --restart-cmd "..."` | Poll and run a shell command to restart a sibling container |

## Inject spec reference

| Field | Description |
|-------|-------------|
| `secret_dir` | Directory for injected files (default `/akeyless/secrets`) |
| `refresh.interval` | Poll interval, e.g. `30s`, `10s` |
| `refresh.on_change` | `restart` or `file` |
| `secrets[].path` | Akeyless item path |
| `secrets[].type` | `static`, `dynamic`, `rotated`, `certificate` |
| `secrets[].env` | Environment variable name |
| `secrets[].file` | Filename under `secret_dir` |
| `secrets[].key_file` | Private key file (certificate) |
| `secrets[].key_env` | Private key env var (certificate) |
| `secrets[].host` | Rotated secret target host |
| `secrets[].args` | Dynamic secret CLI args |
| `secrets[].timeout` | Dynamic secret timeout (seconds) |
| `secrets[].ignore_cache` | Bypass gateway cache for this item |
| `secrets[].version` | Certificate version |

**Defaults:** `on_change` is `restart` if any secret uses `env`, otherwise `file`. Certificate type defaults to `tls.crt` + `tls.key`.

### Examples by type

<details>
<summary>Dynamic secret</summary>

```yaml
secrets:
  - path: /dyn/postgres
    type: dynamic
    timeout: 30
    args: ["--arg=value"]
    file: db-creds.json
```

</details>

<details>
<summary>Rotated secret</summary>

```yaml
secrets:
  - path: /rotated/mysql
    type: rotated
    host: db.internal
    file: mysql.json
```

</details>

<details>
<summary>Certificate</summary>

```yaml
secrets:
  - path: /pki/my-tls-cert
    type: certificate
    file: tls.crt
    key_file: tls.key
    ignore_cache: true
```

</details>

> **Dynamic secrets:** each poll may return new credentials. With `on_change: restart`, that can cause frequent restarts — use `file` mode, a longer interval, or a dedicated spec for dynamic items only.

## Authentication

| Method | Environment |
|--------|-------------|
| API key (default) | `AKEYLESS_ACCESS_ID`, `AKEYLESS_ACCESS_KEY` |
| Universal Identity | `AKEYLESS_ACCESS_TYPE=universal_identity`, `AKEYLESS_UID_TOKEN_FILE` or `AKEYLESS_UID_TOKEN` |
| Pre-authenticated | `AKEYLESS_TOKEN` |
| Cloud | `AKEYLESS_ACCESS_TYPE=aws_iam` / `azure_ad` / `gcp` + `AKEYLESS_ACCESS_ID` |

**UID token file defaults** (same as `akeyless uid-auto-rotate`):

- Linux/macOS: `~/.akeyless/uid_rotator/uid-token`
- Windows: `%PROGRAMDATA%\akeyless\uid_rotator\uid-token`

The token file is **re-read on every auth** so rotations are picked up automatically.

Set `AKEYLESS_ACCESS_TYPE=uid` as an alias for `universal_identity`.

## Docker Compose

```bash
cd examples
cp .env.example .env   # fill in credentials — do not commit .env
docker compose up --build
```

See [examples/docker-compose.yml](./examples/docker-compose.yml) for supervisor and init/sidecar patterns.

## Podman

Same image and commands work with `podman run` / `podman-compose`. Mount the UID token file read-only when using Universal Identity.

## Automation suggestions

| Automation | How |
|------------|-----|
| **CI tests** | GitHub Actions runs `make check-secrets`, `go test`, and build on every PR |
| **Pre-push secret check** | `make check-secrets` — local grep for common credential patterns |
| **Image publish** | `make docker` then push to your registry; pin by digest in production |
| **UID on VMs** | Install `akeyless uid-auto-rotate` on the host; mount token into containers |
| **Compose in prod** | Use Docker/Kubernetes secrets for `AKEYLESS_ACCESS_KEY` or UID file mount — not `.env` in git |
| **Restart sibling container** | `watch --restart-cmd "docker restart myapp"` with controlled socket access |
| **GitOps** | Store only `inject.yaml` (paths, no values) in git; credentials from runtime env |

## Development

```bash
make test          # unit tests
make check-secrets # scan for accidental credentials before publish
make docker        # build container image
```

## Security

Do not commit credentials, `.env`, or token files. See [SECURITY.md](./SECURITY.md).

## Limitations vs Kubernetes injector

- No mutating webhook — set `entrypoint` to `akeyless-inject` explicitly.
- `watch --restart-cmd` may need Docker/Podman socket access.
- Certificate issuance (PKI `get-pki-certificate`) is not supported — only stored certificate items via `get-certificate-value`.

## License

MIT — see [LICENSE](./LICENSE).
