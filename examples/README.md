# Examples

| File | Description |
|------|-------------|
| [inject.yaml](./inject.yaml) | Static secret — env + file |
| [inject-file-refresh.yaml](./inject-file-refresh.yaml) | File-only refresh (`on_change: file`) |
| [inject-certificate.yaml](./inject-certificate.yaml) | TLS cert + key files |
| [docker-compose.yml](./docker-compose.yml) | Supervisor pattern with `.env` |

```bash
cp .env.example .env
# Edit .env with your Access ID, Access Key, and Gateway URL (never commit .env)
docker compose up --build
```

Update `inject.yaml` paths to match secrets in your Akeyless tenant before running.
