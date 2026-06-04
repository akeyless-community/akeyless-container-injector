# Security

## Before you commit or publish

- Do **not** commit `.env`, API keys, UID token files, PEM material, or real secret paths with live values in docs.
- Use [`.env.example`](./.env.example) and environment variables / Docker secrets at runtime only.
- Run `make check-secrets` locally before pushing (see [Makefile](./Makefile)).

## Runtime

- Injected files are written with mode `0600` under `secret_dir` (default `0700`).
- The injector does not log secret values; only paths and process events are logged.
- Prefer **file injection** over environment variables when possible.
- For Universal Identity, mount the UID token file read-only and use `uid-auto-rotate` on the host.

## Reporting issues

Report vulnerabilities through your organization's standard channel for Akeyless Community projects.
