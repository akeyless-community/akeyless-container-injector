#!/usr/bin/env bash
# Pre-publish scan for accidental credentials in tracked files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Docs and templates use placeholder values — scan source and config only.
EXCLUDE=(
  ':!scripts/check-secrets.sh'
  ':!README.md'
  ':!SECURITY.md'
  ':!LICENSE'
  ':!examples/README.md'
  ':!*.example'
  ':!.env.example'
)

patterns=(
  'p-[a-z0-9]{10,}'
  'AKIA[0-9A-Z]{16}'
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
  'AKEYLESS_ACCESS_KEY=[^[:space:]]{20,}'
  'access_key=['\''\"][^'\''\"]{20,}'
)

found=0
for pat in "${patterns[@]}"; do
  if git grep -nE "$pat" -- . "${EXCLUDE[@]}" 2>/dev/null; then
    found=1
  fi
done

if [[ "$found" -ne 0 ]]; then
  echo "check-secrets: possible credential material found — review before publish" >&2
  exit 1
fi

echo "check-secrets: OK"
