#!/usr/bin/env bash
# Publish the passwd web vault and/or marketing site to Cloudflare Pages.
#
# Cloudflare retired the Git-connected Pages flow for this account, so both
# projects are published by direct upload via Wrangler (no build-on-push). This
# script bakes the production URLs into each build and uploads it, so a redeploy
# is one command instead of remembering the env vars and the wrangler paths.
#
# Prereqs: deps installed (run `npm ci` in clients/ and site/ once) and a logged
# in Wrangler (`npx wrangler login`).
#
# Usage:   ./scripts/deploy.sh [vault|site|all]     (default: all)
# Override any URL via the environment, e.g.
#   VITE_API_BASE=https://staging-api.example.com ./scripts/deploy.sh vault
#
# The URLs below are public (they ship in the built bundles), not secrets.
set -euo pipefail

API_BASE="${VITE_API_BASE:-https://passwd-api-qvyk.onrender.com}"
SITE_URL="${PUBLIC_SITE_URL:-https://passwd-site.pages.dev}"
VAULT_URL="${PUBLIC_VAULT_URL:-https://passwd-vault.pages.dev}"
GITHUB_URL="${PUBLIC_GITHUB_URL:-https://github.com/Harry-H4rt/passwd}"
RELEASES_URL="${PUBLIC_RELEASES_URL:-${GITHUB_URL}/releases/latest}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

deploy_vault() {
  echo "==> Building web vault (API: $API_BASE)"
  ( cd "$ROOT/clients" \
    && VITE_API_BASE="$API_BASE" VITE_SITE_URL="$SITE_URL" \
       npm -w @passwd/web run build \
    && npx wrangler pages deploy apps/web/dist \
         --project-name passwd-vault --branch main --commit-dirty=true )
}

deploy_site() {
  echo "==> Building marketing site (vault: $VAULT_URL)"
  ( cd "$ROOT/site" \
    && PUBLIC_SITE_URL="$SITE_URL" PUBLIC_VAULT_URL="$VAULT_URL" \
       PUBLIC_GITHUB_URL="$GITHUB_URL" PUBLIC_RELEASES_URL="$RELEASES_URL" \
       npm run build \
    && npx wrangler pages deploy dist \
         --project-name passwd-site --branch main --commit-dirty=true )
}

case "${1:-all}" in
  vault) deploy_vault ;;
  site)  deploy_site ;;
  all)   deploy_vault; deploy_site ;;
  *)     echo "usage: $0 [vault|site|all]" >&2; exit 1 ;;
esac

echo "==> Done."
