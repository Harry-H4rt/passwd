#!/usr/bin/env bash
# Build the web vault for the mobile app and sync it into the native projects.
#
# The mobile app (clients/apps/mobile) is a Capacitor wrapper: it runs the built
# web vault in a native WebView. This script builds apps/web with the production
# API base, copies the output into apps/mobile/www, then runs `cap sync` so the
# native iOS/Android projects pick up the new web assets and any plugins.
#
# Prereqs: `npm install` has been run, and the native platforms have been added
# once with `npm -w @passwd/mobile run add:android` / `add:ios` (iOS needs a Mac
# with Xcode; Android needs Android Studio's SDK).
#
# Usage:   ./scripts/mobile.sh [sync|android|ios]     (default: sync)
# Override URLs via env, e.g. VITE_API_BASE=https://staging-api ... ./scripts/mobile.sh
set -euo pipefail

API_BASE="${VITE_API_BASE:-https://passwd-api-qvyk.onrender.com}"
SITE_URL="${VITE_SITE_URL:-https://passwd-site.pages.dev}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT/clients"
echo "==> Building web vault for mobile (API: $API_BASE)"
VITE_API_BASE="$API_BASE" VITE_SITE_URL="$SITE_URL" npm -w @passwd/web run build
rm -rf apps/mobile/www
cp -r apps/web/dist apps/mobile/www

cd apps/mobile
case "${1:-sync}" in
  sync)    npx cap sync ;;
  android) npx cap sync android && npx cap open android ;;
  ios)     npx cap sync ios && npx cap open ios ;;
  *)       echo "usage: $0 [sync|android|ios]" >&2; exit 1 ;;
esac
echo "==> Done."
