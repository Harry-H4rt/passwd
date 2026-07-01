import { defineConfig } from "astro/config";

// Canonical site URL (used for SEO/canonical links). Set PUBLIC_SITE_URL at build
// time to your real domain, or your Cloudflare Pages URL for now. Falls back to a
// placeholder so local dev/builds still work.
export default defineConfig({
  site: process.env.PUBLIC_SITE_URL ?? "https://passwd-site.pages.dev",
});
