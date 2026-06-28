// Public site URLs, overridable at build time via PUBLIC_* env vars (see
// site/.env.example). Defaults point at local dev.
const env = import.meta.env as Record<string, string | undefined>;

export const VAULT_URL = env.PUBLIC_VAULT_URL ?? "http://localhost:5173";
export const GITHUB_URL = env.PUBLIC_GITHUB_URL ?? "https://github.com/Harry-H4rt/passwd";
