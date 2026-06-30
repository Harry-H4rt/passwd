// Public site URLs, overridable at build time via PUBLIC_* env vars (see
// site/.env.example). Defaults point at local dev.
const env = import.meta.env as Record<string, string | undefined>;

export const VAULT_URL = env.PUBLIC_VAULT_URL ?? "http://localhost:5173";
export const GITHUB_URL = env.PUBLIC_GITHUB_URL ?? "https://github.com/Harry-H4rt/passwd";

// Where the desktop app's "Download" button points. Defaults to the repo's
// latest GitHub release (Linux AppImage/.deb today; signed mac/Windows later).
export const RELEASES_URL = env.PUBLIC_RELEASES_URL ?? `${GITHUB_URL}/releases/latest`;
