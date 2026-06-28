/// <reference types="vite/client" />

interface ImportMetaEnv {
  // API origin for the backend. Empty (default) means same-origin: the dev proxy
  // in dev, a co-hosted reverse proxy in prod. Set to e.g. https://api.example.com
  // when the SPA and API live on different origins (add that SPA origin to the
  // backend's PASSWD_ALLOWED_ORIGINS).
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
