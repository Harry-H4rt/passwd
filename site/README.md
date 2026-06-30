# site

The public marketing and information site for passwd, built with
[Astro](https://astro.build) (static and fast). The shared design tokens live in
`src/styles/global.css`; the web vault mirrors the same design language.

## Develop

```bash
cd site
npm install
npm run dev       # http://localhost:4321
npm run build     # static output in dist/
npm run preview   # preview the production build
```

## Pages

- `/` — landing page (hero, features, security overview, call to action)
- `/features` — full feature list
- `/security` — zero-knowledge explainer and what the server can and cannot do
- `/faq` — frequently asked questions and the download section

## Configuration

Public URLs are set at build time via `PUBLIC_*` environment variables (see
`.env.example`):

- `PUBLIC_VAULT_URL` — where "Open vault" links (defaults to `http://localhost:5173`).
- `PUBLIC_GITHUB_URL` — repository and "build from source" links.
- `PUBLIC_RELEASES_URL` — the desktop app **Download** button (defaults to
  `$PUBLIC_GITHUB_URL/releases/latest`).

See [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) for production deployment.
