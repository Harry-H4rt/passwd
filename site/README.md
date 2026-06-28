# site — marketing & info site

Public site for passwd, built with [Astro](https://astro.build) (static, fast).
Design tokens live in `src/styles/global.css` (the shared, Proton-like light theme
that the web vault redesign will adopt too).

## Run

```bash
cd site
npm install
npm run dev       # http://localhost:4321
npm run build     # static output in dist/
npm run preview   # preview the production build
```

## Pages

- `/` — landing (hero, features, security teaser, CTA)
- `/features` — full feature list
- `/security` — zero-knowledge explainer + what the server can/can't do
- `/faq` — FAQ + Download section (web vault now; extension + desktop app to come)

## Notes

- "Open vault" / "Create free vault" link to `http://localhost:5173` (dev). Set the
  real vault URL (and `site` in `astro.config.mjs`) before deploying.
- The Download section's desktop button is a placeholder until the Tauri desktop
  app exists (see docs/ROADMAP.md).
