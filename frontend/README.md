# Sub2API Frontend

This Vue 3 and Vite application is the single frontend source for the Cloudflare Pages deployment.

## Architecture contract

```text
Browser
  ├─ static assets and SPA navigation -> Cloudflare Pages
  └─ same-origin API and gateway paths -> Cloudflare Worker -> D1
```

The frontend must not depend on the legacy Go server for HTML rendering or runtime configuration injection. Production API requests default to the relative `/api/v1` base so authentication cookies, OAuth callbacks, downloads, SSE, and WebSocket traffic can remain on the same public origin.

`VITE_API_BASE_URL` is an optional build-time override for controlled development and testing. Production Pages builds should normally leave it unset.

## Local development

```powershell
corepack pnpm@9.15.9 install
corepack pnpm@9.15.9 run dev
```

`VITE_DEV_PROXY_TARGET` controls the local Vite proxy target only. During migration it may point to the legacy backend or the local Worker, but it is not a production origin setting.

## Production build and Pages verification

```powershell
corepack pnpm@9.15.9 run build
Set-Location ../cloudflare
npm run verify:pages
```

Cloudflare Pages deploys `dist` using `wrangler.toml`. Files under `public` are copied into the artifact, including the SPA fallback and response headers.

Pages Functions and `_worker.js` are intentionally excluded. Backend logic belongs in `cloudflare/worker`.
