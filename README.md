# GlitchProtect AccessGate

This repo contains a standalone AccessGate module and Cloudflare Pages functions for ID issue/session/check/block/unblock.

## Run locally

1. Install Wrangler: `npm install -g wrangler`
2. Run: `wrangler pages dev public`
3. Open the local URL.

## Endpoints

- `POST /access/issue`
- `POST /access/session`
- `POST /access/check`
- `POST /access/block`
- `POST /access/unblock`
- `POST /access/is-admin`

## AccessGate client

Load `/libs/SECURITY/AccessGate.js` from any page and configure `window.ACCESS_GATE_CONFIG` as needed.

