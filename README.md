# LinkUnlock Inspector

A small Node.js web app that inspects publicly visible SpeedyLinks redirects and scans returned HTML for exposed links.

## Deploy on Render

1. Sign in to Render and choose **New → Web Service**.
2. Connect this GitHub repository.
3. Render detects `render.yaml`; use the included settings.
4. Deploy and open the generated service URL.

## Local run

```bash
npm install
npm start
```

Open http://localhost:3000.

## Scope and safety

- Fetches only HTTPS URLs hosted on `speedy-links.com` or `www.speedy-links.com`.
- Does not follow redirects, so external destinations are displayed rather than fetched.
- Scans HTML returned by the public page for visible links.
- Does not execute page JavaScript, complete surveys, install apps, forge unlock tokens, bypass access controls, or reveal server-side gated destinations.
- Treat any discovered URL as untrusted and only open it if you recognize and trust the source.
