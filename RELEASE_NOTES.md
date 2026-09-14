# YANSII Free v2.2.0

A Chrome extension (Manifest V3) that passively inspects the web pages you visit during **authorized** security testing and points out potential issues to verify by hand. It does not attack a site on its own — it observes responses, headers, cookies, forms and scripts, and organizes what it finds so you can confirm the real ones.

## How findings are labeled

- **Potential** — a passive pattern match (an indicator to investigate, not proof). No severity number is shown.
- **Observed** — a directly-observable fact (a missing security header, a cookie without `HttpOnly`, `Access-Control-Allow-Origin: *`). Real at its stated severity; impact still depends on context.

Optional, off-by-default active verification can try to reproduce an indicator. **Safe Mode** (the default for external targets) keeps YANSII fully passive.

## In this build

- Scope-limited auto-scan of the pages you browse
- Passive checks: security headers, cookie flags, CORS, reflected/DOM XSS indicators, injection-parameter indicators, SSRF/open-redirect parameters, CSRF token presence, information disclosure and secret-shaped strings, `robots.txt`/`sitemap.xml`/API/GraphQL endpoint recognition, and `postMessage` handler analysis
- A crawler with configurable depth and rate limiting
- Popup, side panel, dashboard, and DevTools views
- JSON export; custom request headers; Safe Mode
- Local-only storage — nothing leaves your browser (no servers, analytics, or telemetry)

## Install (developer mode)

1. Download `yansii-v2.2.0-free.zip` and unzip it (or clone this repository)
2. Open `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** and select the extension folder
5. Open the popup, set your target scope, and browse

Requires Chrome 114+ for the side panel.

## Authorized use only

Use YANSII **only** on applications you own or have explicit, written authorization to test. Findings are indicators and observations — reproduce and confirm them before reporting anything, and stay within each program's scope and rules.

More at [yansii.in](https://yansii.in).

---
SHA-256 (`yansii-v2.2.0-free.zip`): `01ccbe06579a3e0eea431a221ddebdca28b3e92dc1f4e9fcd69d1419038cfdfa`
