# YANSII

A Chrome extension (Manifest V3) that passively inspects the web pages you visit and points out potential security issues, for **authorized** security testing. It runs a set of read-only checks as you browse a target that's in your configured scope, and organizes what it finds so you can verify the real ones by hand.

YANSII does not attack a site on its own. It observes responses, headers, cookies, forms, scripts and page structure, and surfaces **indicators** and **directly-observable facts**. Confirming exploitability is your job — the tool tells you where to look, not that a bug is proven.

## How findings are labeled

Every finding carries an honest confidence tier so a pattern match is never dressed up as a confirmed bug:

- **Potential** — a passive pattern match (e.g. a parameter is reflected, a form has no CSRF token). An indicator to investigate, not proof. No severity number is shown for these.
- **Observed** — a directly-observable fact (e.g. a response is missing `Strict-Transport-Security`, a cookie lacks `HttpOnly`, `Access-Control-Allow-Origin: *`). Real at its stated severity, but its impact still depends on context.

Optional, off-by-default active verification can attempt to promote a potential indicator by reproducing it; with **Safe Mode** on (the default for external targets), YANSII stays entirely passive.

## What it does (free build)

- **Auto-scan** of pages you visit, limited to your target scope
- **Passive checks** across common classes — reflected/DOM XSS indicators, SQLi/command-injection parameter indicators, SSRF/open-redirect parameters, CSRF token presence, security headers, CORS configuration, cookie flags (`HttpOnly`/`Secure`/`SameSite`), information disclosure and secret-shaped strings, `robots.txt`/`sitemap.xml`/API/GraphQL endpoint recognition, and `postMessage` handler analysis
- **Scope enforcement** so only domains you list are scanned; common analytics/CDN domains are filtered out
- **Safe Mode** — disables all active checks; passive observation only
- **Optional active verification** of individual high/critical indicators
- **A crawler** with configurable depth and rate limiting
- **Views** — popup, side panel, full dashboard, and a DevTools panel
- **Export** findings as JSON
- **Custom request headers** (e.g. a required program identification header)
- **Local-only storage** — everything stays in your browser

## Install (developer mode)

1. Download or clone this repository
2. Open `chrome://extensions`
3. Turn on **Developer mode** (top right)
4. Click **Load unpacked** and select the extension directory
5. Pin the icon, open the popup, and set your target scope

Requires Chrome 114+ for the side panel.

## Quick start

1. Click the icon and set a target scope (e.g. `example.com`)
2. Browse the target — scanning runs automatically on in-scope pages
3. Open the side panel or dashboard to review findings
4. Treat each finding as a lead: reproduce and confirm before reporting anything

## Permissions

| Permission | Why |
|------------|-----|
| `activeTab` | Read the current tab to scan it |
| `storage` / `unlimitedStorage` | Store findings and settings locally |
| `scripting` | Inject the content script |
| `sidePanel` | The side-panel UI |
| `webRequest` | Read response headers/cookies to audit them |
| `tabs` | Associate findings with the right tab |
| `declarativeNetRequest` | Inject the custom request headers you configure |
| `alarms` | Keep the service worker alive |
| `host_permissions: <all_urls>` | Scan the in-scope sites you browse to |

## Privacy

All scan data is stored locally (`chrome.storage.local`) and never leaves your browser. YANSII has no servers, analytics, or telemetry. See [PRIVACY_POLICY.md](docs/PRIVACY_POLICY.md) for the full policy. Clear everything at any time from the dashboard.

## Authorized use only

Use YANSII **only** on applications you own or have explicit, written authorization to test. You are responsible for staying within a program's scope and rules. Do not use it for unauthorized testing, denial of service, or any illegal activity.

## Pro

A separate **Pro** tier adds AI-assisted analysis (bring-your-own key), request replay, role/access comparison, parameter discovery, a GraphQL tester, exploit-chain correlation, and report generation. Those features are not part of this free build. See [yansii.in](https://yansii.in) for details.

## Troubleshooting

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## License

See [LICENSE](LICENSE).
