# YANSII — Troubleshooting

## Service Worker Issues

### Service worker crashes or goes inactive
- The keepalive alarm runs at 24-second intervals to prevent inactivity shutdown
- Check `chrome://extensions` for error logs on the extension card
- Click "Reload" on the extension card to restart the service worker
- If crashes persist, check for very large `G.findings` objects (memory trimming caps at 500/domain)

### Extension not responding to messages
- Service worker may have restarted — stored state loads from `chrome.storage.local` on restart
- In-memory state (`G` object) resets on restart — `scheduleFlush()` persists with 3-second debounce

## Findings Issues

### Too many cookie findings
- Cookie findings are deduplicated per cookie name + domain — the same cookie seen on many URLs is one finding, not one per page
- Only session/auth cookies missing `HttpOnly` are flagged; analytics/tracking cookies (`_ga`, `_fbp`, `hubspotutk`, `__hstc`, …) are skipped
- If still noisy, check whether the cookie name matches the tracking filter

### Findings from irrelevant domains
- 34 noise domains are filtered (Google Analytics, DoubleClick, Sentry, HubSpot, etc.)
- Set target scope in popup to restrict scanning to specific domains
- `isNoiseDomain()` checks all subdomains against the filter

### Findings not appearing in dashboard
- Dashboard auto-refreshes every 10 seconds
- Only shows findings for in-scope domains
- `scheduleFlush()` has a 3-second debounce — wait for storage write to complete
- Check the browser console for errors on the dashboard page

### Duplicate findings
- Findings are deduplicated by type, category, and their specific location (a form action, a page URL, or the domain for domain-wide facts like missing headers)
- Header findings attribute per route; cookie findings per cookie name + domain
- If duplicates appear, the finding's location may differ between the two occurrences

## Scanner Issues

### Crawler returns 0 pages
- Auth walls block crawling — configure auth cookies or custom headers before crawling
- Check crawl scope setting (subdomain vs root domain vs custom regex)
- Crawler status polling works via `GET_CRAWL_STATUS` message
- SPA detection may incorrectly identify catch-all routes — check `baselineHash`

### postMessage handlers not captured
- `injected.js` must run at `document_start` in MAIN world
- Handlers registered before `injected.js` loads won't be captured (rare)
- Bridge script (`bridge.js`) relays events from MAIN to ISOLATED world

## Performance Issues

### High memory usage
- Memory trimming caps: 500 findings/domain, 300 requests/domain
- Auto-trim triggers at 5000 total findings (reduces to 200/domain)
- Use "Clear All" button in dashboard to reset
- Close unused tabs to reduce content script instances

### Slow scanning
- Crawler rate limiting: configurable speed (300ms to 3000ms between requests)
- AI analysis rate limit: 10 seconds between calls
- Large pages with many scripts slow down `captureJSFiles()`

## UI Issues

### Side panel won't open
- Chrome 114+ is required for the side panel API
- Right-click the extension icon and select "Open side panel" as an alternative
- If using an older Chrome version, use the dashboard instead

### DevTools panel empty
- DevTools must be opened while on a tab that has been scanned
- Close and reopen DevTools to trigger a data refresh
- Verify the extension is enabled and the page is in scope

### Custom headers not injecting
- The "Send custom headers" toggle must be ON in the popup
- Headers must be in `Name: Value` format, one per line
- Example:
  ```
  Authorization: Bearer eyJhbGci...
  X-Custom-Token: abc123
  ```
- Use Import/Export JSON buttons to verify configuration

## Extension Conflicts

- Other security extensions or ad blockers that hook `fetch`, `XMLHttpRequest`, or `addEventListener` can interfere with YANSII's MAIN world hooks
- Temporarily disable other security-related extensions while using YANSII
- Proxy extensions that modify network requests are common conflict sources

## Debug Mode

Enable detailed logging by setting `DEBUG = true`:

| File | Line | Variable |
|------|------|----------|
| `background.js` | 9 | `let DEBUG = false;` |
| `content.js` | 8 | `const DEBUG = false;` |
| `dashboard.js` | 11 | `let DEBUG = false;` |

All logging is gated behind the DEBUG flag — no console output in production mode.

## Resetting State

To fully reset the extension:
1. Open dashboard > click "Clear All"
2. Or: `chrome.storage.local.clear()` in service worker console
3. Reload the extension from `chrome://extensions`
