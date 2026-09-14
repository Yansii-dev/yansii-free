# YANSII — Privacy Policy

**Last updated:** 2026-09-06  
**Extension:** YANSII — Your Adaptive Next-Step Intelligent Inspector  
**Developer contact:** hello@yansii.in

---

## 1. What Data Is Collected

YANSII collects the following data during authorized security testing:

- **Page URLs visited** — stored locally for organizing scan results by domain
- **HTTP response headers** — stored locally for security header audit (e.g., missing Content-Security-Policy, insecure cookies)
- **Cookie names and attributes** — stored locally for security analysis (HttpOnly, Secure, SameSite flags). Cookie *values* are used locally for role comparison only and are never transmitted externally.
- **Form field names** — stored locally for vulnerability scanning (e.g., detecting missing CSRF tokens)
- **JavaScript file URLs and content excerpts** — stored locally; if AI features are enabled, page context (URL, parameter names, technology detected, endpoint patterns) is sent to the user's configured AI provider
- **API request/response metadata** — stored locally for replay and diff analysis
- **Pattern memory** — learned vulnerability patterns stored locally for improving future scan accuracy
- **postMessage handler source code** — captured from the page DOM, stored locally for security analysis

## 2. How Data Is Used

- **ALL data is used exclusively for security testing** of web applications the user is authorized to test
- No data is used for advertising, analytics, user profiling, or tracking
- No data is sold or shared with third parties
- AI analysis: when enabled by the user, page context is sent to the user's own AI provider for generating security testing suggestions

## 3. Data Storage

- **All data is stored locally** on the user's device via `chrome.storage.local`
- No external database or server is used
- No cloud sync — YANSII uses `chrome.storage.local`, not `chrome.storage.sync` (sync is used only for the enabled/scope toggle, which contains no sensitive data)
- Data is clearable at any time via the Dashboard's "Clear All Data" function
- Pattern memory can be cleared separately

## 4. Data Transmission

Data is transmitted externally **only** under all of the following conditions:

1. The user has **explicitly enabled** AI features (off by default)
2. The user has **provided their own API key** (BYOK model)
3. Data is sent **only** to the user's configured AI API endpoint:
   - Anthropic (api.anthropic.com)
   - OpenAI (api.openai.com)
   - Groq (api.groq.com)
   - OpenRouter (openrouter.ai)
4. All transmissions use **HTTPS**
5. The user controls which provider receives their data

**What is sent to the AI provider:**
- Page URL
- Form field names (not values)
- URL parameter names
- Cookie names (NOT cookie values)
- Detected technology stack
- JavaScript endpoint patterns
- HTTP response header names

**What is NEVER sent externally:**
- Cookie values
- localStorage/sessionStorage values
- Full page HTML
- Response bodies
- API keys found during scanning
- The user's AI API key (sent only as an authentication header to the chosen provider)

## 5. Data Retention

- **Local data** is retained until the user explicitly clears it via the Dashboard
- **No data is retained by YANSII** outside of the user's browser
- AI provider data retention is governed by the user's agreement with their chosen AI provider
- Uninstalling the extension removes all locally stored data

## 6. Third-Party Access

**NONE.** YANSII has no servers, no analytics, no telemetry, no tracking, and no crash reporting. The extension is entirely client-side. The only external communication is to the user's own AI provider when they explicitly enable it.

## 7. User Controls

- **AI features are off by default** — the user must opt in and provide their own API key
- **All scan data** is clearable via Dashboard → Clear All Data
- **Pattern memory** is clearable separately via Dashboard → Clear Patterns
- **Custom headers** can be disabled at any time via the popup toggle
- **Extension** can be fully disabled via the master toggle in the popup
- **Target scope** can be set to restrict scanning to specific domains
- **Safe mode** disables all active verification (passive scanning only)

## 8. AI Safety Compliance

YANSII uses AI APIs within their standard terms of service for security analysis. It does not circumvent, bypass, or disable any AI safety measures. All AI prompts are standard security analysis requests asking for testing suggestions, not exploit generation.

## 9. Cookies and Tracking

YANSII does not set any cookies, does not use any tracking pixels, and does not collect any analytics. The extension accesses page cookies solely for security analysis (detecting insecure cookie attributes) and role comparison (comparing access control between authenticated states).

## 10. Children's Privacy

YANSII is a professional security testing tool intended for authorized security researchers and penetration testers. It is not directed at children under 13.

## 11. Changes to This Policy

Any changes to this privacy policy will be noted in the extension's changelog and reflected in an updated version number.

## 12. Contact

For privacy inquiries, contact: hello@yansii.in
