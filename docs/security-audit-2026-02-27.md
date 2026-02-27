# Security Audit — reNgine-ng
**Date:** 2026-02-27
**Branch:** `claude/security-audit-review-A4Av3`
**Perspectives:** Security Director (customer) + Senior Developer (internal reviewer)

---

## Findings Summary

### Critical / High
| # | Finding | File | Severity |
|---|---------|------|----------|
| A | `ALLOWED_HOSTS = ['*']` — Host Header Injection | `settings.py:55` | High |
| B | `WEBSOCKET_ACCEPT_ALL = True` — dev flag in production | `settings.py:389` | High |
| C | No `DEFAULT_PERMISSION_CLASSES` in DRF config — single point of failure | `settings.py:129` | Critical |
| D | Swagger docs fully public (`AllowAny`) — full API roadmap for attackers | `urls.py:18` | High |
| E | Missing Django security headers (HSTS, secure cookies, content-type sniff) | `settings.py` | High |
| F | `CVEDetails` — user `cve_id` concatenated into outbound URL, no validation | `api/views.py:985` | High |
| G | `BrowsableAPIRenderer` active in production — DRF web UI exposed | `settings.py:132` | Medium |
| H | No explicit `permission_classes` on 50+ `APIView` subclasses | `api/views.py` | High |
| I | `run_command(f'touch {path}')` — unsafe shell command pattern | `api/views.py:1708+` | Medium |
| J | `shell=True` in 15 task locations with domain-origin values in cmd strings | `tasks/*.py` | Critical |

### Also Identified (not in this week's scope)
- PostgreSQL SSL connection commented out
- API keys (OpenAI, Netlas, theHarvester) stored unencrypted in DB
- Default credentials shipped in `.env-dist`
- Django 3.2 EOL; `langchain 0.1.0`, `openai 0.28.0`, `weasyprint 53.3` outdated
- Redis has no password by default
- `GetFileContents` serves tool API key configs to any authenticated user (all roles)

---

## This Week's Action Items

### Item 1 — Add `DEFAULT_PERMISSION_CLASSES` to DRF config
**File:** `web/reNgine/settings.py`
Add `DEFAULT_PERMISSION_CLASSES = ['rest_framework.permissions.IsAuthenticated']` to `REST_FRAMEWORK` dict so all DRF views require authentication by default, even if a future config drift removes the `LoginRequiredMiddleware`.

### Item 2 — Require authentication on Swagger docs
**File:** `web/reNgine/urls.py`
Change `schema_view` from `public=True` + `AllowAny` to `public=False` + `IsAuthenticated`. Attackers should not be able to enumerate all API endpoints, parameters, and models without logging in.

### Item 3 — Fix `ALLOWED_HOSTS` to use env var
**File:** `web/reNgine/settings.py`
Replace hardcoded `['*']` with `[env('DOMAIN_NAME', default='localhost')]`. Prevents HTTP Host Header Injection (password reset poisoning, cache poisoning, SSRF via redirect).

### Item 4 — Remove `WEBSOCKET_ACCEPT_ALL = True` from production settings
**File:** `web/reNgine/settings.py`
The comment in code explicitly says "change in production." Remove the setting or gate it on `DEBUG`. WebSocket connections should go through Django Channels' standard auth.

### Item 5 — Add missing Django security settings
**File:** `web/reNgine/settings.py`
Add:
- `SESSION_COOKIE_SECURE = True` — cookies only over HTTPS
- `CSRF_COOKIE_SECURE = True` — CSRF token only over HTTPS
- `SECURE_CONTENT_TYPE_NOSNIFF = True` — prevent MIME sniffing
- `SECURE_BROWSER_XSS_FILTER = True` — legacy XSS filter header
- `SECURE_HSTS_SECONDS = 31536000` — 1 year HSTS
- `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
- `SECURE_HSTS_PRELOAD = True`

### Item 6 — Validate CVE ID format before outbound HTTP request
**File:** `web/api/views.py`
`CVEDetails.get()` concatenates `cve_id` query param directly into `requests.get('https://cve.circl.lu/api/cve/' + cve_id)`. Add regex validation: `re.match(r'^CVE-\d{4}-\d+$', cve_id)` before the request.

### Item 7 — Remove `BrowsableAPIRenderer` from production renderers
**File:** `web/reNgine/settings.py`
Remove `'rest_framework.renderers.BrowsableAPIRenderer'` from `DEFAULT_RENDERER_CLASSES`. The interactive DRF web UI has no place in a production security tool.

### Item 8 — Add explicit `permission_classes` to all APIView subclasses
**File:** `web/api/views.py`
Add `permission_classes = [IsAuthenticated]` to every `APIView` subclass that lacks it. Defense in depth: don't rely solely on middleware or DRF global defaults.

### Item 9 — Replace `run_command(f'touch {path}')` with `Path.touch()`
**File:** `web/api/views.py`
In `GetFileContents.get()`, replace all `run_command(f'touch {path}')` calls with `Path(path).touch()`. Eliminates an unnecessary shell invocation in a file-serving endpoint.

### Item 10 — Audit `shell=True` in task files; convert to arg-list where possible
**Files:** `web/reNgine/tasks/detect.py`, `dns.py`, `fuzzing.py`, `port_scan.py`, `subdomain.py`, `url.py`, `vulnerability.py`
Review each `shell=True` call. Where the command string is built with f-strings containing domain-origin values, restructure to use argument lists (`shell=False`) and `shlex.quote()` for any remaining dynamic values. Document cases where `shell=True` is unavoidable (pipe chains) and add compensating validation.

---

## Implementation Order
Items 1–7 are config/settings changes: low risk, shippable as one PR.
Item 8 is a mechanical sweep across all APIView classes.
Items 9–10 require testing against scan functionality before merge.
