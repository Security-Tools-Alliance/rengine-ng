# reNgine-ng — Agent Guidelines

Authoritative coding guidelines for this repository.
All AI agents should follow these rules regardless of the editor or tool being used.

## Stack summary

| Layer        | Technology |
|--------------|------------|
| Backend      | Django 5.x, Python 3.12 |
| DB           | PostgreSQL 17, PgBouncer |
| Tasks        | Secator (workflows, scans) |
| Frontend     | HTML5, CSS3, JS (Bootstrap, DataTables server-side) |
| Servers      | Uvicorn (prod), Daphne (dev), Nginx |
| Containers   | Docker, Docker Compose |
| Quality      | Ruff (lint/format), type hints, tests in `app_name/tests/` |

- **App code**: under `web/`; in Docker the project root is `/home/rengine/rengine` (maps to `web/`).
- **API**: Django REST Framework; use User API key for automated tests (no CSRF). Test API key: `StkhUn8u.eabOMNVe9f9LqPShKDJjFXbILzR9wV0M`
- **Logging**: Use `ModuleLogger` and `logger.log_line(...)` only; no direct `logger.info`/`logger.debug` etc.
- **Style**: run `make ruff-format` and `make ruff-fix` to verify style.

---

## Project mantras

- Do what is right
- Security by design — Security by default
- Doing the right thing should be easy
- Batteries included — it just works
- Better explicit than magical

---

## General expectations

You are an expert in Python/Django/JS/PostgreSQL development. Deliver high-quality, non-duplicated code that strictly follows KISS, DRY and SOLID principles.

- Follow existing patterns: study similar code before proposing changes.
- Add type hints to all new code.
- Every code change must include corresponding tests.
- All code and comments must be written in English.
- Do not add comments that describe the refactor itself; only explain non-obvious intent.
- Keep the project modular to avoid circular dependencies:
  - Leaf modules (`logger.py`, `db.py`, `utils.py`) at the bottom.
  - Core business logic (services, repositories) in the middle.
  - Orchestration layers (entrypoints, CLI, HTTP views) at the top.

---

## Mandatory implementation pre-flight

Before writing code, perform this verification sequence:

1. Locate existing shared abstractions/helpers for the target area and reuse them first.
2. Avoid local duplication in templates/modules when a central helper already exists.
3. For **tabbed entity UI** shared between **scan detail** (`startScan/detail_scan.html`) and **target summary** (`targetApp/target/summary.html`), put the tab body in `web/templates/base/_items/<feature>_tab_content.html` and include it from both pages (e.g. flags `detail_scan` / `target_summary`). Check existing partials before adding large HTML blocks to either page.
4. For frontend DataTables changes, enforce central action rendering and URL wiring through shared datatable helpers; use lazy tab init where appropriate, define columns in `column_definitions.js` (`window.RENGINE_*_DATATABLE_COLUMNS`), and keep `DATATABLE_COLUMN_MAP_*` in `column_maps.py` aligned with the **column order** in that array. Reuse **`web/templates/base/_items/_datatable_advanced_search_block.html`** for the advanced-search bar (do not duplicate that markup); align `data-advanced-search` with `advanced_search_profiles.js` and `api/helpers/advanced_search.py`.
5. **Backend IP / XOR / LLM attack surface**:
   - For "IP in scan" checks use `reNgine.services.scan_finding_metrics` (and `reNgine.utilities.scan_lookups` wrappers), not ad-hoc `IpAddress` filters.
   - For mutually exclusive `subdomain_id` / `ip_address_id` (and list forms) use `api.helpers.subdomain_ip_xor` and `api.helpers.secator_scan_target_request`.
   - For LLM endpoints that accept exactly one aggregate entity, use `xor_attack_surface_entity_ids_error`, `attack_surface_entity_query_params_invalid_error`, and `resolve_attack_surface_entity_kind_and_pk` from the same module.
   - Resolve entities for LLM attack-surface APIs only through `api.helpers.llm_attack_surface_access`.
   - Build large aggregate context in `reNgine.llm.attack_surface_context`.
   - Keep Python `ATTACK_SURFACE_KIND_*` in `api/helpers/subdomain_ip_xor.py` aligned with `RENGINE_ATTACK_SURFACE_ENTITY_*` in `web/static/custom/target_entity_kind.js`.
6. Update or add tests that protect the new/changed shared contract.

---

## Scan config architecture

Organization, Scope, Target, and ScanHistory each carry a `scan_config` JSONField with the same schema (profiles, threads, rate_limit, timeout, retries, delay, proxy, user_agent, request_headers, follow_redirect, depth, extra_config).

- **Resolution hierarchy**: Organization → Scope → Target → Scan (user override). Only keys present in a lower-level `scan_config` act as overrides; missing keys inherit from the level above.
- **Backend service**: `resolve_scan_params(target, scope, organization, user_override)` in `web/targetApp/services/scope_params.py` computes the effective config. `build_effective_params_display(scope, target, organization)` provides annotated display data for the UI.
- **Shared UI**: All four forms (org, scope, target, scan) include `web/templates/shared/_scan_params_block.html` and load `web/static/custom/scan_params.js` (non-scan pages) or `secatar_scan_core.js` (scan page).
- **POST parsing**: `parse_scan_config_from_post(post, prefix, profiles_dict, existing_config)` in `scope_params.py` converts form data into the JSON structure.

---

## Python backend conventions

### Architecture and layering

- Organise modules to avoid circular dependencies:
  - Leaf modules (`logger.py`, `db.py`, `utils.py`) sit at the bottom.
  - Core business logic (services, repositories) sits in the middle.
  - Orchestration layers (entrypoints, CLI, HTTP views) sit at the top.

### Python code style

- Prefer simple, explicit code that follows KISS, DRY and SOLID.
- Use named expressions when they simplify the code.
- Prefer f-strings for string formatting.
- Replace nested `if` chains with combined conditions when it improves readability.
- Swap `if/else` branches to remove negations when it makes the logic clearer.
- Avoid temporary variables that are immediately returned.
- Keep variable assignments close to their usage.
- Raise specific exceptions instead of generic `Exception` / `BaseException`.
- Convert loops to comprehensions or `sum()` when it stays readable.
- Extract long blocks into helper methods to improve comprehension.
- Place private methods at the bottom of the file.

```python
# ❌ Before
if not user.is_active:
    return
if user.is_admin:
    do_admin_action(user)

# ✅ After
if user.is_active and user.is_admin:
    do_admin_action(user)
```

### Logging

- Use `ModuleLogger` from `module_logger.py` for all logs.
- Always go through `logger.log_line(...)` so logs are correctly formatted.
- Never call `logger.debug`, `logger.info`, etc. directly.

```python
logger.log_line(PREFIX_SYNC, "POOL", f"executor started with max_workers={max_workers}", level="debug")
```

### IP hosts, scan membership, and API XOR parameters

- **IP literals**: normalize/validate with `reNgine.core.ip_literal`.
- **No Subdomain row for numeric hosts**: `SubdomainRepository.get_or_create_from_host` returns `None` for IP literals; IP-backed assets use `IpAddress` and `EndPoint.ip_address`.
- **"IP linked to this scan"**: use `reNgine.services.scan_finding_metrics`. Do not reintroduce parallel filter logic.
- **Mutually exclusive ids in APIs**: use `api.helpers.subdomain_ip_xor` and `api.helpers.secator_scan_target_request`.

### LLM attack surface

- **Access control**: resolve `Target`, `Scope`, `Organization`, `Subdomain`, `IpAddress` with `api.helpers.llm_attack_surface_access` only. Do not load by primary key without the same project filter.
- **Entity XOR and kinds**: `api.helpers.subdomain_ip_xor` centralises XOR validation. Keep constants in sync with `web/static/custom/target_entity_kind.js`.
- **Aggregate context**: `reNgine.llm.attack_surface_context` builds capped, structured text; extend caps there rather than duplicating logic in views.

### Markdown `attack_surface` field

`Organization`, `Scope`, `Target`, and `IpAddress` expose an `attack_surface` text field and `formatted_attack_surface` for HTML display. Persist and edit through the existing flows; do not bypass validation or escaping rules when rendering user-authored markdown.

---

## Frontend & DataTables conventions

### Shared tab content partials

- Primary tab bodies that appear on both **scan detail** and **target summary** must live in `web/templates/base/_items/<feature>_tab_content.html`.
- Page templates should only wrap the tab pane and `{% include %}` the partial with context flags.
- Do not embed large duplicated tab markup directly in a single page template.

### Advanced search bar

- The shared markup for the advanced search row must come from `web/templates/base/_items/_datatable_advanced_search_block.html`.
- When adding a new DataTable tab that uses advanced search, register a profile in `web/static/custom/datatables/advanced_search_profiles.js` and add the same context to `web/api/helpers/advanced_search.py`.

### JavaScript style

- Always use `const` or `let` instead of `var`.
- Prefer function expressions assigned to variables instead of function declarations at top-level when working inside blocks.
- Do not hardcode URLs in JS — use Django routes passed from templates via `data-*` attributes or JSON config.

```javascript
// ❌ Bad
const url = "/api/targets/42/";

// ✅ Good – injected from template
const url = document.querySelector("#target-table").dataset.apiUrl;
```

### DataTables

- All DataTables must use **server-side processing** (`serverSide: true`).
- Backend column/order maps in `web/api/helpers/datatables/column_maps.py`; frontend in `web/static/custom/datatables/`.

#### Mandatory pre-flight before any DataTable change

1. Check whether a shared renderer/helper already exists in `web/static/custom/datatables/` (especially `actions.js`, `column_definitions.js`, `init.js`, `filters.js`).
2. If a shared renderer exists, reuse/extend it instead of writing inline HTML render logic.
3. If a new action renderer is required, add it to `actions.js` and expose it through `window.RengineDatatableActionRenderers`.
4. Wire URLs through `get_datatable_action_urls()` in `web/api/helpers/datatables/actions.py` and consume via `window.RENGINE_DATATABLE_ACTION_URLS`.
5. Keep templates focused on DataTable composition; avoid feature logic duplication in template JS blocks.
6. Add/adjust tests for datatable action URL contracts in `web/api/tests/test_datatables.py`.

#### Frontend modules (`web/static/custom/datatables/`)

Load order in `base.html` must be respected (escape → layout → cookies → columns → rowgroup → filters → config → actions → init → tooltips → column_definitions).

- **escape.js** – `safeText`, `safeAttr`, `safeBadge`, `safeLink`, `safeTooltipTitle`. Use for any content from the server or user.
- **layout.js** – Scroller options, length menu, `getRengineDatatableLayoutFull`.
- **cookies.js** – Cookie read/write for row-group and preferences.
- **columns.js** – `getColumnIndexByName`, `rengineColumnByName`, `getRengineDatatableOrderFromNames`.
- **rowgroup.js** – `getRengineRowGroupInitialState`, row-group selector attachment.
- **filters.js** – `getRengineDatatableFilterParams`, `buildRengineDatatableAjaxData`, `attachDatatableFilters`.
- **config.js** – Central element IDs: `RENGINE_DATATABLE_FILTER_PARAMS_SCRIPT_ID`, `RENGINE_DATATABLE_ROW_GROUP_CONFIG_SCRIPT_ID`.
- **actions.js** – Action column renderers (subdomain, IP, vulnerability, target). Uses `safeAttr`/`safeText` from escape.js.
- **target_entity_kind.js** – Attack-surface entity kind constants and `RengineTargetEntityKind`. Must match `ATTACK_SURFACE_KIND_*` in `api/helpers/subdomain_ip_xor.py`.
- **init.js** – `getRengineDatatableConfig`, `initServerSideDataTable`, **`initRengineServerSideDataTable`** (one-call entry point).
- **tooltips.js** – `getRengineDatatableDrawCallbackTooltips` for drawCallback tooltip refresh.
- **column_definitions.js** – Shared column arrays and default order/row-group metadata. Single source of truth; keep in sync with backend column maps.
- **selection_helpers.js** – `createRengineDatatableIdSelection` for numeric row-id sets.
- **ip_scan_table_handlers.js** – Delegated click handlers for IP row actions.

#### Backend contract

- Column index → order field mapping lives in `column_maps.py` (`DATATABLE_COLUMN_MAP_*`).
- When you add, move, or remove a column: update `DATATABLE_COLUMN_MAP_*`, the serializer, and the `columns` array and `columnDefs` in JS/template.
- Every column definition must set **`name`** (e.g. `{ data: "id", name: "id" }`).

#### Heavy DataTables inside tabbed UI

- Initialise non-default tabs with large server-side tables on first user activation of that tab; guard with `DataTable.isDataTable(...)`.

#### Filter and script element IDs

- Use `window.RENGINE_DATATABLE_FILTER_PARAMS_SCRIPT_ID` and `window.RENGINE_DATATABLE_ROW_GROUP_CONFIG_SCRIPT_ID` instead of hardcoding string IDs.

#### List-page setup

- Use `initRengineServerSideDataTable(tableSelector, options)` as the one-call entry point.

### Scan parameters UI

`web/templates/shared/_scan_params_block.html` renders profile selectors and numeric fields. Include with:

```django
{% include "shared/_scan_params_block.html" with field_prefix="scope" effective_params=effective_params profiles_dict=profiles_dict %}
```

- **Non-scan pages**: load `web/static/custom/scan_params.js`.
- **Scan page**: uses `web/static/custom/secator/secatar_scan_core.js`. Do not load both on the same page.

### Responsive design

All UI changes must respect responsive design for proper display on different screen sizes.

### Recon note AJAX routes

Prefer slug-prefixed URLs: `/<slug>/list_note`, `/<slug>/flip_todo_status`, etc. (see `web/recon_note/urls.py`).

---

## Security rules

### 1. Paths and file system

- **Rule 1.1**: No data from the user, request, or database must be concatenated directly with `Path()`, `os.path.join()` or passed to `open()` without validation.
- **Rule 1.2**: Use the central helpers: `reNgine.core.path.resolve_results_dir_under_base`, `safe_rmtree`, `is_safe_path`; `reNgine.core.validators.sanitize_path_component`.
- **Rule 1.3**: For relative paths from URLs: reject `..`, absolute paths, and null characters; normalise with `sanitize_path_component` or a helper that checks `is_safe_path(base, resolved)`.
- **Rule 1.4**: Do not duplicate safe-path logic; use the single reference module `reNgine.core.path`.

### 2. Logs (log injection)

- **Rule 2.1**: For logger calls whose message can contain user/request/DB data, use `%`-style formatting: `logger.info("... %s ...", value)`. Do not use f-strings or string concatenation in log messages for such data.
- **Rule 2.2**: Reject any pattern like `logger.info(f"... {variable}")` when `variable` may be externally controlled.

### 3. URLs

- **Rule 3.1**: To compare host or scheme of a URL, use `urllib.parse.urlparse(url)` and compare `.netloc` or `.hostname`. Do not use simple substring checks.
- **Rule 3.2**: URLs constructed from user data must be validated (allowed schemes, no `javascript:`) before use.

### 4. XSS and dynamic content

- **Rule 4.1**: Any data from server or user injected into the DOM must go through `htmlEncode` (or `safeText`/`safeAttr` from `escape.js`) **before** insertion.
- **Rule 4.2**: Single central `htmlEncode` implementation; canonical locations: `web/static/custom/custom.js` and `web/static/custom/datatables/escape.js`.
- **Rule 4.3**: In Django templates, use `|escape` by default. Use `|safe` only for content whose origin is well understood.
- **Rule 4.4**: For URL attributes (`href`, `src`), validate the scheme; use `sanitizeUrlForAttribute` to avoid `javascript:`.

### 5. Dynamic objects and properties

- **Rule 5.1**: When an object key comes from the network or a user, use a `Map` or validate the key against an allowlist; reject `__proto__`, `constructor`, `prototype`.
- **Rule 5.2**: Treat `response[key]`, `item[field]`, or `options[userInput]` as suspicious when the key is not a constant.

### 6. File permissions

- **Rule 6.1**: Files created by the application must not use overly permissive modes. Prefer `0o640` or `0o600` for sensitive data.
- **Rule 6.2**: In tests, use the most restrictive mode that fits the scenario.

### 7. Cross-cutting

- **Rule 7.1**: Single place for path validation, HTML escaping, and URL validation; other modules call these helpers.
- **Rule 7.2**: Prefer native Django mechanisms (file storage, name validation, CSRF, template escaping) and only bypass with justification.
- **Rule 7.3**: CodeQL alerts of level High and Medium must be addressed or explicitly accepted with justification.
- **Rule 7.4 (LLM attack surface)**: Any view or API loading `Target`, `Scope`, `Organization`, `Subdomain`, or `IpAddress` for LLM features must enforce project membership through `api.helpers.llm_attack_surface_access`. Do not trust a bare integer id from the client without that filter.

### 8. Information exposure through exceptions

- **Rule 8.1**: Never return raw exception text (`str(e)`) or stack traces to the client. Log server-side with `logger.exception` or `logger.error(exc_info=True)`, then return a generic message.
- **Rule 8.2**: Use `get_safe_user_message` to produce user-facing messages. For 500-level errors, return a fixed generic message.

### 9. Network binding

- **Rule 9.1**: Debug servers (e.g. debugpy) must not bind to `0.0.0.0` by default. Use `127.0.0.1`.
- **Rule 9.2**: If all-interface binding is required, do it via an explicit environment variable with documented risks.

### 10. External scripts

- **Rule 10.1**: Any CDN script must include an SRI `integrity` attribute with the hash of the exact file version, and `crossorigin="anonymous"`. Update the SRI hash on version upgrades.
- **Rule 10.2**: Alternative: host scripts locally (`static/`) and document the update procedure.

---

## Testing conventions

### Test location

- All tests must live under `web/<app_name>/tests/`.
- Mirror the code structure: if code is in `web/<app_name>/lib_dir/`, tests must be in `web/<app_name>/tests/lib_dir/`.

### Test base classes and data

- All unit tests must use `BaseTestCase` from `utils/test_base.py`.
- Use `TestDataGenerator` to create test data; do not hand-roll ad-hoc factories.
- Anonymise all test data (IPs, hostnames, DNS, emails) so no real data appears in tests.

```python
from utils.test_base import BaseTestCase, TestDataGenerator

class TargetServiceTestCase(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.data_gen = TestDataGenerator()
        self.target = self.data_gen.create_target()
```

### Positive and negative test data

- Include both **valid** (happy path) and **invalid or malicious** cases.
- **Valid data**: use `TestDataGenerator` only.
- **Invalid/malicious data**: use `BadPathSamples` and `BadUrlSamples` from `utils.test_utils`. Do not duplicate magic strings; add new constants there and reuse.

### Security-related tests

- For code that handles paths, URLs, user input, or displayed content, add tests that verify **rejection** of invalid or malicious inputs.

### Determinism and isolation

- Tests must be deterministic and independent of timing.
- Avoid `sleep`, real network calls, or external services.
- Cover edge cases, especially around error handling.

### Running tests

```bash
make test                                          # full suite (after model changes)
make test KEEPDB=1                                 # fast (no model changes)
make test-only TESTS="app.tests.module.Class.test" KEEPDB=1 VERBOSITY=2
make test VERBOSITY=2
make test-app APPS=api VERBOSITY=3 KEEPDB=1
```

### Temporary test files

Delete temporary Python test files or validation scripts once they are no longer needed.

---

## Secator usage

### When to apply

Apply these guidelines when working on features that interact with Secator: scan workflows, tasks, orchestration from the web UI.

### Listing Secator configurations (inside web container)

```bash
docker exec -it rengine-web-1 bash -c \
  "poetry run -C /home/rengine/rengine python3 -c 'from secator.loader import get_configs_by_type; print(get_configs_by_type(\"workflow\"))'"
```

Replace `"workflow"` with `"scan"` or `"task"` as needed.

### Documentation

- Main docs: [Secator docs](https://github.com/freelabz/secator-docs)
- Repo and tools overview: [Secator repo](https://github.com/freelabz/secator)
- Full integrated tools list: [.github/ai/secator-tools.md](.github/ai/secator-tools.md)

### Integration guidelines

- Orchestrate Secator from dedicated service/orchestrator modules; avoid mixing orchestration logic directly into views.
- Validate all user input before passing it into Secator configurations (targets, scopes, workflow names, etc.).
- Do not duplicate Secator configuration parsing logic; reuse shared helpers/modules.
- **IP targets for Secator**: `reNgine.secator.services.target_builder_service.TargetBuilderService` resolves host targets from `IpAddress` rows tied to the current target's `ScanHistory`. Prefer extending that service instead of reintroducing domain-only IP collection.

---

## Change management

- Do not perform radical changes without explicit discussion.
- Do not add new dependencies without maintainer approval.
- Do not modify the CI/CD configuration without understanding the entire pipeline.

---

## Stack reference

### Core technologies

- **Django** 5.x — ORM, REST API, auth, permissions
- **Python** 3.12 — backend logic, type hints
- **Secator** 0.25.1+ — async scan execution, workflow orchestration via Redis/Celery
- **PostgreSQL** 17 — persistent storage; **PgBouncer** — connection pooling
- **HTML5, CSS3** (Bootstrap), **JavaScript** ES6+, AJAX, DataTables (server-side)
- **Uvicorn** (prod), **Daphne** (dev), **Nginx** — reverse proxy, SSL, static files
- **Docker** / Docker Compose
- **Ruff** — lint and format; config in `docker/web/pyproject.toml`

### Key modules

- **targetApp** — Organizations, Scopes, Targets. Models carry `scan_config` JSONField (same schema on all three). Services in `web/targetApp/services/scope_params.py`: `resolve_scan_params()`, `build_effective_params_display()`, `parse_scan_config_from_post()`.
- **startScan** — `ScanHistory.scan_config` JSONField stores user overrides at scan launch. Scan page uses `secatar_scan_core.js` for parameter/profile management.
- **Workers** — remote deployment, SSH, health checks.
- **UI** — responsive, real-time, DataTables, charts; shared `_scan_params_block.html` + `scan_params.js`.

### Learning resources

- [Django](https://docs.djangoproject.com/) · [DRF](https://www.django-rest-framework.org/) · [Python](https://docs.python.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) · [Docker](https://docs.docker.com/)
- [Secator docs](https://github.com/freelabz/secator-docs) · [Secator repo](https://github.com/freelabz/secator)

---

## Secator tools

Tools integrated in Secator. List configurations with `get_configs_by_type("workflow" | "scan" | "task")` inside the web container.

| Category | Tool | Description |
|----------|------|-------------|
| recon/dns | dnsx | Fast multi-purpose DNS toolkit (queries) |
| recon/dns | dnsxbrute | Same as dnsx, bruteforce mode |
| recon/dns | subfinder | Fast subdomain finder |
| recon/ip | fping | Find alive hosts on local networks |
| recon/ip | mapcidr | Expand CIDR ranges into IPs |
| recon/port | naabu | Fast port discovery tool |
| recon/user | maigret | Hunt for user accounts across many websites |
| http | httpx | Fast HTTP prober |
| http/crawler | cariddi | Fast crawler, endpoint secrets/API keys/tokens matcher |
| http/crawler | gau | Offline URL crawler (Alien Vault, Wayback, Common Crawl, URLScan) |
| http/crawler | gospider | Fast web spider (Go) |
| http/crawler | katana | Next-generation crawling and spidering framework |
| http/fuzzer | dirsearch | Web path discovery |
| http/fuzzer | feroxbuster | Fast recursive content discovery (Rust) |
| http/fuzzer | ffuf | Fast web fuzzer (Go) |
| osint | h8mail | Email OSINT and breach hunting |
| vuln/code | grype | Vulnerability scanner for container images and filesystems |
| vuln/http | dalfox | XSS scanning and parameter analysis |
| vuln/http | msfconsole | Metasploit Framework CLI |
| vuln/multi | wpscan | WordPress security scanner |
| vuln/multi | nmap | Port/vuln scanning with NSE scripts |
| vuln/multi | nuclei | Fast configurable vuln scanner (YAML DSL) |
| tagger | gf | Wrapper around grep for common patterns |
