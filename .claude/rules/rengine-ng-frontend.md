---
description: Frontend and Datatables conventions for reNgine-ng, including JavaScript style, URL handling, responsive design, and server-side DataTables usage.
---

# reNgine-ng – Frontend & Datatables conventions

## Scope

Apply these guidelines when working on frontend code:

- JavaScript files under `web/`
- Django templates rendering frontend HTML/JS
- Datatables configuration (JS and templates)

## JavaScript style

- Always use `const` or `let` instead of `var`.
- Prefer function expressions assigned to variables instead of function declarations at top-level when working inside blocks.
- Do not hardcode URLs in JS:
  - Use Django routes passed from templates (for example, via `data-*` attributes or JSON config).

### Example – avoid hardcoded URLs

```javascript
// ❌ Bad
const url = "/api/targets/42/";

// ✅ Good – injected from template
const url = document.querySelector("#target-table").dataset.apiUrl;
```

## Datatables

- All DataTables must use **server-side processing** (`serverSide: true`).
- Construction of DataTables must be centralised and standardised:
  - Use existing helpers in `web/api/helpers/datatables.py`.
  - Use JS helpers in `web/static/custom/datatables/` (especially `escape.js` and shared renderers) – no bespoke initialisation logic scattered in multiple files.
- Creating a new table should be as simple as defining the business-specific aspects:
  - Columns and renderers
  - Filters
  - Tooltips
  - Layout configuration

### Datatables contract reference

- The canonical contract for column index → order field mapping and frontend wiring is documented in the header of `web/api/helpers/datatables.py`.
- When you add, move, or remove a column in a DataTable:
  - Update the corresponding `DATATABLE_COLUMN_MAP_*` entry in `datatables.py`.
  - Update the serializer fields if the displayed data changes.
  - Update the `columns[]` array and `columnDefs` in the JS/template so indices and names stay in sync.

## Responsive design

- All UI changes must respect responsive design for proper display on different screen sizes.

## Security cross-reference

- For HTML/JS injection and XSS-related rules, also see the security rule `rengine-ng-security.md` (HTML escaping, `htmlEncode`, URL validation).

