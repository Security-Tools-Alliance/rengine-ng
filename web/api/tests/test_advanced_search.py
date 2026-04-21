from unittest.mock import patch

from django.urls import reverse
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from api.helpers import advanced_search as advanced_search_mod
from api.helpers.advanced_search import (
    parse_advanced_search_ast,
    parse_advanced_search_term,
    validate_advanced_search_expression,
    validate_expression_for_context,
)
from api.helpers.advanced_search_eval import boolean_field_value_from_token
from api.helpers.advanced_search_values import _base_queryset_for_context, _subdomain_distinct_technology_values
from api.helpers.query import build_vulnerability_datatable_base_queryset, parse_subdomain_datatable_request
from api.views import ListSubdomains
from startScan.models import Subdomain, Technology
from utils.test_base import BaseTestCase


class TestAdvancedSearchParser(BaseTestCase):
    """Unit tests for advanced search tokenizer, AST, and validation."""

    def test_parse_ast_single_general_atom(self):
        ast, err = parse_advanced_search_ast("nuclei")
        self.assertIsNone(err)
        self.assertEqual(ast, ("atom", "nuclei"))

    def test_parse_ast_and_chain(self):
        ast, err = parse_advanced_search_ast("http_status=200&technology=nuclei")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "and")
        self.assertEqual(len(ast[1]), 2)

    def test_parse_ast_or_chain(self):
        ast, err = parse_advanced_search_ast("severity=critical|status=open")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "or")
        self.assertEqual(len(ast[1]), 2)

    def test_parse_ast_mixed_precedence_and_before_or(self):
        """A|B&C parses as A OR (B AND C)."""
        ast, err = parse_advanced_search_ast("status=open|severity=high&cvss_score>8")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "or")
        self.assertEqual(ast[1][0], ("atom", "status=open"))
        inner = ast[1][1]
        self.assertEqual(inner[0], "and")

    def test_parse_ast_parentheses_override(self):
        ast, err = parse_advanced_search_ast("(status=open|status=closed)&name=x")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "and")
        self.assertEqual(ast[1][1], ("atom", "name=x"))
        self.assertEqual(ast[1][0][0], "or")

    def test_keyword_and_or(self):
        ast, err = parse_advanced_search_ast("http_status=200 AND technology=nuclei")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "and")

    def test_and_or_ignored_inside_double_quotes(self):
        ast, err = parse_advanced_search_ast('name="research AND development"')
        self.assertIsNone(err)
        self.assertEqual(ast, ("atom", 'name="research AND development"'))

    def test_and_outside_quotes_still_splits(self):
        ast, err = parse_advanced_search_ast('name="a"&http_status=200')
        self.assertIsNone(err)
        self.assertEqual(ast[0], "and")
        self.assertEqual(len(ast[1]), 2)

    def test_unclosed_quote_invalid(self):
        _, err = parse_advanced_search_ast('name="open')
        self.assertEqual(err, "unclosed_quote")

    def test_escaped_structural_chars_are_literal_in_atoms(self):
        ast, err = parse_advanced_search_ast(r"http_url=https://x.test/?a=1\&b=2&name=a\|b")
        self.assertIsNone(err)
        self.assertEqual(ast[0], "and")
        self.assertEqual(ast[1][0], ("atom", "http_url=https://x.test/?a=1&b=2"))
        self.assertEqual(ast[1][1], ("atom", "name=a|b"))

    def test_not_equal_operator(self):
        parsed, err = parse_advanced_search_term("http_status!=404")
        self.assertIsNone(err)
        self.assertEqual(parsed, ("http_status", "!", "404"))

    def test_quoted_value_preserves_operators(self):
        parsed, err = parse_advanced_search_term('http_url="https://a.test/p?q=a!=b"')
        self.assertIsNone(err)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], "http_url")
        self.assertEqual(parsed[1], "=")
        self.assertEqual(parsed[2], "https://a.test/p?q=a!=b")

    def test_quoted_value_with_escapes(self):
        parsed, err = parse_advanced_search_term(r'name="foo\"bar"')
        self.assertIsNone(err)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed[0], "name")
        self.assertEqual(parsed[2], 'foo"bar')

    def test_unquoted_still_splits_on_first_equals_after_field(self):
        parsed, err = parse_advanced_search_term("page_title=a=b")
        self.assertIsNone(err)
        self.assertEqual(parsed, ("page_title", "=", "a=b"))

    def test_parse_term_invalid_without_value(self):
        parsed, err = parse_advanced_search_term("http_status=")
        self.assertIsNone(err)
        self.assertIsNone(parsed)

    def test_parse_term_invalid_quoted_literal(self):
        parsed, err = parse_advanced_search_term('http_url="trail\\')
        self.assertEqual(err, "invalid_quoted_value")
        self.assertIsNone(parsed)

    def test_parse_term_invalid_quoted_unclosed_in_literal(self):
        parsed, err = parse_advanced_search_term('http_url="no_close')
        self.assertEqual(err, "invalid_quoted_value")
        self.assertIsNone(parsed)

    def test_unmatched_paren_invalid(self):
        _, err = parse_advanced_search_ast("(name=test")
        self.assertIsNotNone(err)

    def test_validate_expression_ok(self):
        r = validate_advanced_search_expression("http_status=200")
        self.assertTrue(r["valid"])
        self.assertIsNone(r.get("parse_error"))

    def test_validate_parse_error_includes_detail(self):
        r = validate_advanced_search_expression('name="open')
        self.assertFalse(r["valid"])
        self.assertEqual(r.get("parse_error"), "unclosed_quote")
        self.assertIn("quote", (r.get("error_detail") or "").lower())

    def test_validate_expression_invalid_quoted_value_in_walk(self):
        _orig = advanced_search_mod.parse_advanced_search_term

        def _fake(term: str):
            if (term or "").strip() == "synthetic_bad_literal":
                return None, "invalid_quoted_value"
            return _orig(term)

        with patch.object(advanced_search_mod, "parse_advanced_search_term", _fake):
            r = validate_advanced_search_expression("synthetic_bad_literal")
        self.assertFalse(r["valid"])
        self.assertEqual(r.get("parse_error"), "invalid_quoted_value")
        self.assertIn("malformed", (r.get("error_detail") or "").lower())

    def test_advanced_search_field_catalog_names_lowercase(self):
        from api.helpers.advanced_search import ADVANCED_SEARCH_FIELD_CATALOG

        for ctx, fields in ADVANCED_SEARCH_FIELD_CATALOG.items():
            for f in fields:
                self.assertEqual(f["name"], f["name"].lower(), msg="%s/%s" % (ctx, f["name"]))

    def test_datatable_request_parsers_align_with_values_api(self):
        from types import SimpleNamespace

        dg = self.data_generator
        slug = dg.project.slug
        scan_id = dg.scan_history.id
        req = SimpleNamespace(query_params={"project": slug, "scan_id": str(scan_id)})
        k = parse_subdomain_datatable_request(req)
        self.assertEqual(k["project_slug"], slug)
        self.assertEqual(k["scan_id"], scan_id)
        req2 = SimpleNamespace(query_params={"project": slug, "scan_history": str(scan_id)})
        qs = build_vulnerability_datatable_base_queryset(req2)
        self.assertIsNotNone(qs)

    def test_validate_unknown_field_warning(self):
        r = validate_expression_for_context("unknownfield=x", "subdomains")
        self.assertTrue(r["valid"])
        self.assertTrue(any("unknown_field" in w for w in r.get("warnings", [])))

    def test_api_advanced_search_fields(self):
        url = reverse("api:advancedSearchFields")
        response = self.client.get(url, {"context": "vulnerabilities"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("fields", response.data)
        names = {f["name"] for f in response.data["fields"]}
        self.assertTrue(len(names) >= 5)
        self.assertNotIn("type", names)
        self.assertNotIn("cve_id", names)
        self.assertIn("description", names)
        r2 = self.client.get(url, {"context": "subdomains"})
        self.assertEqual(r2.status_code, status.HTTP_200_OK)
        sn = {f["name"] for f in r2.data["fields"]}
        self.assertNotIn("cname", sn)
        self.assertNotIn("http_url", sn)
        r3 = self.client.get(url, {"context": "ips"})
        self.assertEqual(r3.status_code, status.HTTP_200_OK)
        ipn = {f["name"] for f in r3.data["fields"]}
        self.assertIn("address", ipn)
        self.assertIn("subdomain", ipn)
        self.assertIn("port", ipn)

    def test_api_advanced_search_validate(self):
        url = reverse("api:advancedSearchValidate")
        response = self.client.post(
            url,
            {"expression": "(unclosed", "context": "endpoints"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["valid"])
        self.assertEqual(response.data.get("parse_error"), "unclosed_parenthesis")
        self.assertTrue(response.data.get("error_detail"))

    def test_api_advanced_search_values_endpoints_http_status(self):
        dg = self.data_generator
        slug = dg.project.slug
        dg.create_endpoint(
            name="valst1",
            http_url="https://a.example-test.invalid/valst1",
            http_status=200,
        )
        dg.create_endpoint(
            name="valst2",
            http_url="https://b.example-test.invalid/valst2",
            http_status=404,
        )
        url = reverse("api:advancedSearchValues")
        response = self.client.get(
            url,
            {"context": "endpoints", "field": "http_status", "project": slug},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        vals = response.data.get("values") or []
        self.assertIn("200", vals)
        self.assertIn("404", vals)

    def test_api_advanced_search_values_subdomains_uses_default_endpoint_display(self):
        """page_title / http_status / content_length match DataTable (default EndPoint first)."""
        dg = self.data_generator
        slug = dg.project.slug
        scan_id = dg.scan_history.id
        sd = dg.create_subdomain(
            name="advsearch-disp.example.invalid",
            page_title="",
            http_status=0,
            content_length=0,
        )
        dg.create_endpoint(
            subdomain=sd,
            is_default=True,
            page_title="UniqueDisplayTitle",
            http_status=418,
            content_length=9999,
        )
        url = reverse("api:advancedSearchValues")
        r1 = self.client.get(
            url,
            {"context": "subdomains", "field": "page_title", "project": slug, "scan_id": scan_id},
        )
        self.assertEqual(r1.status_code, status.HTTP_200_OK)
        self.assertIn("UniqueDisplayTitle", r1.data.get("values") or [])
        r2 = self.client.get(
            url,
            {"context": "subdomains", "field": "http_status", "project": slug, "scan_id": scan_id},
        )
        self.assertEqual(r2.status_code, status.HTTP_200_OK)
        self.assertIn("418", r2.data.get("values") or [])
        r3 = self.client.get(
            url,
            {"context": "subdomains", "field": "content_length", "project": slug, "scan_id": scan_id},
        )
        self.assertEqual(r3.status_code, status.HTTP_200_OK)
        self.assertIn("9999", r3.data.get("values") or [])

    def test_advanced_search_values_view_json_renderer_only(self):
        """Avoid DatatablesRenderer when scope copies format=datatables from DataTable ajax URL."""
        from api.views_advanced_search import AdvancedSearchValuesView

        self.assertEqual(list(AdvancedSearchValuesView.renderer_classes), [JSONRenderer])

    def test_api_advanced_search_values_invalid_context(self):
        url = reverse("api:advancedSearchValues")
        response = self.client.get(
            url,
            {"context": "nope", "field": "http_status", "project": self.data_generator.project.slug},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("context"), "nope")

    def test_api_advanced_search_values_invalid_field(self):
        url = reverse("api:advancedSearchValues")
        response = self.client.get(
            url,
            {"context": "endpoints", "field": "not_a_field", "project": self.data_generator.project.slug},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get("context"), "endpoints")
        self.assertEqual(response.data.get("field"), "not_a_field")

    def test_api_advanced_search_values_removed_subdomain_fields(self):
        url = reverse("api:advancedSearchValues")
        slug = self.data_generator.project.slug
        for fld in ("cname", "http_url", "content_type"):
            r = self.client.get(
                url,
                {"context": "subdomains", "field": fld, "project": slug},
            )
            self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST, msg=fld)

    def test_boolean_field_value_unknown_token_returns_none(self):
        self.assertIsNone(boolean_field_value_from_token("maybe", "true", "false"))
        self.assertIs(boolean_field_value_from_token("true", "true", "false"), True)
        self.assertIs(boolean_field_value_from_token("false", "true", "false"), False)

    def test_base_queryset_unknown_context_returns_error(self):
        class DummyRequest:
            pass

        qs, err = _base_queryset_for_context(DummyRequest(), "unknown_ctx")
        self.assertIsNone(qs)
        self.assertEqual(err, "unknown_context")

    def test_subdomain_distinct_technology_values_deduplicates_union_before_limit(self):
        scan = self.data_generator.scan_history
        domain = self.data_generator.domain
        subdomain = self.data_generator.create_subdomain(
            name="adv-tech.example.invalid",
            scan_history=scan,
            domain=domain,
        )
        m2m_tech = Technology.objects.create(scan_history=scan, name="django")
        endpoint_only_tech = Technology.objects.create(scan_history=scan, name="flask")
        subdomain.technologies.add(m2m_tech)
        endpoint = self.data_generator.create_endpoint(
            http_url="https://adv-tech.example.invalid/",
            scan_history=scan,
            domain=domain,
            subdomain=subdomain,
        )
        endpoint.techs.add(m2m_tech, endpoint_only_tech)

        values = _subdomain_distinct_technology_values(
            Subdomain.objects.filter(id=subdomain.id),
            q_prefix="",
            lim=2,
        )

        self.assertEqual(values, ["django", "flask"])

    def test_subdomain_distinct_technology_values_subdomain_cap_limits_scope(self):
        scan = self.data_generator.scan_history
        domain = self.data_generator.domain
        sub_a = self.data_generator.create_subdomain(
            name="cap-a.example.invalid",
            scan_history=scan,
            domain=domain,
        )
        sub_b = self.data_generator.create_subdomain(
            name="cap-b.example.invalid",
            scan_history=scan,
            domain=domain,
        )
        tech_a = Technology.objects.create(scan_history=scan, name="tech-only-on-a")
        tech_b = Technology.objects.create(scan_history=scan, name="tech-only-on-b")
        sub_a.technologies.add(tech_a)
        sub_b.technologies.add(tech_b)
        qs = Subdomain.objects.filter(id__in=[sub_a.id, sub_b.id])
        capped = _subdomain_distinct_technology_values(qs, "", 10, subdomain_cap=1)
        if sub_a.scan_history_id > sub_b.scan_history_id:
            self.assertEqual(capped, ["tech-only-on-a"])
        elif sub_b.scan_history_id > sub_a.scan_history_id:
            self.assertEqual(capped, ["tech-only-on-b"])
        elif sub_a.id > sub_b.id:
            self.assertEqual(capped, ["tech-only-on-a"])
        else:
            self.assertEqual(capped, ["tech-only-on-b"])
        uncapped = _subdomain_distinct_technology_values(qs, "", 10, subdomain_cap=0)
        self.assertEqual(set(uncapped), {"tech-only-on-a", "tech-only-on-b"})

    def test_advanced_search_invalid_boolean_atom_does_not_filter(self):
        view = ListSubdomains()
        view.search_config = ListSubdomains.search_config
        from startScan.models import Subdomain

        base = Subdomain.objects.all()
        n = base.count()
        filtered = view.apply_advanced_search(base, "is_important=maybe")
        self.assertEqual(filtered.count(), n)
