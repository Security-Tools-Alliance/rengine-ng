"""Tests for finding scope filter helpers (restrict_findings_to_target)."""

from targetApp.services.scope_params import (
    get_finding_scope_filter_domain,
    get_finding_scope_filter_domain_for_target,
    get_finding_scope_filter_host,
    get_finding_scope_filter_host_for_target,
    get_finding_scope_filters_for_target,
)
from utils.test_base import BaseTestCase


class FindingScopeFilterDomainTest(BaseTestCase):
    """Tests for get_finding_scope_filter_domain."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_organization()
        self.data_generator.create_scope()
        self.scope = self.data_generator.scope
        self.target = self.data_generator.target

    def test_scope_none_returns_none(self) -> None:
        self.assertIsNone(get_finding_scope_filter_domain(None, self.target))

    def test_restrict_false_returns_none(self) -> None:
        self.scope.restrict_findings_to_target = False
        self.scope.save()
        self.assertIsNone(get_finding_scope_filter_domain(self.scope, self.target))

    def test_restrict_true_domain_filter_rejects_ip(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_domain(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertFalse(fn("192.168.1.1"))
        self.assertFalse(fn("10.0.0.1"))

    def test_restrict_true_allows_target_domain(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_domain(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn(self.target.value))
        self.assertTrue(fn("sub." + self.target.value))

    def test_restrict_true_rejects_domain_outside_list(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.save()
        fn = get_finding_scope_filter_domain(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertFalse(fn("other-unrelated.com"))

    def test_restrict_true_allows_whitelisted_domain(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = ["allowed-extra.com"]
        self.scope.save()
        fn = get_finding_scope_filter_domain(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn("allowed-extra.com"))
        self.assertTrue(fn("sub.allowed-extra.com"))

    def test_restrict_true_allowed_finding_hosts_adds_root_domains(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.allowed_finding_hosts = ["sub.example-from-hosts.com"]
        self.scope.save()
        fn = get_finding_scope_filter_domain(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn("example-from-hosts.com"))
        self.assertTrue(fn("other.example-from-hosts.com"))


class FindingScopeFilterHostTest(BaseTestCase):
    """Tests for get_finding_scope_filter_host."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_organization()
        self.data_generator.create_scope()
        self.scope = self.data_generator.scope
        self.target = self.data_generator.target

    def test_scope_none_returns_none(self) -> None:
        self.assertIsNone(get_finding_scope_filter_host(None, self.target))

    def test_restrict_true_host_filter_allows_ip(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn("192.168.1.1"))
        self.assertTrue(fn("10.0.0.1"))

    def test_restrict_true_allows_target_host(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn(self.target.value))
        self.assertTrue(fn("www." + self.target.value))

    def test_restrict_true_rejects_host_outside_list(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertFalse(fn("other-unrelated.com"))

    def test_allowed_finding_hosts_non_empty_only_listed_hosts_accepted(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.allowed_finding_hosts = ["allowed-one.example.com", "192.168.1.1"]
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn("allowed-one.example.com"))
        self.assertTrue(fn("192.168.1.1"))
        self.assertFalse(fn("other-unrelated.com"))
        self.assertFalse(fn("10.0.0.1"))

    def test_allowed_finding_hosts_empty_keeps_domain_based_behavior(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.allowed_finding_hosts = []
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn(self.target.value))
        self.assertTrue(fn("192.168.1.1"))

    def test_allowed_finding_hosts_non_empty_target_host_still_allowed(self) -> None:
        """Target host is allowed even when not in allowed_finding_hosts (target stays in scope)."""
        self.scope.restrict_findings_to_target = True
        self.scope.allowed_finding_domains = []
        self.scope.allowed_finding_hosts = ["www.other-domain.com"]
        self.scope.save()
        fn = get_finding_scope_filter_host(self.scope, self.target)
        self.assertIsNotNone(fn)
        self.assertTrue(fn(self.target.value))
        self.assertTrue(fn("www." + self.target.value))


class FindingScopeFiltersForTargetTest(BaseTestCase):
    """Tests for get_finding_scope_filters_for_target and _for_target helpers."""

    def setUp(self) -> None:
        super().setUp()
        self.data_generator.create_organization()
        self.data_generator.create_scope()
        self.scope = self.data_generator.scope
        self.target = self.data_generator.target

    def test_returns_dict_with_both_filters(self) -> None:
        result = get_finding_scope_filters_for_target(self.target.id)
        self.assertIn("domain_filter", result)
        self.assertIn("host_filter", result)

    def test_invalid_target_id_returns_none_filters(self) -> None:
        result = get_finding_scope_filters_for_target(999999)
        self.assertIsNone(result["domain_filter"])
        self.assertIsNone(result["host_filter"])

    def test_domain_for_target_returns_same_as_dict(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_domain_for_target(self.target.id)
        self.assertIsNotNone(fn)
        self.assertFalse(fn("192.168.1.1"))

    def test_host_for_target_returns_same_as_dict(self) -> None:
        self.scope.restrict_findings_to_target = True
        self.scope.save()
        fn = get_finding_scope_filter_host_for_target(self.target.id)
        self.assertIsNotNone(fn)
        self.assertTrue(fn("192.168.1.1"))
