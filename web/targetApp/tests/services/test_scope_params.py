from unittest.mock import patch
import uuid

from django.http import QueryDict
from django.test import override_settings

from scanEngine.models import SecatorProfile, SecatorWorker
from targetApp.services.scope_params import (
    PARAM_KEYS,
    TARGET_OVERRIDE_PREFIX,
    _build_allowed_hosts_set,
    _profiles_to_list,
    apply_resolved_to_secator_config,
    build_effective_params_display,
    build_effective_params_display_from_configs,
    flatten_profile_opts_into_config,
    get_allowed_workers_for_scope,
    get_default_worker_for_scope,
    get_scope_for_target,
    get_scope_worker_ids,
    get_scope_worker_validation,
    get_workers_for_scan_dropdown,
    normalize_allowed_hosts_from_list,
    parse_target_scan_override_from_post,
    resolve_profiles_for_runner,
    resolve_scan_params,
    strip_empty_override_keys,
)
from utils.test_base import BaseTestCase


class ResolveScanParamsTest(BaseTestCase):
    """Tests for resolve_scan_params helper."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    # ------------------------------------------------------------------
    # Target without scope, without override -> defaults from settings
    # ------------------------------------------------------------------
    def test_target_no_scope_no_override_returns_defaults(self):
        result = resolve_scan_params(self.data_generator.target)

        self.assertEqual(result["threads"], 30)
        self.assertEqual(result["rate_limit"], 150)
        self.assertEqual(result["timeout"], 5)
        self.assertEqual(result["retries"], 1)
        self.assertEqual(result["delay"], 0)
        self.assertFalse(result["follow_redirect"])
        self.assertIsNone(result["depth"])
        self.assertIsNone(result["proxy"])
        self.assertIsNone(result["user_agent"])
        self.assertIsNone(result["header"])
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["worker_ids"], [])
        self.assertEqual(result["extra_config"], {})

    # ------------------------------------------------------------------
    # Target with scan_config, without scope
    # ------------------------------------------------------------------
    def test_target_scan_config_applied(self):
        target = self.data_generator.target
        target.scan_config = {
            "threads": 10,
            "proxy": "socks5://10.0.0.1:1080",
            "user_agent": "TestAgent/1.0",
        }
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["threads"], 10)
        self.assertEqual(result["proxy"], "socks5://10.0.0.1:1080")
        self.assertEqual(result["user_agent"], "TestAgent/1.0")
        self.assertEqual(result["rate_limit"], 150)

    def test_scan_config_non_dict_normalized(self):
        """Legacy or malformed scan_config (list, string) is treated as empty dict."""
        target = self.data_generator.target
        target.scan_config = [1, 2, 3]
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["threads"], 30)
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["extra_config"], {})

    # ------------------------------------------------------------------
    # Target scan_config header
    # ------------------------------------------------------------------
    def test_target_scan_config_header(self):
        target = self.data_generator.target
        target.scan_config = {"header": {"Authorization": "Bearer test-token-0000"}}
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["header"], {"Authorization": "Bearer test-token-0000"})

    def test_scope_empty_header_does_not_override_organization(self):
        """
        When scope has header set to empty dict, resolved value is org's
        header, not {} (empty dict must not override parent config).
        """
        org_headers = {"User-Agent": "Mozilla/5.0"}
        self.data_generator.organization.scan_config = {"header": org_headers}
        self.data_generator.organization.save()

        scope = self.data_generator.create_scope(header={})

        result = resolve_scan_params(
            self.data_generator.target,
            scope=scope,
            organization=scope.organization,
        )

        self.assertEqual(result["header"], org_headers)

    def test_scope_empty_profiles_does_not_override_organization(self):
        """When scope has profiles set to empty dict, resolved value is org profiles, not []."""
        self.data_generator.organization.scan_config = {
            "profiles": {"speed": "polite", "evasion": "stealth"},
        }
        self.data_generator.organization.save()
        scope = self.data_generator.create_scope(default_profiles={})

        result = resolve_scan_params(
            self.data_generator.target,
            scope=scope,
            organization=scope.organization,
        )

        self.assertEqual(result["profiles"], ["polite", "stealth"])

    def test_scope_empty_extra_config_does_not_override_organization(self):
        """When scope has extra_config set to empty dict, resolved value is org extra_config."""
        self.data_generator.organization.scan_config = {
            "extra_config": {"wordlist": "/org/list.txt"},
        }
        self.data_generator.organization.save()
        scope = self.data_generator.create_scope(scan_config={"extra_config": {}})

        result = resolve_scan_params(
            self.data_generator.target,
            scope=scope,
            organization=scope.organization,
        )

        self.assertEqual(result["extra_config"], {"wordlist": "/org/list.txt"})

    def test_target_header_beat_scope_header(self):
        """
        When both target.scan_config and scope.scan_config have header,
        target takes precedence.
        """
        target_headers = {"X-From": "target", "X-Common": "target-value"}
        scope_headers = {"X-From": "scope", "X-Common": "scope-value"}

        target = self.data_generator.target
        target.scan_config = {"header": target_headers}
        target.save()
        scope = self.data_generator.create_scope(header=scope_headers)

        params = resolve_scan_params(target=target, scope=scope)

        self.assertEqual(
            params["header"],
            target_headers,
            msg="target scan_config header should override scope",
        )
        self.assertNotEqual(target_headers, scope_headers)

    # ------------------------------------------------------------------
    # Target with scope, scope params applied
    # ------------------------------------------------------------------
    def test_scope_params_applied(self):
        scope = self.data_generator.create_scope(
            threads=5,
            rate_limit=50,
            timeout=30,
            proxy="http://10.0.0.2:8080",
            user_agent="ScopeAgent/2.0",
        )

        result = resolve_scan_params(self.data_generator.target, scope=scope)

        self.assertEqual(result["threads"], 5)
        self.assertEqual(result["rate_limit"], 50)
        self.assertEqual(result["timeout"], 30)
        self.assertEqual(result["proxy"], "http://10.0.0.2:8080")
        self.assertEqual(result["user_agent"], "ScopeAgent/2.0")

    # ------------------------------------------------------------------
    # Target override takes precedence over scope
    # ------------------------------------------------------------------
    def test_target_override_beats_scope(self):
        target = self.data_generator.target
        target.scan_config = {"threads": 99}
        target.save()

        scope = self.data_generator.create_scope(threads=5, rate_limit=50)

        result = resolve_scan_params(target, scope=scope)

        self.assertEqual(result["threads"], 99)
        self.assertEqual(result["rate_limit"], 50)

    # ------------------------------------------------------------------
    # User override beats everything
    # ------------------------------------------------------------------
    def test_user_override_beats_all(self):
        target = self.data_generator.target
        target.scan_config = {"threads": 99}
        target.save()

        scope = self.data_generator.create_scope(threads=5)

        result = resolve_scan_params(
            target,
            scope=scope,
            user_override={"threads": 1, "proxy": "http://10.0.0.3:3128"},
        )

        self.assertEqual(result["threads"], 1)
        self.assertEqual(result["proxy"], "http://10.0.0.3:3128")

    # ------------------------------------------------------------------
    # Target in 2 scopes, explicit scope_id
    # ------------------------------------------------------------------
    def test_explicit_scope_used(self):
        scope_a = self.data_generator.create_scope(
            name="Scope A",
            threads=10,
            rate_limit=100,
        )
        scope_b = self.data_generator.create_scope(
            name="Scope B",
            threads=20,
            rate_limit=200,
        )
        target = self.data_generator.target
        scope_a.targets.add(target)
        scope_b.targets.add(target)

        result_a = resolve_scan_params(target, scope=scope_a)
        result_b = resolve_scan_params(target, scope=scope_b)

        self.assertEqual(result_a["threads"], 10)
        self.assertEqual(result_a["rate_limit"], 100)
        self.assertEqual(result_b["threads"], 20)
        self.assertEqual(result_b["rate_limit"], 200)

    # ------------------------------------------------------------------
    # Profiles resolution: scope dict format
    # ------------------------------------------------------------------
    def test_scope_default_profiles_dict_format(self):
        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite", "evasion": "stealth"},
        )

        result = resolve_scan_params(self.data_generator.target, scope=scope)

        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])
        self.assertEqual(len(result["profiles"]), 2)

    def test_scope_default_profiles_list_format_compat(self):
        """Legacy list format stored before migration to dict is still handled."""
        scope = self.data_generator.create_scope(
            default_profiles=["polite", "stealth"],
        )

        result = resolve_scan_params(self.data_generator.target, scope=scope)

        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])

    def test_target_scan_config_profiles_beats_scope(self):
        """Target overrides scope only for the same category; other categories are inherited."""
        target = self.data_generator.target
        target.scan_config = {"profiles": {"speed": "aggressive"}}
        target.save()

        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite", "evasion": "stealth"},
        )

        result = resolve_scan_params(target, scope=scope)

        self.assertIn("aggressive", result["profiles"])
        self.assertIn("stealth", result["profiles"])
        self.assertEqual(len(result["profiles"]), 2)

    def test_user_override_profiles_beat_target_and_scope(self):
        target = self.data_generator.target
        target.scan_config = {"profiles": {"speed": "aggressive"}}
        target.save()

        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite"},
        )

        result = resolve_scan_params(
            target,
            scope=scope,
            user_override={"profiles": ["insane"]},
        )

        self.assertEqual(result["profiles"], ["insane"])

    def test_no_profiles_returns_empty_list(self):
        result = resolve_scan_params(self.data_generator.target)
        self.assertEqual(result["profiles"], [])

    # ------------------------------------------------------------------
    # Extra config merge
    # ------------------------------------------------------------------
    def test_extra_config_merged(self):
        scope = self.data_generator.create_scope(
            extra_config={"wordlist": "/path/to/list.txt", "method": "GET"},
        )
        target = self.data_generator.target
        target.scan_config = {
            "extra_config": {"method": "POST"},
        }
        target.save()

        result = resolve_scan_params(target, scope=scope)

        self.assertEqual(result["extra_config"]["wordlist"], "/path/to/list.txt")
        self.assertEqual(result["extra_config"]["method"], "POST")

    def test_user_override_extra_config(self):
        scope = self.data_generator.create_scope(
            extra_config={"wordlist": "/path/to/list.txt"},
        )

        result = resolve_scan_params(
            self.data_generator.target,
            scope=scope,
            user_override={"extra_config": {"wordlist": "/other/list.txt"}},
        )

        self.assertEqual(result["extra_config"]["wordlist"], "/other/list.txt")

    def test_malformed_extra_config_values_are_ignored(self):
        scope = self.data_generator.create_scope(
            extra_config={"wordlist": "/valid/list.txt"},
        )
        result = resolve_scan_params(self.data_generator.target, scope=scope)
        self.assertEqual(result["extra_config"]["wordlist"], "/valid/list.txt")

        scope_malformed = self.data_generator.create_scope(
            name="ScopeMalformed",
            extra_config="not-a-dict",
        )
        result = resolve_scan_params(self.data_generator.target, scope=scope_malformed)
        self.assertIsInstance(result.get("extra_config"), dict)
        self.assertEqual(result["extra_config"], {})

        target = self.data_generator.target
        target.scan_config = {"extra_config": ["not-a-dict"]}
        target.save()
        scope = self.data_generator.create_scope(
            name="ScopeDict",
            extra_config={"wordlist": "/scope/list.txt"},
        )
        result = resolve_scan_params(target, scope=scope)
        self.assertEqual(result["extra_config"]["wordlist"], "/scope/list.txt")

        target.scan_config = {"extra_config": {"method": "POST"}}
        target.save()
        result = resolve_scan_params(
            target,
            scope=scope,
            user_override={"extra_config": "also-not-a-dict"},
        )
        self.assertEqual(result["extra_config"]["wordlist"], "/scope/list.txt")
        self.assertEqual(result["extra_config"]["method"], "POST")

    # ------------------------------------------------------------------
    # Null values in override are ignored
    # ------------------------------------------------------------------
    def test_none_in_override_falls_through(self):
        scope = self.data_generator.create_scope(threads=5)

        result = resolve_scan_params(
            self.data_generator.target,
            scope=scope,
            user_override={"threads": None},
        )

        self.assertEqual(result["threads"], 5)

    # ------------------------------------------------------------------
    # All PARAM_KEYS present in result
    # ------------------------------------------------------------------
    def test_all_param_keys_in_result(self):
        result = resolve_scan_params(self.data_generator.target)
        for key in PARAM_KEYS:
            self.assertIn(key, result)
        self.assertIn("profiles", result)
        self.assertIn("worker_ids", result)
        self.assertIn("extra_config", result)

    def test_scope_with_workers_returns_worker_ids(self):
        worker1 = SecatorWorker.objects.create(
            name="test-worker-scope-1",
            ssh_host="192.0.2.1",
            ssh_user="scan",
            deploy_path="/opt/secator",
            is_active=True,
        )
        worker2 = SecatorWorker.objects.create(
            name="test-worker-scope-2",
            ssh_host="192.0.2.2",
            ssh_user="scan",
            deploy_path="/opt/secator",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker1, worker2)

        result = resolve_scan_params(self.data_generator.target, scope=scope)

        self.assertEqual(set(result["worker_ids"]), {worker1.id, worker2.id})

    def test_scope_inactive_workers_excluded_from_worker_ids(self):
        """Only active workers linked to the scope are included in worker_ids."""
        active_worker = SecatorWorker.objects.create(
            name="test-worker-active",
            ssh_host="192.0.2.1",
            ssh_user="scan",
            deploy_path="/opt/secator",
            is_active=True,
        )
        inactive_worker = SecatorWorker.objects.create(
            name="test-worker-inactive",
            ssh_host="192.0.2.2",
            ssh_user="scan",
            deploy_path="/opt/secator",
            is_active=False,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(active_worker, inactive_worker)

        result = resolve_scan_params(self.data_generator.target, scope=scope)

        self.assertEqual(set(result["worker_ids"]), {active_worker.id})
        self.assertNotIn(inactive_worker.id, result["worker_ids"])

    # ------------------------------------------------------------------
    # Override settings defaults
    # ------------------------------------------------------------------
    @override_settings(DEFAULT_THREADS=42, DEFAULT_RATE_LIMIT=999)
    def test_custom_settings_defaults(self):
        result = resolve_scan_params(self.data_generator.target)
        self.assertEqual(result["threads"], 42)
        self.assertEqual(result["rate_limit"], 999)


class ResolveProfilesForRunnerTest(BaseTestCase):
    """Tests for resolve_profiles_for_runner: built-in -> inline dict, custom -> name."""

    def test_empty_returns_empty(self):
        self.assertEqual(resolve_profiles_for_runner([]), [])

    def test_unknown_profile_returns_name(self):
        result = resolve_profiles_for_runner(["nonexistent-profile-xyz"])
        self.assertEqual(result, ["nonexistent-profile-xyz"])

    def test_custom_profile_returns_name(self):
        name = "test-custom-runner-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=name,
            category="speed",
            description="Custom",
            opts="rate_limit: 50\n",
            profile_type="custom",
            is_active=True,
        )
        result = resolve_profiles_for_runner([name])
        self.assertEqual(result, [name])

    def test_builtin_profile_returns_inline_dict(self):
        name = "test-builtin-runner-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=name,
            category="speed",
            description="Built-in for test",
            opts="rate_limit: 100\ndelay: 0\n",
            profile_type="builtin",
            is_active=True,
        )
        result = resolve_profiles_for_runner([name])
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], dict)
        self.assertEqual(result[0]["type"], "profile")
        self.assertEqual(result[0]["name"], name)
        self.assertEqual(result[0]["category"], "speed")
        self.assertEqual(result[0]["opts"]["rate_limit"], 100)
        self.assertEqual(result[0]["opts"]["delay"], 0)

    def test_mixed_builtin_and_custom_returns_mixed_list(self):
        custom_name = "test-custom-mix-%s" % (str(uuid.uuid4())[:8],)
        builtin_name = "test-builtin-mix-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=custom_name,
            category="speed",
            description="Custom",
            opts="threads: 4\n",
            profile_type="custom",
            is_active=True,
        )
        SecatorProfile.objects.create(
            name=builtin_name,
            category="evasion",
            description="Built-in",
            opts="delay: 1\n",
            profile_type="builtin",
            is_active=True,
        )
        result = resolve_profiles_for_runner([custom_name, builtin_name])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], custom_name)
        self.assertIsInstance(result[1], dict)
        self.assertEqual(result[1]["name"], builtin_name)
        self.assertEqual(result[1]["opts"]["delay"], 1)


class ApplyResolvedToSecatorConfigTest(BaseTestCase):
    """Tests for apply_resolved_to_secator_config."""

    def test_empty_header_in_resolved_does_not_overwrite_existing(self):
        """When resolved has header {}, existing secator_config is not overwritten."""
        secator_config = {"header": {"User-Agent": "Mozilla/5.0"}}
        resolved = {"header": {}}

        apply_resolved_to_secator_config(secator_config, resolved)

        self.assertEqual(secator_config["header"], {"User-Agent": "Mozilla/5.0"})

    def test_empty_extra_config_in_resolved_does_not_overwrite_existing(self):
        """When resolved has extra_config {}, existing secator_config is not overwritten."""
        secator_config = {"extra_config": {"custom": "value"}}
        resolved = {"extra_config": {}}

        apply_resolved_to_secator_config(secator_config, resolved)

        self.assertEqual(secator_config["extra_config"], {"custom": "value"})


class FlattenProfileOptsIntoConfigTest(BaseTestCase):
    """Tests for flatten_profile_opts_into_config."""

    def test_profile_opts_merged_into_config(self):
        """Profile opts (threads, rate_limit, etc.) are merged into config in place."""
        name = "test-flatten-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=name,
            category="speed",
            description="Test",
            opts="threads: 4\nrate_limit: 100\ndelay: 0.5\n",
            profile_type="custom",
            is_active=True,
        )
        config = {"profiles": [name], "threads": 30, "rate_limit": 150}
        flatten_profile_opts_into_config(config)
        self.assertEqual(config["threads"], 4)
        self.assertEqual(config["rate_limit"], 100)
        self.assertEqual(config["delay"], 0.5)
        self.assertEqual(config["profiles"], [name])

    def test_profiles_dict_format_supported(self):
        """profiles as category dict is supported via _profiles_to_list."""
        name = "test-flatten-dict-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=name,
            category="speed",
            description="Test",
            opts="threads: 20\n",
            profile_type="custom",
            is_active=True,
        )
        config = {"profiles": {"speed": name}, "threads": 30}
        flatten_profile_opts_into_config(config)
        self.assertEqual(config["threads"], 20)

    def test_empty_profiles_leaves_config_unchanged(self):
        config = {"threads": 30, "rate_limit": 150}
        flatten_profile_opts_into_config(config)
        self.assertEqual(config["threads"], 30)
        self.assertEqual(config["rate_limit"], 150)

    def test_no_profiles_key_leaves_config_unchanged(self):
        config = {"threads": 30}
        flatten_profile_opts_into_config(config)
        self.assertEqual(config["threads"], 30)


class ProfilesToListTest(BaseTestCase):
    """Tests for _profiles_to_list helper."""

    def test_dict_format_returns_values(self):
        result = _profiles_to_list({"speed": "polite", "evasion": "stealth"})
        self.assertIn("polite", result)
        self.assertIn("stealth", result)
        self.assertEqual(len(result), 2)

    def test_list_format_passthrough(self):
        result = _profiles_to_list(["polite", "stealth"])
        self.assertEqual(result, ["polite", "stealth"])

    def test_none_returns_empty(self):
        result = _profiles_to_list(None)
        self.assertEqual(result, [])

    def test_empty_dict_returns_empty(self):
        result = _profiles_to_list({})
        self.assertEqual(result, [])

    def test_empty_list_returns_empty(self):
        result = _profiles_to_list([])
        self.assertEqual(result, [])

    def test_dict_ignores_unknown_categories(self):
        result = _profiles_to_list({"speed": "polite", "unknown_cat": "ignored"})
        self.assertEqual(result, ["polite"])

    def test_invalid_type_returns_empty(self):
        result = _profiles_to_list("polite")
        self.assertEqual(result, [])


class BuildEffectiveParamsDisplayTest(BaseTestCase):
    """Tests for build_effective_params_display helper."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_no_scope_no_target_returns_defaults(self):
        result = build_effective_params_display()
        self.assertEqual(result["threads"]["source"], "default")
        self.assertEqual(result["threads"]["value"], 30)

    def test_scope_param_shows_scope_source(self):
        scope = self.data_generator.create_scope(threads=5, proxy="http://10.0.0.2:8080")
        result = build_effective_params_display(scope=scope)
        self.assertEqual(result["threads"]["source"], "scope")
        self.assertEqual(result["threads"]["value"], 5)
        self.assertEqual(result["proxy"]["source"], "scope")
        self.assertEqual(result["proxy"]["value"], "http://10.0.0.2:8080")

    def test_target_override_takes_precedence_over_scope(self):
        scope = self.data_generator.create_scope(threads=5)
        target = self.data_generator.target
        target.scan_config = {"threads": 99}
        target.save()

        result = build_effective_params_display(scope=scope, target=target)

        self.assertEqual(result["threads"]["source"], "target")
        self.assertEqual(result["threads"]["value"], 99)

    def test_profiles_source_from_scope(self):
        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite"},
        )
        result = build_effective_params_display(scope=scope)
        self.assertEqual(result["profiles"]["source"], "scope")
        self.assertEqual(result["profiles"]["value"], {"speed": "polite"})

    def test_profiles_source_from_target(self):
        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite"},
        )
        target = self.data_generator.target
        target.scan_config = {"profiles": {"speed": "aggressive"}}
        target.save()

        result = build_effective_params_display(scope=scope, target=target)

        self.assertEqual(result["profiles"]["source"], "target")
        self.assertEqual(result["profiles"]["value"], {"speed": "aggressive"})

    def test_profiles_source_default_when_none(self):
        result = build_effective_params_display()
        self.assertEqual(result["profiles"]["source"], "default")
        self.assertIsNone(result["profiles"]["value"])

    @override_settings(DEFAULT_DELAY=2.5, DEFAULT_FOLLOW_REDIRECT=True)
    def test_display_reflects_settings_defaults(self):
        result = build_effective_params_display()
        self.assertEqual(result["delay"]["value"], 2.5)
        self.assertEqual(result["delay"]["source"], "default")
        self.assertIs(result["follow_redirect"]["value"], True)
        self.assertEqual(result["follow_redirect"]["source"], "default")

    def test_worker_display_default_when_no_scope(self):
        result = build_effective_params_display()
        self.assertIn("worker", result)
        self.assertEqual(result["worker"]["value"], "Local")
        self.assertEqual(result["worker"]["source"], "default")


class BuildEffectiveParamsDisplayFromConfigsTest(BaseTestCase):
    """Tests for build_effective_params_display_from_configs (draft + parent configs)."""

    def test_organization_only_draft(self):
        result = build_effective_params_display_from_configs(
            org_config={"threads": 8, "rate_limit": 100},
        )
        self.assertEqual(result["threads"]["value"], 8)
        self.assertEqual(result["threads"]["source"], "organization")
        self.assertEqual(result["rate_limit"]["value"], 100)
        self.assertEqual(result["rate_limit"]["source"], "organization")
        self.assertEqual(result["timeout"]["source"], "default")
        self.assertIn("worker", result)
        self.assertEqual(result["worker"]["value"], "Local")
        self.assertEqual(result["worker"]["source"], "default")

    def test_user_override_source_scan(self):
        result = build_effective_params_display_from_configs(
            org_config={"threads": 5},
            user_override={"threads": 20},
        )
        self.assertEqual(result["threads"]["value"], 20)
        self.assertEqual(result["threads"]["source"], "scan")

    def test_priority_override_over_target_over_scope_over_org(self):
        result = build_effective_params_display_from_configs(
            org_config={"threads": 1},
            scope_config={"threads": 2},
            target_config={"threads": 3},
            user_override={"threads": 4},
        )
        self.assertEqual(result["threads"]["value"], 4)
        self.assertEqual(result["threads"]["source"], "scan")

        result = build_effective_params_display_from_configs(
            org_config={"threads": 1},
            scope_config={"threads": 2},
            target_config={"threads": 3},
        )
        self.assertEqual(result["threads"]["value"], 3)
        self.assertEqual(result["threads"]["source"], "target")

    def test_profiles_user_override_source_scan(self):
        result = build_effective_params_display_from_configs(
            org_config={"profiles": {"speed": "polite"}},
            user_override={"profiles": {"speed": "aggressive", "evasion": "stealth"}},
        )
        self.assertEqual(result["profiles"]["source"], "scan")
        self.assertEqual(result["profiles"]["value"], {"speed": "aggressive", "evasion": "stealth"})

    def test_profile_opts_merged_into_effective_display(self):
        """Effective display overlays profile opts for params that would be default."""
        profile_name = "test-profile-opts-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=profile_name,
            category="speed",
            description="Profile with opts for effective display",
            opts="delay: 0.5\nthreads: 6\n",
            profile_type="custom",
            is_active=True,
        )
        result = build_effective_params_display_from_configs(
            user_override={"profiles": {"speed": profile_name}},
        )
        self.assertEqual(result["delay"]["value"], 0.5)
        self.assertEqual(result["delay"]["source"], "profile")
        self.assertEqual(result["delay"].get("profile_name"), profile_name)
        self.assertEqual(result["threads"]["value"], 6)
        self.assertEqual(result["threads"]["source"], "profile")
        self.assertEqual(result["threads"].get("profile_name"), profile_name)
        self.assertIn("profile_display_list", result)
        self.assertEqual(len(result["profile_display_list"]), 1)
        self.assertEqual(result["profile_display_list"][0]["category"], "speed")
        self.assertEqual(result["profile_display_list"][0]["name"], profile_name)
        self.assertIn("delay", result["profile_display_list"][0]["tooltip"])
        self.assertIn("threads", result["profile_display_list"][0]["tooltip"])

    def test_profile_opts_override_org_scope_target_when_no_scan_override(self):
        """Profile opts override target/scope/org for params the profile defines, when not set at scan."""
        profile_name = "test-profile-no-override-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=profile_name,
            category="speed",
            description="Profile with opts",
            opts="threads: 99\ndelay: 2.0\n",
            profile_type="custom",
            is_active=True,
        )
        result = build_effective_params_display_from_configs(
            org_config={"threads": 10},
            user_override={"profiles": {"speed": profile_name}},
        )
        self.assertEqual(result["threads"]["value"], 99)
        self.assertEqual(result["threads"]["source"], "profile")
        self.assertEqual(result["delay"]["value"], 2.0)
        self.assertEqual(result["delay"]["source"], "profile")

    def test_profile_opts_do_not_override_explicit_scan_param(self):
        """Profile opts do not override when user explicitly sets the param at scan level."""
        profile_name = "test-profile-scan-override-%s" % (str(uuid.uuid4())[:8],)
        SecatorProfile.objects.create(
            name=profile_name,
            category="speed",
            description="Profile with opts",
            opts="threads: 99\ndelay: 2.0\n",
            profile_type="custom",
            is_active=True,
        )
        result = build_effective_params_display_from_configs(
            org_config={"threads": 10},
            user_override={"profiles": {"speed": profile_name}, "threads": 5},
        )
        self.assertEqual(result["threads"]["value"], 5)
        self.assertEqual(result["threads"]["source"], "scan")
        self.assertEqual(result["delay"]["value"], 2.0)
        self.assertEqual(result["delay"]["source"], "profile")

    def test_profile_display_list_empty_when_no_profiles(self):
        result = build_effective_params_display_from_configs(user_override={})
        self.assertEqual(result["profile_display_list"], [])

    def test_profile_opts_full_yaml_with_nested_opts_key(self):
        """When SecatorProfile.opts stores full YAML with top-level 'opts:', inner opts are applied."""
        profile_name = "test-full-yaml-%s" % (str(uuid.uuid4())[:8],)
        full_yaml = (
            "type: profile\n"
            "name: %s\n"
            "category: speed\n"
            "description: Full file format\n"
            "opts:\n"
            "  rate_limit: 100\n"
            "  delay: 0\n"
            "  timeout: 10\n"
            "  retries: 5\n"
        ) % (profile_name,)
        SecatorProfile.objects.create(
            name=profile_name,
            category="speed",
            description="Full file format",
            opts=full_yaml,
            profile_type="custom",
            is_active=True,
        )
        result = build_effective_params_display_from_configs(
            user_override={"profiles": {"speed": profile_name}},
        )
        self.assertEqual(result["rate_limit"]["value"], 100)
        self.assertEqual(result["rate_limit"]["source"], "profile")
        self.assertEqual(result["rate_limit"].get("profile_name"), profile_name)
        self.assertEqual(result["delay"]["value"], 0)
        self.assertEqual(result["delay"]["source"], "profile")
        self.assertEqual(result["delay"].get("profile_name"), profile_name)
        self.assertEqual(result["timeout"]["value"], 10)
        self.assertEqual(result["timeout"]["source"], "profile")
        self.assertEqual(result["retries"]["value"], 5)
        self.assertEqual(result["retries"]["source"], "profile")
        self.assertEqual(result["retries"].get("profile_name"), profile_name)
        self.assertEqual(len(result["profile_display_list"]), 1)
        self.assertIn("rate_limit", result["profile_display_list"][0]["tooltip"])
        self.assertIn("retries", result["profile_display_list"][0]["tooltip"])


class ParseTargetScanOverrideFromPostTest(BaseTestCase):
    """Tests for parse_target_scan_override_from_post."""

    def test_empty_post_returns_empty_dict_and_no_errors(self):
        post = QueryDict("", mutable=True)
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result, {})
        self.assertEqual(errors, [])

    def test_int_params_parsed(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}threads"] = "10"
        post[f"{TARGET_OVERRIDE_PREFIX}rate_limit"] = "50"
        post[f"{TARGET_OVERRIDE_PREFIX}timeout"] = "30"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["threads"], 10)
        self.assertEqual(result["rate_limit"], 50)
        self.assertEqual(result["timeout"], 30)
        self.assertEqual(errors, [])

    def test_invalid_int_omitted(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}threads"] = "not_a_number"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("threads", result)
        self.assertEqual(errors, [])

    def test_str_params_parsed(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}proxy"] = "http://127.0.0.1:8080"
        post[f"{TARGET_OVERRIDE_PREFIX}user_agent"] = "Custom/1.0"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["proxy"], "http://127.0.0.1:8080")
        self.assertEqual(result["user_agent"], "Custom/1.0")
        self.assertEqual(errors, [])

    def test_delay_float_parsed(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}delay"] = "1.5"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["delay"], 1.5)
        self.assertEqual(errors, [])

    def test_delay_invalid_float_values_ignored(self):
        invalid_values = ["abc", "1.2.3", "", " "]
        for value in invalid_values:
            with self.subTest(value=value):
                post = QueryDict("", mutable=True)
                post[f"{TARGET_OVERRIDE_PREFIX}delay"] = value
                result, errors = parse_target_scan_override_from_post(post)
                self.assertNotIn("delay", result)
                self.assertEqual(errors, [])

    def test_follow_redirect_boolean(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}follow_redirect"] = "True"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertIs(result["follow_redirect"], True)
        self.assertEqual(errors, [])
        post[f"{TARGET_OVERRIDE_PREFIX}follow_redirect"] = "False"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertIs(result["follow_redirect"], False)

    def test_header_empty_string_omits_key(self):
        """When header field is present but empty, result must not contain 'header' (no {} stored)."""
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = ""
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("header", result)
        self.assertEqual(errors, [])

    def test_header_valid_json(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = '{"X-Api-Key": "secret"}'
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["header"], {"X-Api-Key": "secret"})
        self.assertEqual(errors, [])

    def test_header_multiline_format(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = '"X-Api-Key": "secret"\n"Cookie": "session=abc"'
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["header"], {"X-Api-Key": "secret", "Cookie": "session=abc"})
        self.assertEqual(errors, [])

    def test_header_invalid_json_omitted_and_error_added(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = "not json"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("header", result)
        self.assertEqual(len(errors), 1)
        self.assertTrue(
            "Invalid JSON" in errors[0] or "Invalid header" in errors[0],
            "Expected invalid header or JSON message, got: %s" % (errors[0],),
        )

    def test_header_non_dict_json_adds_error(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = "[1, 2, 3]"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("header", result)
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_header_invalid_json_preserves_existing_override(self):
        """On invalid header input, existing header are kept and an error is returned."""
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = "not json"
        pre_existing_override = {"header": {"X-Api-Key": "secret"}}
        result, errors = parse_target_scan_override_from_post(post, existing_override=pre_existing_override)
        self.assertEqual(result.get("header"), {"X-Api-Key": "secret"})
        self.assertEqual(len(errors), 1)
        self.assertTrue(
            "Invalid JSON" in errors[0] or "Invalid header" in errors[0],
            "Expected invalid header or JSON message, got: %s" % (errors[0],),
        )

    def test_header_non_dict_json_preserves_existing_override(self):
        """On valid JSON that is not an object, existing header are kept and an error is returned."""
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = "[1, 2, 3]"
        pre_existing_override = {"header": {"X-Api-Key": "secret"}}
        result, errors = parse_target_scan_override_from_post(post, existing_override=pre_existing_override)
        self.assertEqual(result.get("header"), {"X-Api-Key": "secret"})
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_header_non_dict_json_no_existing_override(self):
        """
        When header JSON is valid but not an object (e.g. array) and there is
        no existing override, header must not be set and an error must be returned.
        """
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}header"] = "[1, 2, 3]"
        result, errors = parse_target_scan_override_from_post(post, existing_override=None)
        self.assertNotIn("header", result)
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_profiles_dict_included_when_passed(self):
        post = QueryDict("", mutable=True)
        profiles = {"speed": "polite", "evasion": "stealth"}
        result, errors = parse_target_scan_override_from_post(post, profiles_dict=profiles)
        self.assertEqual(result["profiles"], profiles)
        self.assertEqual(errors, [])

    def test_profiles_empty_dict_omits_key(self):
        """When profiles_dict is {} or all values empty, result must not contain 'profiles'."""
        post = QueryDict("", mutable=True)
        result, errors = parse_target_scan_override_from_post(post, profiles_dict={})
        self.assertNotIn("profiles", result)
        self.assertEqual(errors, [])

        result2, errors2 = parse_target_scan_override_from_post(post, profiles_dict={"speed": "", "evasion": "  "})
        self.assertNotIn("profiles", result2)
        self.assertEqual(errors2, [])

    def test_empty_values_omitted(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}threads"] = "  "
        post[f"{TARGET_OVERRIDE_PREFIX}proxy"] = ""
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("threads", result)
        self.assertNotIn("proxy", result)
        self.assertEqual(errors, [])

    def test_clearing_override_field_removes_key(self):
        """Submitting an empty value for a param removes it from the override (revert to default)."""
        existing_override = {"threads": 10, "proxy": "http://127.0.0.1:8080"}
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}threads"] = ""
        post[f"{TARGET_OVERRIDE_PREFIX}proxy"] = "   "
        result, errors = parse_target_scan_override_from_post(post, existing_override=existing_override)
        self.assertNotIn("threads", result)
        self.assertNotIn("proxy", result)
        self.assertEqual(errors, [])


class StripEmptyOverrideKeysTest(BaseTestCase):
    """Tests for strip_empty_override_keys."""

    def test_strip_removes_empty_dict_keys_keeps_scalars(self):
        """Empty header, profiles, extra_config are removed; threads and other scalars kept."""
        config = {
            "header": {},
            "profiles": {},
            "extra_config": {},
            "threads": 10,
            "proxy": "http://127.0.0.1:8080",
        }
        result = strip_empty_override_keys(config)
        self.assertNotIn("header", result)
        self.assertNotIn("profiles", result)
        self.assertNotIn("extra_config", result)
        self.assertEqual(result["threads"], 10)
        self.assertEqual(result["proxy"], "http://127.0.0.1:8080")

    def test_strip_profiles_all_empty_omits_key(self):
        """Profiles dict with only empty/whitespace values is treated as empty and removed."""
        config = {"profiles": {"speed": "", "evasion": "  "}, "threads": 5}
        result = strip_empty_override_keys(config)
        self.assertNotIn("profiles", result)
        self.assertEqual(result["threads"], 5)

    def test_strip_leaves_non_empty_dicts(self):
        """Non-empty header, profiles, extra_config are left unchanged."""
        config = {
            "header": {"X-Api-Key": "secret"},
            "profiles": {"speed": "aggressive"},
            "extra_config": {"wordlist": "/path.txt"},
            "threads": 1,
        }
        result = strip_empty_override_keys(config)
        self.assertEqual(result["header"], {"X-Api-Key": "secret"})
        self.assertEqual(result["profiles"], {"speed": "aggressive"})
        self.assertEqual(result["extra_config"], {"wordlist": "/path.txt"})
        self.assertEqual(result["threads"], 1)


class NormalizeAllowedHostsTest(BaseTestCase):
    """Tests for normalize_allowed_hosts_from_list and _build_allowed_hosts_set."""

    def test_normalize_empty_list_returns_empty(self):
        self.assertEqual(normalize_allowed_hosts_from_list([]), [])

    def test_normalize_none_returns_empty(self):
        self.assertEqual(normalize_allowed_hosts_from_list(None), [])

    def test_normalize_non_list_returns_empty(self):
        self.assertEqual(normalize_allowed_hosts_from_list("single string"), [])
        self.assertEqual(normalize_allowed_hosts_from_list({"key": "value"}), [])

    def test_normalize_strips_lower_dedupe(self):
        result = normalize_allowed_hosts_from_list(["  Host.Example.COM  ", "host.example.com", "other.com"])
        self.assertEqual(result, ["host.example.com", "other.com"])

    def test_normalize_skips_non_strings_and_empty(self):
        result = normalize_allowed_hosts_from_list(["valid.com", 123, None, "", "  ", "another.com"])
        self.assertEqual(result, ["valid.com", "another.com"])

    def test_build_allowed_hosts_set_none_scope_returns_empty(self):
        self.assertEqual(_build_allowed_hosts_set(None), set())

    def test_build_allowed_hosts_set_non_list_allowed_finding_hosts_returns_empty(self):
        scope = type("Scope", (), {"allowed_finding_hosts": "not a list"})()
        self.assertEqual(_build_allowed_hosts_set(scope), set())
        scope_dict = type("Scope", (), {"allowed_finding_hosts": {"a": 1}})()
        self.assertEqual(_build_allowed_hosts_set(scope_dict), set())


class GetScopeForTargetTest(BaseTestCase):
    """Tests for get_scope_for_target helper."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_none_target_returns_none(self):
        self.assertIsNone(get_scope_for_target(None))

    def test_target_with_no_scopes_returns_none(self):
        target = self.data_generator.target
        target.scopes.clear()
        self.assertIsNone(get_scope_for_target(target))

    def test_target_with_one_scope_returns_that_scope(self):
        target = self.data_generator.target
        scope = self.data_generator.create_scope(name="Single scope")
        result = get_scope_for_target(target)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, scope.id)

    def test_target_with_multiple_scopes_returns_first_by_id_and_logs_warning(self):
        scope_a = self.data_generator.create_scope(name="Scope A")
        scope_b = self.data_generator.create_scope(name="Scope B")
        target = self.data_generator.target
        scope_a.targets.add(target)
        scope_b.targets.add(target)
        with patch("targetApp.services.scope_params.logger") as mock_logger:
            result = get_scope_for_target(target)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, min(scope_a.id, scope_b.id))
        mock_logger.log_line.assert_called()
        call_args = mock_logger.log_line.call_args
        self.assertIn("multiple scopes", call_args[0][2])


class GetScopeWorkerIdsTest(BaseTestCase):
    """Tests for get_scope_worker_ids helper."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_none_scope_returns_empty(self):
        self.assertEqual(get_scope_worker_ids(None), [])

    def test_scope_with_no_workers_returns_empty(self):
        scope = self.data_generator.create_scope()
        self.assertEqual(get_scope_worker_ids(scope), [])

    def test_scope_with_workers_returns_active_ids(self):
        worker1 = SecatorWorker.objects.create(
            name="w1",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        worker2 = SecatorWorker.objects.create(
            name="w2",
            ssh_host="192.0.2.2",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker1, worker2)
        result = get_scope_worker_ids(scope)
        self.assertEqual(set(result), {worker1.id, worker2.id})


class GetWorkersForScanDropdownTest(BaseTestCase):
    """Tests for get_workers_for_scan_dropdown helper."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_no_scope_no_allowed_returns_all_active_workers(self):
        worker = SecatorWorker.objects.create(
            name="standalone-worker",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        result = get_workers_for_scan_dropdown()
        ids = [w.id for w in result]
        self.assertIn(worker.id, ids)
        self.assertEqual([w.name for w in result], sorted([w.name for w in result]))

    def test_scope_with_workers_returns_scope_workers_ordered_by_name(self):
        worker_a = SecatorWorker.objects.create(
            name="worker-a",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        worker_b = SecatorWorker.objects.create(
            name="worker-b",
            ssh_host="192.0.2.2",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker_b, worker_a)
        result = get_workers_for_scan_dropdown(scope=scope)
        self.assertEqual([w.id for w in result], [worker_a.id, worker_b.id])
        self.assertEqual([w.name for w in result], ["worker-a", "worker-b"])

    def test_scope_with_no_workers_returns_empty(self):
        scope = self.data_generator.create_scope()
        result = get_workers_for_scan_dropdown(scope=scope)
        self.assertEqual(result, [])

    def test_allowed_worker_ids_empty_returns_empty(self):
        result = get_workers_for_scan_dropdown(allowed_worker_ids=[])
        self.assertEqual(result, [])

    def test_allowed_worker_ids_filters_and_orders(self):
        worker1 = SecatorWorker.objects.create(
            name="z-worker",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        worker2 = SecatorWorker.objects.create(
            name="a-worker",
            ssh_host="192.0.2.2",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        result = get_workers_for_scan_dropdown(allowed_worker_ids=[worker1.id, worker2.id])
        self.assertEqual([w.name for w in result], ["a-worker", "z-worker"])
        self.assertEqual(set(w.id for w in result), {worker1.id, worker2.id})


class GetAllowedWorkersForScopeTest(BaseTestCase):
    """Tests for get_allowed_workers_for_scope."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_none_scope_returns_local_only(self):
        result = get_allowed_workers_for_scope(None)
        self.assertEqual(result, [(None, "Local")])

    def test_scope_allow_local_no_workers_returns_local_only(self):
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = True
        scope.save()
        result = get_allowed_workers_for_scope(scope)
        self.assertEqual(result, [(None, "Local")])

    def test_scope_disallow_local_no_workers_returns_local_fallback(self):
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = False
        scope.save()
        result = get_allowed_workers_for_scope(scope)
        self.assertEqual(result, [(None, "Local")])

    def test_scope_allow_local_with_one_worker_returns_local_and_worker(self):
        worker = SecatorWorker.objects.create(
            name="remote-1",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker)
        result = get_allowed_workers_for_scope(scope)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], (None, "Local"))
        self.assertEqual(result[1][0], worker.id)
        self.assertEqual(result[1][1], worker.name)

    def test_scope_disallow_local_with_one_worker_returns_worker_only(self):
        worker = SecatorWorker.objects.create(
            name="remote-1",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = False
        scope.save()
        scope.workers.add(worker)
        result = get_allowed_workers_for_scope(scope)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], worker.id)
        self.assertEqual(result[0][1], worker.name)


class GetDefaultWorkerForScopeTest(BaseTestCase):
    """Tests for get_default_worker_for_scope."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_none_scope_returns_none(self):
        self.assertIsNone(get_default_worker_for_scope(None))

    def test_scope_one_option_local_returns_none(self):
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = True
        scope.save()
        self.assertIsNone(get_default_worker_for_scope(scope))

    def test_scope_one_option_remote_returns_worker_id(self):
        worker = SecatorWorker.objects.create(
            name="only-remote",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = False
        scope.save()
        scope.workers.add(worker)
        self.assertEqual(get_default_worker_for_scope(scope), worker.id)

    def test_scope_two_options_no_default_returns_none(self):
        worker = SecatorWorker.objects.create(
            name="w1",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker)
        scope.default_worker = None
        scope.save()
        result = get_default_worker_for_scope(scope)
        self.assertIsNone(result)

    def test_scope_two_options_with_default_returns_worker_id(self):
        worker = SecatorWorker.objects.create(
            name="default-w",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.workers.add(worker)
        scope.default_worker = worker
        scope.save()
        self.assertEqual(get_default_worker_for_scope(scope), worker.id)


class GetScopeWorkerValidationTest(BaseTestCase):
    """Tests for get_scope_worker_validation."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_none_scope_returns_allow_local_true_empty_ids(self):
        result = get_scope_worker_validation(None)
        self.assertEqual(result["allow_local"], True)
        self.assertEqual(result["worker_ids"], [])

    def test_scope_allow_local_no_workers(self):
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = True
        scope.save()
        result = get_scope_worker_validation(scope)
        self.assertEqual(result["allow_local"], True)
        self.assertEqual(result["worker_ids"], [])

    def test_scope_disallow_local_with_workers(self):
        worker = SecatorWorker.objects.create(
            name="w1",
            ssh_host="192.0.2.1",
            ssh_user="u",
            deploy_path="/opt/s",
            is_active=True,
        )
        scope = self.data_generator.create_scope()
        scope.allow_local_worker = False
        scope.save()
        scope.workers.add(worker)
        result = get_scope_worker_validation(scope)
        self.assertEqual(result["allow_local"], False)
        self.assertEqual(result["worker_ids"], [worker.id])
