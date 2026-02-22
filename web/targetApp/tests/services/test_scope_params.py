from django.http import QueryDict
from django.test import override_settings

from scanEngine.models import SecatorWorker
from targetApp.services.scope_params import (
    PARAM_KEYS,
    TARGET_OVERRIDE_PREFIX,
    _profiles_to_list,
    build_effective_params_display,
    parse_target_scan_override_from_post,
    resolve_scan_params,
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
        self.assertIsNone(result["request_headers"])
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["worker_ids"], [])
        self.assertEqual(result["extra_config"], {})

    # ------------------------------------------------------------------
    # Target with scan_config_override, without scope
    # ------------------------------------------------------------------
    def test_target_scan_config_override_applied(self):
        target = self.data_generator.target
        target.scan_config_override = {
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

    def test_scan_config_override_non_dict_normalized(self):
        """Legacy or malformed scan_config_override (list, string) is treated as empty dict."""
        target = self.data_generator.target
        target.scan_config_override = [1, 2, 3]
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["threads"], 30)
        self.assertEqual(result["profiles"], [])
        self.assertEqual(result["extra_config"], {})

    # ------------------------------------------------------------------
    # Target.request_headers historical compat
    # ------------------------------------------------------------------
    def test_target_request_headers_historical_compat(self):
        target = self.data_generator.target
        target.request_headers = {"Authorization": "Bearer test-token-0000"}
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["request_headers"], {"Authorization": "Bearer test-token-0000"})

    def test_scan_config_override_request_headers_takes_priority(self):
        target = self.data_generator.target
        target.request_headers = {"Authorization": "Bearer old-token"}
        target.scan_config_override = {
            "request_headers": {"X-Custom": "override-value"},
        }
        target.save()

        result = resolve_scan_params(target)

        self.assertEqual(result["request_headers"], {"X-Custom": "override-value"})

    def test_target_request_headers_beat_scope_request_headers(self):
        """
        When both target.request_headers and scope.request_headers are set,
        target.request_headers must take precedence (historical behavior).
        """
        target_headers = {"X-From": "target", "X-Common": "target-value"}
        scope_headers = {"X-From": "scope", "X-Common": "scope-value"}

        target = self.data_generator.target
        target.request_headers = target_headers
        target.save()
        scope = self.data_generator.create_scope(request_headers=scope_headers)

        params = resolve_scan_params(target=target, scope=scope)

        self.assertEqual(
            params["request_headers"],
            target_headers,
            msg="target.request_headers should override scope.request_headers",
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
        target.scan_config_override = {"threads": 99}
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
        target.scan_config_override = {"threads": 99}
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

    def test_target_scan_config_override_profiles_beats_scope(self):
        """Target.scan_config_override["profiles"] (level 2) overrides scope defaults."""
        target = self.data_generator.target
        target.scan_config_override = {"profiles": {"speed": "aggressive"}}
        target.save()

        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite", "evasion": "stealth"},
        )

        result = resolve_scan_params(target, scope=scope)

        self.assertEqual(result["profiles"], ["aggressive"])

    def test_user_override_profiles_beat_target_and_scope(self):
        target = self.data_generator.target
        target.scan_config_override = {"profiles": {"speed": "aggressive"}}
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
        target.scan_config_override = {
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
        target.scan_config_override = {"extra_config": ["not-a-dict"]}
        target.save()
        scope = self.data_generator.create_scope(
            name="ScopeDict",
            extra_config={"wordlist": "/scope/list.txt"},
        )
        result = resolve_scan_params(target, scope=scope)
        self.assertEqual(result["extra_config"]["wordlist"], "/scope/list.txt")

        target.scan_config_override = {"extra_config": {"method": "POST"}}
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
        target.scan_config_override = {"threads": 99}
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
        target.scan_config_override = {"profiles": {"speed": "aggressive"}}
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

    def test_request_headers_valid_json(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = '{"X-Api-Key": "secret"}'
        result, errors = parse_target_scan_override_from_post(post)
        self.assertEqual(result["request_headers"], {"X-Api-Key": "secret"})
        self.assertEqual(errors, [])

    def test_request_headers_invalid_json_omitted_and_error_added(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = "not json"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("request_headers", result)
        self.assertEqual(len(errors), 1)
        self.assertIn("Invalid JSON", errors[0])

    def test_request_headers_non_dict_json_adds_error(self):
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = "[1, 2, 3]"
        result, errors = parse_target_scan_override_from_post(post)
        self.assertNotIn("request_headers", result)
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_request_headers_invalid_json_preserves_existing_override(self):
        """On invalid JSON, existing request_headers are kept and an error is returned."""
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = "not json"
        pre_existing_override = {"request_headers": {"X-Api-Key": "secret"}}
        result, errors = parse_target_scan_override_from_post(post, existing_override=pre_existing_override)
        self.assertEqual(result.get("request_headers"), {"X-Api-Key": "secret"})
        self.assertEqual(len(errors), 1)
        self.assertIn("Invalid JSON", errors[0])

    def test_request_headers_non_dict_json_preserves_existing_override(self):
        """On valid JSON that is not an object, existing request_headers are kept and an error is returned."""
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = "[1, 2, 3]"
        pre_existing_override = {"request_headers": {"X-Api-Key": "secret"}}
        result, errors = parse_target_scan_override_from_post(post, existing_override=pre_existing_override)
        self.assertEqual(result.get("request_headers"), {"X-Api-Key": "secret"})
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_request_headers_non_dict_json_no_existing_override(self):
        """
        When request_headers JSON is valid but not an object (e.g. array) and there is
        no existing override, request_headers must not be set and an error must be returned.
        """
        post = QueryDict("", mutable=True)
        post[f"{TARGET_OVERRIDE_PREFIX}request_headers"] = "[1, 2, 3]"
        result, errors = parse_target_scan_override_from_post(post, existing_override=None)
        self.assertNotIn("request_headers", result)
        self.assertEqual(len(errors), 1)
        self.assertIn("JSON object", errors[0])

    def test_profiles_dict_included_when_passed(self):
        post = QueryDict("", mutable=True)
        profiles = {"speed": "polite", "evasion": "stealth"}
        result, errors = parse_target_scan_override_from_post(post, profiles_dict=profiles)
        self.assertEqual(result["profiles"], profiles)
        self.assertEqual(errors, [])

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
