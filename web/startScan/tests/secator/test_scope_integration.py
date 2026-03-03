"""
Integration tests for scope parameter merging in the Secator pipeline.
"""

from django.http import QueryDict

from startScan.secator.form import _merge_scope_params_into_config, parse_secator_profiles_to_dict
from utils.test_base import BaseTestCase


class MergeScopeParamsTest(BaseTestCase):
    """Tests that _merge_scope_params_into_config correctly merges Scope/Target params."""

    def setUp(self):
        super().setUp()
        self.data_generator.create_organization()

    def test_no_scope_id_returns_unchanged(self):
        config = {"proxy": None, "delay": 0, "profiles": []}
        post = QueryDict("", mutable=True)
        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)
        self.assertEqual(result, config)

    def test_scope_params_merged(self):
        scope = self.data_generator.create_scope(
            threads=5,
            rate_limit=50,
            timeout=30,
            proxy="http://10.0.0.2:8080",
        )
        config = {"proxy": None, "delay": 0, "profiles": []}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertEqual(result["threads"], 5)
        self.assertEqual(result["rate_limit"], 50)
        self.assertEqual(result["timeout"], 30)
        self.assertEqual(result["proxy"], "http://10.0.0.2:8080")

    def test_existing_config_not_overwritten(self):
        scope = self.data_generator.create_scope(proxy="http://10.0.0.2:8080")
        config = {"proxy": "socks5://10.0.0.1:1080", "delay": 5, "profiles": []}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertEqual(result["proxy"], "socks5://10.0.0.1:1080")
        self.assertEqual(result["delay"], 5)

    def test_scope_default_profiles_dict_format_merged(self):
        scope = self.data_generator.create_scope(
            default_profiles={"speed": "polite", "evasion": "stealth"},
        )
        config = {"proxy": None, "delay": 0}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])

    def test_scope_default_profiles_list_format_compat(self):
        """Legacy list format still works until data migration."""
        scope = self.data_generator.create_scope(default_profiles=["polite", "stealth"])
        config = {"proxy": None, "delay": 0}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertIn("polite", result["profiles"])
        self.assertIn("stealth", result["profiles"])

    def test_existing_profiles_not_overwritten(self):
        scope = self.data_generator.create_scope(default_profiles={"speed": "polite"})
        config = {"proxy": None, "delay": 0, "profiles": ["insane"]}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertEqual(result["profiles"], ["insane"])

    def test_invalid_scope_id_returns_unchanged(self):
        config = {"proxy": None, "delay": 0, "profiles": []}
        post = QueryDict("", mutable=True)
        post["scope_id"] = "99999"

        result, _ = _merge_scope_params_into_config(config, post, self.data_generator.target.id)
        self.assertEqual(result, config)

    def test_invalid_target_id_returns_unchanged(self):
        scope = self.data_generator.create_scope()
        config = {"proxy": None, "delay": 0, "profiles": []}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        result, _ = _merge_scope_params_into_config(config, post, 99999)
        self.assertEqual(result, config)

    def test_worker_ids_not_added_when_scope_has_no_workers(self):
        scope = self.data_generator.create_scope()
        config = {"proxy": None, "delay": 0, "profiles": []}
        post = QueryDict("", mutable=True)
        post["scope_id"] = str(scope.id)

        config_result, scope_worker_ids = _merge_scope_params_into_config(config, post, self.data_generator.target.id)

        self.assertNotIn("_worker_ids", config_result)


class ParseSecatorProfilesToDictTest(BaseTestCase):
    """Tests for parse_secator_profiles_to_dict."""

    def test_empty_post_returns_empty_dict(self):
        post = QueryDict("", mutable=True)
        result = parse_secator_profiles_to_dict(post)
        self.assertEqual(result, {})

    def test_enabled_speed_profile(self):
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "on"
        post["speed_profile"] = "polite"

        result = parse_secator_profiles_to_dict(post)

        self.assertEqual(result, {"speed": "polite"})

    def test_custom_profile_takes_precedence_over_builtin(self):
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "on"
        post["speed_custom_profile"] = "my_custom_speed"
        post["speed_profile"] = "polite"

        result = parse_secator_profiles_to_dict(post)

        self.assertEqual(result["speed"], "my_custom_speed")

    def test_multiple_categories(self):
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "on"
        post["speed_profile"] = "polite"
        post["use_evasion_profile"] = "on"
        post["stealth_profile"] = "stealth"

        result = parse_secator_profiles_to_dict(post)

        self.assertEqual(result["speed"], "polite")
        self.assertEqual(result["evasion"], "stealth")
        self.assertEqual(len(result), 2)

    def test_disabled_switch_excluded(self):
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "off"
        post["speed_profile"] = "polite"

        result = parse_secator_profiles_to_dict(post)

        self.assertNotIn("speed", result)

    def test_all_four_categories(self):
        post = QueryDict("", mutable=True)
        post["use_speed_profile"] = "on"
        post["speed_profile"] = "polite"
        post["use_evasion_profile"] = "on"
        post["stealth_profile"] = "stealth"
        post["use_general_profile"] = "on"
        post["general_profile"] = "full"
        post["use_network_profile"] = "on"
        post["network_profile"] = "all_ports"

        result = parse_secator_profiles_to_dict(post)

        self.assertEqual(result["speed"], "polite")
        self.assertEqual(result["evasion"], "stealth")
        self.assertEqual(result["general"], "full")
        self.assertEqual(result["network"], "all_ports")
