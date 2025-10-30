"""
Pure API database hooks for Secator workers.
No Django dependencies - only HTTP API calls.
"""

import logging
import os
from typing import Any, Dict, Optional

import requests


logger = logging.getLogger(__name__)


class DatabaseHooks:
    """Pure API hooks for saving Secator results via HTTP API."""

    def __init__(self, scan_history_id: int, domain_id: int, rengine_context: Optional[Dict[str, Any]] = None):
        """
        Initialize API database hooks.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional reNgine context
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.rengine_context = rengine_context or {}

        # API configuration
        self.api_url = os.getenv("RENGINE_API_URL", "http://web:8000").rstrip("/")
        self.api_key = os.getenv("RENGINE_API_KEY")

        logger.info(f"🔧 DatabaseHooks initialized for scan {scan_history_id}, domain {domain_id}")
        logger.info(f"🔧 API URL: {self.api_url}")
        logger.info(f"🔧 API Key: {'SET' if self.api_key else 'NOT SET'}")

        if not self.api_key:
            raise ValueError("RENGINE_API_KEY environment variable is required")

        # Setup session
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Api-Key {self.api_key}", "Content-Type": "application/json"})

        logger.info("🔧 DatabaseHooks session configured")

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make HTTP request to API."""
        url = f"{self.api_url}/api/{endpoint.lstrip('/')}"

        logger.info(f"🌐 Making {method} request to {url}")
        if data:
            logger.info(f"🌐 Request data keys: {list(data.keys())}")
            logger.info(f"🌐 Full request data: {data}")

        # Log the curl command for debugging
        curl_cmd = f"curl -X {method} '{url}'"
        curl_cmd += f" -H 'Authorization: Api-Key {self.api_key}'"
        curl_cmd += " -H 'Content-Type: application/json'"
        if data:
            import json

            curl_cmd += f" -d '{json.dumps(data)}'"
        logger.info(f"🔧 CURL COMMAND: {curl_cmd}")

        try:
            response = self.session.request(method=method, url=url, json=data, timeout=30)

            logger.info(f"🌐 Response status: {response.status_code}")
            logger.info(f"🌐 Response headers: {dict(response.headers)}")
            logger.info(f"🌐 Response body: {response.text}")

            if response.status_code in [200, 201]:
                try:
                    result = response.json()
                    logger.info(f"🌐 API call successful: {result}")
                    return result
                except ValueError:
                    logger.info("🌐 API call successful (no JSON response)")
                    return {"status": True, "message": "Success"}
            else:
                error_msg = f"API error {response.status_code}: {response.text}"
                logger.error(f"🌐 {error_msg}")
                return {"status": False, "error": error_msg}

        except Exception as e:
            error_msg = f"Request error: {str(e)}"
            logger.error(f"🌐 {error_msg}")
            return {"status": False, "error": error_msg}

    def on_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Save item to database via API.

        Args:
            item: Secator result item

        Returns:
            item: Original item
        """
        logger.info(f"📦 on_item called with item type: {item.get('_type')}, target: {item.get('target', 'unknown')}")
        try:
            item_type = item.get("_type")

            # Check if item should be filtered out
            if self._should_filter_item(item):
                logger.info(f"🚫 Filtering out item: {item.get('target', 'unknown')}")
                return item

            # Map item types to API endpoints
            endpoint_mapping = {
                "ip": "secator/ip/",
                "subdomain": "secator/subdomain/",
                "port": "secator/port/",
                "url": "secator/endpoint/",
                "tag": "secator/technology/",
                "vulnerability": "secator/vulnerability/",
                "record": "secator/dns_record/",
                "exploit": "secator/exploit/",
                "user_account": "secator/employee/",
            }

            if item_type not in endpoint_mapping:
                logger.debug(f"Unhandled item type: {item_type}")
                return item

            endpoint = endpoint_mapping[item_type]
            data = {
                "item": item,
                "scan_history_id": self.scan_history_id,
                "domain_id": self.domain_id,
                "rengine_context": self.rengine_context,
            }

            result = self._make_request("POST", endpoint, data)

            if result.get("status"):
                logger.debug(f"Successfully saved {item_type} item via API")
            else:
                logger.error(f"Failed to save {item_type} item via API: {result.get('error', 'Unknown error')}")

        except Exception as e:
            logger.error(f"Error saving item to database via API: {e}")

        return item

    def on_duplicate(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Handle duplicate item."""
        logger.debug(f"Duplicate item detected: {item.get('_type')} - {item.get('target')}")
        return item

    def on_error(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Handle error item."""
        logger.error(f"Error item received: {item}")
        return item

    def _should_filter_item(self, item: Dict[str, Any]) -> bool:
        """Check if item should be filtered out based on reNgine context."""
        item_type = item.get("_type")

        if item_type == "subdomain":
            target = item.get("target", "")
            if not target:
                return True

            # Check imported subdomains
            imported_subdomains = self.rengine_context.get("imported_subdomains", [])
            if target in imported_subdomains:
                return True

            # Check out of scope subdomains
            out_of_scope_subdomains = self.rengine_context.get("out_of_scope_subdomains", [])
            if target in out_of_scope_subdomains:
                return True

        return False
