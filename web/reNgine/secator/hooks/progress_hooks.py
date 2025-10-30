"""
Pure API progress hooks for Secator workers.
No Django dependencies - only HTTP API calls.
"""

from datetime import datetime
import logging
import os
from typing import Optional

import requests


logger = logging.getLogger(__name__)

# Constants for scan status
RUNNING_TASK = 1
SUCCESS_TASK = 2
FAILED_TASK = 3


class ProgressHooks:
    """Pure API hooks for tracking scan progress via HTTP API."""

    def __init__(self, scan_history_id: int, domain_id: int = None):
        """
        Initialize API progress hooks.

        Args:
            scan_history_id: ID of the scan history
            domain_id: ID of the domain (optional)
        """
        self.scan_history_id = scan_history_id
        self.domain_id = domain_id
        self.item_count = 0

        # API configuration
        self.api_url = os.getenv("RENGINE_API_URL", "http://web:8000").rstrip("/")
        self.api_key = os.getenv("RENGINE_API_KEY")

        logger.info(f"🔧 ProgressHooks initialized for scan {scan_history_id}, domain {domain_id}")
        logger.info(f"🔧 API URL: {self.api_url}")
        logger.info(f"🔧 API Key: {'SET' if self.api_key else 'NOT SET'}")

        if not self.api_key:
            raise ValueError("RENGINE_API_KEY environment variable is required")

        # Setup session
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Api-Key {self.api_key}", "Content-Type": "application/json"})

        logger.info("🔧 ProgressHooks session configured")

    def _make_request(self, method: str, endpoint: str, data: Optional[dict] = None) -> dict:
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

    def on_init(self, runner=None):
        """Execute when runner init is completed."""
        logger.info(f"Scan {self.scan_history_id} initialized")

    def on_start(self, runner=None):
        """Mark scan as started via API."""
        logger.info(f"🚀 on_start called for scan {self.scan_history_id}")

        # Update scan status
        result = self._make_request("PUT", f"secator/scan/{self.scan_history_id}/status/", {"status": RUNNING_TASK})
        if not result.get("status"):
            logger.error(f"Failed to update scan status via API: {result.get('error', 'Unknown error')}")

        # Create scan activity
        result = self._make_request(
            "POST",
            f"secator/scan/{self.scan_history_id}/activity/",
            {"message": "Secator scan started", "status": RUNNING_TASK},
        )
        if not result.get("status"):
            logger.error(f"Failed to create scan activity via API: {result.get('error', 'Unknown error')}")

        logger.info(f"🚀 Scan {self.scan_history_id} started")

    def on_iter(self, runner=None):
        """Update scan progress on each iteration."""
        self.item_count += 1
        if self.item_count % 10 == 0:
            logger.debug(f"Scan {self.scan_history_id} - {self.item_count} items processed")

    def on_end(self, runner=None):
        """Mark scan as completed via API."""
        logger.info(f"🏁 on_end called for scan {self.scan_history_id}")
        try:
            final_status = SUCCESS_TASK
            status_h = "SUCCESS"

            logger.info(f"🏁 Scan {self.scan_history_id}: Completed successfully")

            # Update scan status and completion time via API
            stop_scan_date = datetime.now().isoformat()
            result = self._make_request(
                "PUT",
                f"secator/scan/{self.scan_history_id}/status/",
                {"status": final_status, "stop_scan_date": stop_scan_date},
            )
            if not result.get("status"):
                logger.error(f"Failed to update scan status via API: {result.get('error', 'Unknown error')}")

            # Create final scan activity via API
            result = self._make_request(
                "POST",
                f"secator/scan/{self.scan_history_id}/activity/",
                {"message": f"Secator scan completed - {self.item_count} items processed", "status": final_status},
            )
            if not result.get("status"):
                logger.error(f"Failed to create scan activity via API: {result.get('error', 'Unknown error')}")

            logger.info(f"Scan {self.scan_history_id} completed with status {status_h}")

        except Exception as e:
            self._handle_scan_error(e)

    def _handle_scan_error(self, error):
        """Handle scan error by marking scan as failed."""
        logger.error(f"Error in on_end hook: {error}")
        try:
            self._make_request("PUT", f"secator/scan/{self.scan_history_id}/status/", {"status": FAILED_TASK})
            self._make_request(
                "POST",
                f"secator/scan/{self.scan_history_id}/activity/",
                {"message": f"Scan failed with error: {error}", "status": FAILED_TASK},
            )
        except Exception as e2:
            logger.error(f"Failed to update scan status after error: {e2}")
