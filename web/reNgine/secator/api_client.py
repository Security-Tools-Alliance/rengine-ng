"""
API Client for Secator hooks to communicate with reNgine-ng API.
Provides a reusable client for all Secator hooks to save data via API instead of direct database access.
"""

import os
import time
from typing import Any, Dict, Optional

from celery.utils.log import get_task_logger
import requests


logger = get_task_logger(__name__)


class RengineAPIClient:
    """
    API client for Secator hooks to communicate with reNgine-ng API.

    This client handles authentication, retry logic, and error handling
    for all API calls made by Secator hooks.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        """
        Initialize the API client.

        Args:
            api_url: Base URL of the reNgine-ng API (defaults to RENGINE_API_URL env var)
            api_key: API key for authentication (defaults to RENGINE_API_KEY env var)
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.api_url = (api_url or os.getenv("RENGINE_API_URL", "http://web:8000")).rstrip("/")
        self.api_key = api_key or os.getenv("RENGINE_API_KEY")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries

        if not self.api_key:
            raise ValueError("RENGINE_API_KEY environment variable is required")

        # Setup session with default headers
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Api-Key {self.api_key}", "Content-Type": "application/json"})

        # Disable SSL warnings if not verifying
        if not verify_ssl:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _make_request(
        self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Make an HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            endpoint: API endpoint (without leading slash)
            data: Request body data
            params: Query parameters

        Returns:
            Dict containing the response data

        Raises:
            requests.RequestException: If all retry attempts fail
        """
        url = f"{self.api_url}/api/{endpoint.lstrip('/')}"

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"API {method} request to {url} (attempt {attempt + 1}/{self.max_retries})")

                response = self.session.request(
                    method=method, url=url, json=data, params=params, timeout=self.timeout, verify=self.verify_ssl
                )

                # Log response for debugging
                logger.debug(f"API response: {response.status_code} - {response.text[:200]}")

                # Handle successful response
                if response.status_code in [200, 201]:
                    try:
                        return response.json()
                    except ValueError:
                        return {"status": True, "message": "Success"}

                # Handle client errors (don't retry)
                elif response.status_code in [400, 401, 403, 404, 422]:
                    error_msg = f"Client error {response.status_code}: {response.text}"
                    logger.error(error_msg)
                    return {"status": False, "error": error_msg}

                # Handle server errors (retry)
                else:
                    error_msg = f"Server error {response.status_code}: {response.text}"
                    logger.warning(f"Attempt {attempt + 1} failed: {error_msg}")

                    if attempt == self.max_retries - 1:
                        return {"status": False, "error": error_msg}

                    # Wait before retry (exponential backoff)
                    time.sleep(2**attempt)

            except requests.exceptions.Timeout:
                error_msg = f"Request timeout after {self.timeout}s"
                logger.warning(f"Attempt {attempt + 1} failed: {error_msg}")

                if attempt == self.max_retries - 1:
                    return {"status": False, "error": error_msg}

                time.sleep(2**attempt)

            except requests.exceptions.ConnectionError as e:
                error_msg = f"Connection error: {str(e)}"
                logger.warning(f"Attempt {attempt + 1} failed: {error_msg}")

                if attempt == self.max_retries - 1:
                    return {"status": False, "error": error_msg}

                time.sleep(2**attempt)

            except requests.exceptions.RequestException as e:
                error_msg = f"Request error: {str(e)}"
                logger.error(error_msg)
                return {"status": False, "error": error_msg}

        return {"status": False, "error": "Max retries exceeded"}

    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a POST request.

        Args:
            endpoint: API endpoint
            data: Request body data

        Returns:
            Dict containing the response data
        """
        return self._make_request("POST", endpoint, data=data)

    def put(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a PUT request.

        Args:
            endpoint: API endpoint
            data: Request body data

        Returns:
            Dict containing the response data
        """
        return self._make_request("PUT", endpoint, data=data)

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make a GET request.

        Args:
            endpoint: API endpoint
            params: Query parameters

        Returns:
            Dict containing the response data
        """
        return self._make_request("GET", endpoint, params=params)

    def save_secator_item(
        self,
        item_type: str,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Save a Secator item via the appropriate API endpoint.

        Args:
            item_type: Type of Secator item (ip, subdomain, port, url, tag, vulnerability, record, exploit, user_account)
            item: Secator item data
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional reNgine context

        Returns:
            Dict containing the response data
        """
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
            error_msg = f"Unknown item type: {item_type}"
            logger.error(error_msg)
            return {"status": False, "error": error_msg}

        endpoint = endpoint_mapping[item_type]
        data = {
            "item": item,
            "scan_history_id": scan_history_id,
            "domain_id": domain_id,
            "rengine_context": rengine_context or {},
        }

        return self.post(endpoint, data)

    def update_scan_status(self, scan_id: int, status: int, stop_scan_date: Optional[str] = None) -> Dict[str, Any]:
        """
        Update scan status via API.

        Args:
            scan_id: ID of the scan
            status: New status code
            stop_scan_date: Optional stop date (ISO format)

        Returns:
            Dict containing the response data
        """
        endpoint = f"secator/scan/{scan_id}/status/"
        data = {"status": status}
        if stop_scan_date:
            data["stop_scan_date"] = stop_scan_date

        return self.put(endpoint, data)

    def create_scan_activity(self, scan_id: int, message: str, status: int) -> Dict[str, Any]:
        """
        Create scan activity via API.

        Args:
            scan_id: ID of the scan
            message: Activity message
            status: Activity status code

        Returns:
            Dict containing the response data
        """
        endpoint = f"secator/scan/{scan_id}/activity/"
        data = {"message": message, "status": status}

        return self.post(endpoint, data)
