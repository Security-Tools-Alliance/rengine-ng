"""
Employee Repository - Data access for employee operations.
Handles Employee database operations from Secator UserAccount type.
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from django.utils import timezone

from reNgine.core.validators import is_valid_domain, is_valid_email, is_valid_url
from reNgine.utilities.logger import get_module_logger
from startScan.models import Email, Employee, EndPoint, ScanHistory, Subdomain
from targetApp.models import Domain


logger = get_module_logger(__name__)


class EmployeeRepository:
    """Repository for employee-related database operations."""

    def save_from_secator(
        self,
        item: Dict[str, Any],
        scan_history_id: int,
        domain_id: int,
        rengine_context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Employee]:
        """
        Save employee from Secator UserAccount result.

        Args:
            item: Secator UserAccount item
            scan_history_id: ID of the scan history
            domain_id: ID of the domain
            rengine_context: Optional context (unused)

        Returns:
            Employee: Saved employee object or None
        """
        try:
            return self._process_secator_employee_item(item, scan_history_id, domain_id)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found when saving employee: {e}")
            return None
        except IntegrityError as e:
            logger.error(f"Integrity error saving employee: {e}")
            return None
        except Exception as e:
            logger.error(f"Error saving employee from Secator: {e}")
            return None

    def _process_secator_employee_item(
        self, item: Dict[str, Any], scan_history_id: int, domain_id: int
    ) -> Optional[Employee]:
        username = item.get("username")
        email = item.get("email")
        site_name = item.get("site_name")
        url = item.get("url")

        if not username and not email:
            logger.warning("Employee item missing username and email fields")
            return None

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        # Get or create employee
        employee, created = Employee.objects.get_or_create(
            username=username or "",
            scan_history=scan_history,
            defaults={
                "name": username or email or "Unknown",
                "site_name": site_name or "",
                "url": url or "",
                "target_domain": domain,
                "discovered_date": timezone.now(),
                "extra_data": item.get("extra_data", {}),
            },
        )

        # Associate email if provided
        if email and is_valid_email(email):
            email_obj, _ = Email.objects.get_or_create(address=email)
            employee.emails.add(email_obj)

        if created:
            logger.info(f"Created employee: {username or email}")
        else:
            logger.debug(f"Employee already exists: {username or email}")

        # Associate with subdomain/endpoint if URL is provided
        if url:
            self._associate_with_target(employee, url, scan_history_id)

        return employee

    def get_or_create(
        self, username: str, email: str, scan_history_id: int, **kwargs
    ) -> Tuple[Optional[Employee], bool]:
        """
        Get or create an employee.

        Args:
            username: Username
            email: Email address
            scan_history_id: Scan history ID
            **kwargs: Additional fields

        Returns:
            tuple: (Employee, created boolean) or (None, False)
        """
        try:
            scan_history = ScanHistory.objects.get(id=scan_history_id)

            defaults = {
                "name": username or email or "Unknown",
                "discovered_date": timezone.now(),
                "extra_data": {},
            } | kwargs
            employee, created = Employee.objects.get_or_create(
                username=username or "", scan_history=scan_history, defaults=defaults
            )

            # Associate email if provided
            if email and is_valid_email(email):
                email_obj, _ = Email.objects.get_or_create(address=email)
                employee.emails.add(email_obj)

            return employee, created

        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return None, False
        except Exception as e:
            logger.error(f"Error in get_or_create employee: {e}")
            return None, False

    def bulk_create(self, employees: List[Dict[str, Any]], scan_history_id: int, domain_id: int) -> List[Employee]:
        """
        Bulk create employees.

        Args:
            employees: List of employee dictionaries with 'username' and 'email' (or 'emails' list)
            scan_history_id: ID of the scan history
            domain_id: ID of the domain

        Returns:
            list: List of created Employee objects
        """
        try:
            return self._create_employees_in_bulk(scan_history_id, domain_id, employees)
        except ObjectDoesNotExist as e:
            logger.error(f"Object not found: {e}")
            return []
        except Exception as e:
            logger.error(f"Error in bulk create employees: {e}")
            return []

    def _create_employees_in_bulk(
        self, scan_history_id: int, domain_id: int, employees: List[Dict[str, Any]]
    ) -> List[Employee]:
        from startScan.models import Email

        scan_history = ScanHistory.objects.get(id=scan_history_id)
        domain = Domain.objects.get(id=domain_id)

        created_employees = []
        for employee_data in employees:
            username = employee_data.get("username", "")

            # Support both 'email' (string) and 'emails' (list)
            email_addresses = []
            if "emails" in employee_data:
                email_addresses = (
                    employee_data["emails"] if isinstance(employee_data["emails"], list) else [employee_data["emails"]]
                )
            elif "email" in employee_data:
                email_addresses = [employee_data["email"]]

            if username or email_addresses:
                # Get or create employee (username is unique per domain)
                employee, created = Employee.objects.get_or_create(
                    username=username,
                    target_domain=domain,
                    defaults={
                        "name": username or (email_addresses[0] if email_addresses else "Unknown"),
                        "site_name": employee_data.get("site_name", ""),
                        "url": employee_data.get("url", ""),
                        "scan_history": scan_history,
                        "discovered_date": timezone.now(),
                        "extra_data": employee_data.get("extra_data", {}),
                    },
                )

                # Associate emails (ManyToMany)
                if email_addresses:
                    for email_address in email_addresses:
                        if email_address and email_address.strip():
                            email_obj, _ = Email.objects.get_or_create(address=email_address.strip())
                            employee.emails.add(email_obj)

                if created:
                    created_employees.append(employee)

        logger.info(f"Created {len(created_employees)} new employees")
        return created_employees

    def get_employees_for_domain(self, domain_id: int) -> List[Employee]:
        """
        Get all employees associated with a domain.

        Args:
            domain_id: Domain ID

        Returns:
            list: List of Employee objects
        """
        try:
            domain = Domain.objects.get(id=domain_id)
            return list(Employee.objects.filter(target_domain=domain))

        except ObjectDoesNotExist:
            logger.error(f"Domain with ID {domain_id} not found")
            return []
        except Exception as e:
            logger.error(f"Error getting employees for domain: {e}")
            return []

    def get_employees_for_subdomain(self, subdomain_name: str, scan_history_id: int) -> List[Employee]:
        """
        Get all employees associated with a subdomain.

        Args:
            subdomain_name: Subdomain name
            scan_history_id: Scan history ID

        Returns:
            list: List of Employee objects
        """
        try:
            if subdomain := Subdomain.objects.filter(name=subdomain_name, scan_history_id=scan_history_id).first():
                return list(Employee.objects.filter(subdomain=subdomain))
            logger.warning(f"Subdomain {subdomain_name} not found in scan {scan_history_id}")
            return []

        except Exception as e:
            logger.error(f"Error getting employees for subdomain: {e}")
            return []

    def search_by_email(self, email: str) -> List[Employee]:
        """
        Search employees by email address.

        Args:
            email: Email address to search for

        Returns:
            list: List of Employee objects
        """
        try:
            if not is_valid_email(email):
                logger.warning(f"Invalid email address: {email}")
                return []

            return list(Employee.objects.filter(emails__address__icontains=email))

        except Exception as e:
            logger.error(f"Error searching employees by email: {e}")
            return []

    def search_by_username(self, username: str) -> List[Employee]:
        """
        Search employees by username.

        Args:
            username: Username to search for

        Returns:
            list: List of Employee objects
        """
        try:
            if not username or not username.strip():
                logger.warning("Username is empty")
                return []

            return list(Employee.objects.filter(username__icontains=username.strip()))

        except Exception as e:
            logger.error(f"Error searching employees by username: {e}")
            return []

    def _associate_with_target(self, employee: Employee, url: str, scan_history_id: int) -> None:
        """
        Associate employee with subdomain or endpoint based on URL.

        Args:
            employee: Employee object
            url: URL to associate with
            scan_history_id: Scan history ID
        """
        try:
            if not is_valid_url(url):
                logger.warning(f"Invalid URL for employee association: {url}")
                return

            if endpoint := EndPoint.objects.filter(http_url=url, scan_history_id=scan_history_id).first():
                employee.endpoint = endpoint
                employee.save(update_fields=["endpoint"])
                logger.debug(f"Associated employee {employee.username or employee.email} with endpoint {url}")
                return

            # If no endpoint found, try subdomain association
            hostname = urlparse(url).hostname
            if hostname and is_valid_domain(hostname):
                if subdomain := Subdomain.objects.filter(name=hostname, scan_history_id=scan_history_id).first():
                    employee.subdomain = subdomain
                    employee.save(update_fields=["subdomain"])
                    logger.debug(f"Associated employee {employee.username or employee.email} with subdomain {hostname}")
                else:
                    logger.debug(f"Subdomain {hostname} not found in scan {scan_history_id}")

        except Exception as e:
            logger.error(f"Error associating employee with target: {e}")

    def validate_employee_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and clean employee data.

        Args:
            data: Employee data dictionary

        Returns:
            dict: Validated and cleaned data
        """
        try:
            validated_data = {}

            # Validate username
            username = data.get("username", "").strip()
            if username:
                validated_data["username"] = username

            if email := data.get("email", "").strip():
                if is_valid_email(email):
                    validated_data["email"] = email
                else:
                    logger.warning(f"Invalid email address: {email}")

            if site_name := data.get("site_name", "").strip():
                validated_data["site_name"] = site_name

            if url := data.get("url", "").strip():
                if is_valid_url(url):
                    validated_data["url"] = url
                else:
                    logger.warning(f"Invalid URL: {url}")

            # Validate extra data
            extra_data = data.get("extra_data")
            if extra_data and isinstance(extra_data, dict):
                validated_data["extra_data"] = extra_data

            return validated_data

        except Exception as e:
            logger.error(f"Error validating employee data: {e}")
            return {}
