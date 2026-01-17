"""
Utility classes and functions for the targetApp module.
"""


class StatsTracker:
    """
    A utility class to track statistics for target processing operations.

    This class encapsulates the logic for counting different types of targets
    and their creation/existing status, providing a clean interface and
    reducing the risk of manual counting errors.

    Usage:
        stats = StatsTracker()
        stats.domain(created=True)  # Increment domains_created
        stats.subdomain(created=False)  # Increment subdomains_existing
        result = stats.as_dict()  # Get all stats as dictionary
    """

    def __init__(self):
        """Initialize all counters to zero."""
        self.domains_created = 0
        self.domains_existing = 0
        self.subdomains_created = 0
        self.subdomains_existing = 0
        self.ips_created = 0
        self.ips_existing = 0
        self.total_processed = 0

    def domain(self, created: bool) -> None:
        """
        Record a domain processing result.

        Args:
            created (bool): True if domain was newly created, False if it already existed
        """
        if created:
            self.domains_created += 1
        else:
            self.domains_existing += 1

    def subdomain(self, created: bool) -> None:
        """
        Record a subdomain processing result.

        Args:
            created (bool): True if subdomain was newly created, False if it already existed
        """
        if created:
            self.subdomains_created += 1
        else:
            self.subdomains_existing += 1

    def ip(self, created: bool) -> None:
        """
        Record an IP address processing result.

        Args:
            created (bool): True if IP was newly created, False if it already existed
        """
        if created:
            self.ips_created += 1
        else:
            self.ips_existing += 1

    def processed(self) -> None:
        """Increment the total processed counter."""
        self.total_processed += 1

    def get_total_processed(self) -> int:
        """
        Calculate the total number of processed items.

        Returns:
            int: Total count of domains and subdomains processed (created + existing)
        """
        return self.domains_created + self.domains_existing + self.subdomains_created + self.subdomains_existing

    def as_dict(self) -> dict:
        """
        Export all statistics as a dictionary.

        Returns:
            dict: Dictionary containing all statistics with descriptive keys
        """
        return {
            "domains_created": self.domains_created,
            "domains_existing": self.domains_existing,
            "subdomains_created": self.subdomains_created,
            "subdomains_existing": self.subdomains_existing,
            "ips_created": self.ips_created,
            "ips_existing": self.ips_existing,
            "total_processed": self.get_total_processed(),
        }

    def __str__(self) -> str:
        """String representation for debugging and logging."""
        return f"StatsTracker({self.as_dict()})"

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"StatsTracker("
            f"domains: {self.domains_created}+{self.domains_existing}, "
            f"subdomains: {self.subdomains_created}+{self.subdomains_existing}, "
            f"ips: {self.ips_created}+{self.ips_existing})"
        )
