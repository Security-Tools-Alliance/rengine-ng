"""
Core exceptions for reNgine.

Used when the application needs to signal a specific condition (e.g. finding out of scope)
without overloading generic Exception or mixing with Django/DRF exceptions.
"""


class FindingOutOfScopeError(Exception):
    """
    Raised when a finding is rejected because it is out of scope
    (restrict_findings_to_target). The API should respond with 200 and a synthetic id
    (skipped) rather than 422, so Secator does not mark the task as failed.

    Repositories (e.g. CertificateRepository, DnsRepository) that call scope checks
    do not catch this exception; they only catch ObjectDoesNotExist and IntegrityError.
    FindingOutOfScopeError propagates to the API layer, which returns 200 with
    status "skipped" and skipped=True.
    """

    pass
