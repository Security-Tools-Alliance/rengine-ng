from utils.test_base import BaseTestCase

from .test_advanced_search import TestAdvancedSearchParser
from .test_endpoint import (
    TestEndPointChangesViewSet,
    TestEndPointViewSet,
    TestInterestingEndpointViewSet,
)
from .test_ip import (
    TestIpAddressViewSet,
    TestIPToDomain,
    TestListIPs,
    TestListPorts,
)
from .test_organization import (
    TestListOrganizations,
    TestListTargetsInOrganization,
    TestListTargetsWithoutOrganization,
)
from .test_osint import (
    TestListDorks,
    TestListDorkTypes,
    TestListEmails,
    TestListEmployees,
    TestListMetadata,
    TestListOsintUsers,
)
from .test_project import (
    TestAddReconNote,
    TestCreateProjectApi,
    TestListTodoNotes,
)
from .test_scan import (
    TestDirectoryViewSet,
    TestFetchSubscanResults,
    TestListActivityLogsViewSet,
    TestListEngines,
    TestListInterestingKeywords,
    TestListS3BucketsDatatable,
    TestListScanEnginesDatatable,
    TestListScanHistory,
    TestListScanLogsViewSet,
    TestListSubScans,
    TestListTechnology,
    TestListWordlistsDatatable,
    TestScanStatus,
    TestStopScan,
    TestVisualiseData,
)
from .test_search import (
    TestSearchHistoryView,
    TestUniversalSearch,
)
from .test_secator_api import (
    TestSecatorAPIAuthentication,
    TestSecatorFindingCreate,
    TestSecatorFindingUpdate,
    TestSecatorRunnerCreate,
    TestSecatorRunnerUpdate,
)
from .test_start_scan import TestStartScanAPI
from .test_subdomain import (
    TestDeleteSubdomain,
    TestInterestingSubdomainViewSet,
    TestListSubdomains,
    TestQueryInterestingSubdomains,
    TestSubdomainChangesViewSet,
    TestSubdomainDatatableViewSet,
    TestSubdomainsViewSet,
    TestToggleSubdomainImportantStatus,
)
from .test_target import (
    TestAddTarget,
    TestListTargetsDatatableViewSet,
)
from .test_tools import (
    TestDeleteMultipleRows,
    TestGetFileContents,
    TestOllamaManager,
    TestRengineUpdateCheck,
)
from .test_vulnerability import (
    TestDeleteVulnerability,
    TestFetchMostCommonVulnerability,
    TestFetchMostVulnerable,
    TestLLMVulnerabilityReportGenerator,
    TestVulnerabilityReport,
    TestVulnerabilityViewSet,
)
from .test_worker_pull import TestWorkerPullApi


__all__ = [
    # Base
    "BaseTestCase",
    # test_advanced_search
    "TestAdvancedSearchParser",
    # test_endpoint
    "TestEndPointChangesViewSet",
    "TestEndPointViewSet",
    "TestInterestingEndpointViewSet",
    # test_ip
    "TestIpAddressViewSet",
    "TestIPToDomain",
    "TestListIPs",
    "TestListPorts",
    # test_organization
    "TestListOrganizations",
    "TestListTargetsInOrganization",
    "TestListTargetsWithoutOrganization",
    # test_osint
    "TestListDorks",
    "TestListDorkTypes",
    "TestListEmails",
    "TestListEmployees",
    "TestListMetadata",
    "TestListOsintUsers",
    # test_project
    "TestAddReconNote",
    "TestCreateProjectApi",
    "TestListTodoNotes",
    # test_scan
    "TestDirectoryViewSet",
    "TestFetchSubscanResults",
    "TestListActivityLogsViewSet",
    "TestListEngines",
    "TestListInterestingKeywords",
    "TestListS3BucketsDatatable",
    "TestListScanEnginesDatatable",
    "TestListScanHistory",
    "TestListScanLogsViewSet",
    "TestListSubScans",
    "TestListTechnology",
    "TestListWordlistsDatatable",
    "TestScanStatus",
    "TestStopScan",
    "TestVisualiseData",
    # test_start_scan
    "TestStartScanAPI",
    # test_search
    "TestSearchHistoryView",
    "TestUniversalSearch",
    # test_secator_api
    "TestSecatorAPIAuthentication",
    "TestSecatorFindingCreate",
    "TestSecatorFindingUpdate",
    "TestSecatorRunnerCreate",
    "TestSecatorRunnerUpdate",
    # test_subdomain
    "TestDeleteSubdomain",
    "TestInterestingSubdomainViewSet",
    "TestListSubdomains",
    "TestQueryInterestingSubdomains",
    "TestSubdomainChangesViewSet",
    "TestSubdomainDatatableViewSet",
    "TestSubdomainsViewSet",
    "TestToggleSubdomainImportantStatus",
    # test_target
    "TestAddTarget",
    "TestListTargetsDatatableViewSet",
    # test_tools
    "TestDeleteMultipleRows",
    "TestGetFileContents",
    "TestOllamaManager",
    "TestRengineUpdateCheck",
    # test_worker_pull
    "TestWorkerPullApi",
    # test_vulnerability
    "TestDeleteVulnerability",
    "TestFetchMostCommonVulnerability",
    "TestFetchMostVulnerable",
    "TestLLMVulnerabilityReportGenerator",
    "TestVulnerabilityReport",
    "TestVulnerabilityViewSet",
]
