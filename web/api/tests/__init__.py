from utils.test_base import BaseTestCase

from .test_endpoint import (
    TestEndPointChangesViewSet,
    TestEndPointViewSet,
    TestInterestingEndpointViewSet,
)
from .test_ip import (
    TestDomainIPHistory,
    TestIpAddressViewSet,
    TestIPToDomain,
    TestListIPs,
    TestListPorts,
    TestReverseWhois,
    TestWhois,
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
    TestInitiateSubTask,
    TestListActivityLogsViewSet,
    TestListEngines,
    TestListInterestingKeywords,
    TestListScanHistory,
    TestListScanLogsViewSet,
    TestListSubScans,
    TestListTechnology,
    TestScanStatus,
    TestStopScan,
    TestVisualiseData,
)
from .test_search import (
    TestSearchHistoryView,
    TestUniversalSearch,
)
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
    TestCMSDetector,
    TestDeleteMultipleRows,
    TestGetExternalToolCurrentVersion,
    TestGetFileContents,
    TestGfList,
    TestGithubToolCheckGetLatestRelease,
    TestOllamaManager,
    TestRengineUpdateCheck,
    TestUninstallTool,
    TestUpdateTool,
    TestWafDetector,
)
from .test_vulnerability import (
    TestCVEDetails,
    TestDeleteVulnerability,
    TestFetchMostCommonVulnerability,
    TestFetchMostVulnerable,
    TestLLMVulnerabilityReportGenerator,
    TestVulnerabilityReport,
    TestVulnerabilityViewSet,
)

__all__ = [
    # Base
    "BaseTestCase",
    # test_endpoint
    "TestEndPointChangesViewSet",
    "TestEndPointViewSet",
    "TestInterestingEndpointViewSet",
    # test_ip
    "TestDomainIPHistory",
    "TestIpAddressViewSet",
    "TestIPToDomain",
    "TestListIPs",
    "TestListPorts",
    "TestReverseWhois",
    "TestWhois",
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
    "TestInitiateSubTask",
    "TestListActivityLogsViewSet",
    "TestListEngines",
    "TestListInterestingKeywords",
    "TestListScanHistory",
    "TestListScanLogsViewSet",
    "TestListSubScans",
    "TestListTechnology",
    "TestScanStatus",
    "TestStopScan",
    "TestVisualiseData",
    # test_search
    "TestSearchHistoryView",
    "TestUniversalSearch",
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
    "TestCMSDetector",
    "TestDeleteMultipleRows",
    "TestGetExternalToolCurrentVersion",
    "TestGetFileContents",
    "TestGfList",
    "TestGithubToolCheckGetLatestRelease",
    "TestOllamaManager",
    "TestRengineUpdateCheck",
    "TestUninstallTool",
    "TestUpdateTool",
    "TestWafDetector",
    # test_vulnerability
    "TestCVEDetails",
    "TestDeleteVulnerability",
    "TestFetchMostCommonVulnerability",
    "TestFetchMostVulnerable",
    "TestLLMVulnerabilityReportGenerator",
    "TestVulnerabilityReport",
    "TestVulnerabilityViewSet",
]
