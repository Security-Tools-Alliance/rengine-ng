from django.conf.urls import include, url
from django.urls import path
from rest_framework import routers

from .views import *

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'listDatatableSubdomain', SubdomainDatatableViewSet, basename='subdomain-datatable')
router.register(r'listTargets', ListTargetsDatatableViewSet, basename='targets')
router.register(r'listSubdomains', SubdomainsViewSet, basename='subdomains')
router.register(r'listEndpoints', EndPointViewSet, basename='endpoints')
router.register(r'listDirectories', DirectoryViewSet, basename='directories')
router.register(r'listVulnerability', VulnerabilityViewSet, basename='vulnerabilities')
router.register(r'listInterestingSubdomains', InterestingSubdomainViewSet, basename='interesting-subdomains')
router.register(r'listInterestingEndpoints', InterestingEndpointViewSet, basename='interesting-endpoints')
router.register(r'listSubdomainChanges', SubdomainChangesViewSet, basename='subdomain-changes')
router.register(r'listEndPointChanges', EndPointChangesViewSet, basename='endpoint-changes')
router.register(r'listIps', IpAddressViewSet, basename='ip-addresses')
router.register(r'listActivityLogs', ListActivityLogsViewSet, basename='activity-logs')
router.register(r'listScanLogs', ListScanLogsViewSet, basename='scan-logs')

urlpatterns = [
    url('^', include(router.urls)),
    path(
        'add/target/',
        AddTarget.as_view(),
        name='addTarget'),
    path(
        'add/recon_note/',
        AddReconNote.as_view(),
        name='addReconNote'),
    path(
        'queryTechnologies/',
        ListTechnology.as_view(),
        name='listTechnologies'),
    path(
        'queryPorts/',
        ListPorts.as_view(),
        name='listPorts'),
    path(
        'queryIps/',
        ListIPs.as_view(),
        name='listIPs'),
    path(
        'queryIp/',
        GetIpDetails.as_view(),
        name='getIpDetails'),
    path(
        'queryInterestingSubdomains/',
        QueryInterestingSubdomains.as_view(),
        name='queryInterestingSubdomains'),
    path(
        'querySubdomains/',
        ListSubdomains.as_view(),
        name='querySubdomains'),
    path(
        'queryEndpoints/',
        ListEndpoints.as_view(),
        name='queryEndpoints'),
    path(
        'queryOsintUsers/',
        ListOsintUsers.as_view(),
        name='queryOsintUsers'),
    path(
        'queryMetadata/',
        ListMetadata.as_view(),
        name='queryMetadata'),
    path(
        'queryEmails/',
        ListEmails.as_view(),
        name='queryEmails'),
    path(
        'queryEmployees/',
        ListEmployees.as_view(),
        name='queryEmployees'),
    path(
        'queryDorks/',
        ListDorks.as_view(),
        name='queryDorks'),
    path(
        'queryDorkTypes/',
        ListDorkTypes.as_view(),
        name='queryDorkTypes'),
    path(
        'queryDorkTypes/',
        ListDorkTypes.as_view(),
        name='queryDorkTypes'),
    path(
        'queryAllScanResultVisualise/',
        VisualiseData.as_view(),
        name='queryAllScanResultVisualise'),
    path(
        'queryTargetsWithoutOrganization/',
        ListTargetsWithoutOrganization.as_view(),
        name='queryTargetsWithoutOrganization'),
    path(
        'queryTargetsInOrganization/',
        ListTargetsInOrganization.as_view(),
        name='queryTargetsInOrganization'),
    path(
        'listOrganizations/',
        ListOrganizations.as_view(),
        name='listOrganizations'),
    path(
        'listEngines/',
        ListEngines.as_view(),
        name='listEngines'),
    path(
        'listSubScans/',
        ListSubScans.as_view(),
        name='listSubScans'),
    path(
        'listScanHistory/',
        ListScanHistory.as_view(),
        name='listScanHistory'),
    path(
        'listTodoNotes/',
        ListTodoNotes.as_view(),
        name='listTodoNotes'),
    path(
        'listInterestingKeywords/',
        ListInterestingKeywords.as_view(),
        name='listInterestingKeywords'),
    path(
        'getFileContents/',
        GetFileContents.as_view(),
        name='getFileContents'),
    path(
        'vulnerability/report/',
        VulnerabilityReport.as_view(),
        name='vulnerability_report'),
    path(
        'tools/ip_to_domain/',
        IPToDomain.as_view(),
        name='ip_to_domain'),
    path(
        'tools/whois/',
        Whois.as_view(),
        name='whois'),
    path(
        'tools/reverse/whois/',
        ReverseWhois.as_view(),
        name='reverse_whois'),
    path(
        'tools/domain_ip_history',
        DomainIPHistory.as_view(),
        name='domain_ip_history'),
    path(
        'tools/cms_detector/',
        CMSDetector.as_view(),
        name='cms_detector'),
    path(
        'tools/cve_details/',
        CVEDetails.as_view(),
        name='cve_details'),
    path(
        'tools/waf_detector/',
        WafDetector.as_view(),
        name='waf_detector'),
    path(
        'tools/gf_list/',
        GfList.as_view(),
        name='gf_list'),
    path(
        'tools/llm_vulnerability_report/',
        LLMVulnerabilityReportGenerator.as_view(),
        name='llm_vulnerability_report_generator'),
    path(
        'tools/llm_get_possible_attacks/',
        LLMAttackSuggestion.as_view(),
        name='llm_get_possible_attacks'),
    path(
        'tools/llm_models/',
        LLMModelsManager.as_view(),
        name='llm_models_manager'),
    path(
        'tools/available_ollama_models/',
        AvailableOllamaModels.as_view(),
        name='available_ollama_models'),
    path(
        'github/tool/get_latest_releases/',
        GithubToolCheckGetLatestRelease.as_view(),
        name='github_tool_latest_release'),
    path(
        'external/tool/get_current_release/',
        GetExternalToolCurrentVersion.as_view(),
        name='external_tool_get_current_release'),
    path(
        'tool/update/',
        UpdateTool.as_view(),
        name='update_tool'),
    path(
        'tool/uninstall/',
        UninstallTool.as_view(),
        name='uninstall_tool'),
	path(
        'tool/ollama/',
        OllamaManager.as_view(),
        name='ollama_manager'),
    path(
        'tool/ollama/<path:model_name>/',
        OllamaDetailManager.as_view(),
        name='ollama_detail_manager'),        
    path(
        'rengine/update/',
        RengineUpdateCheck.as_view(),
        name='check_rengine_update'),
    path(
        'action/subdomain/delete/',
        DeleteSubdomain.as_view(),
        name='delete_subdomain'),
    path(
        'action/vulnerability/delete/',
        DeleteVulnerability.as_view(),
        name='delete_vulnerability'),
    path(
        'action/rows/delete/',
        DeleteMultipleRows.as_view(),
        name='delete_rows'),
    path(
        'toggle/subdomain/important/',
        ToggleSubdomainImportantStatus.as_view(),
        name='toggle_subdomain'),
    path(
        'action/initiate/subtask/',
        InitiateSubTask.as_view(),
        name='initiate_subscan'),
    path(
        'action/stop/scan/',
        StopScan.as_view(),
        name='stop_scan'),
    path(
        'fetch/results/subscan/',
        FetchSubscanResults.as_view(),
        name='fetch_subscan_results'),
    path(
        'fetch/most_vulnerable/',
        FetchMostVulnerable.as_view(),
        name='fetch_most_vulnerable'),
    path(
        'fetch/most_common_vulnerability/',
        FetchMostCommonVulnerability.as_view(),
        name='fetch_most_common_vulnerability'),
    path(
        'search/',
        UniversalSearch.as_view(),
        name='search'),
    path(
        'search/history/',
        SearchHistoryView.as_view(),
        name='search_history'),
    # API for fetching currently ongoing scans and upcoming scans
    path(
        'scan_status/',
        ScanStatus.as_view(),
        name='scan_status'),
    path(
        'action/create/project',
        CreateProjectApi.as_view(),
        name='create_project'),
    path(
        'uncommon-web-ports/', 
         UncommonWebPortsView.as_view(), 
         name='uncommonWebPorts'),
]

urlpatterns += router.urls
