from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="scan_engine_index"),
    path("add/", views.add_engine, name="add_engine"),
    path("duplicate/<int:id>", views.duplicate_engine, name="duplicate_engine"),
    path("delete/<int:id>", views.delete_engine, name="delete_engine_url"),
    path("update/<int:id>", views.update_engine, name="update_engine"),
    path("api_vault/", views.api_vault, name="api_vault"),
    path("api_vault/delete/", views.api_vault_delete, name="api_vault_delete"),
    path("hackerone_settings", views.hackerone_settings, name="hackerone_settings"),
    path("interesting/lookup", views.interesting_lookup, name="interesting_lookup"),
    path("llm_toolkit", views.llm_toolkit_section, name="llm_toolkit"),
    path("notification_settings", views.notification_settings, name="notification_settings"),
    path("proxy_settings", views.proxy_settings, name="proxy_settings"),
    path("rengine_settings", views.rengine_settings, name="rengine_settings"),
    path("report_settings", views.report_settings, name="report_settings"),
    path("testHackerone", views.test_hackerone, name="testHackerone"),
    path("tool_settings", views.tool_specific_settings, name="tool_settings"),
    path("wordlist", views.wordlist_list, name="wordlist_list"),
    path("wordlist/delete/<int:id>", views.delete_wordlist, name="delete_wordlist"),
    path("wordlist/add", views.add_wordlist, name="add_wordlist"),
    # Workflow Integration URLs
    path("workflows/", views.secator_workflows, name="workflows"),
    path("workflows/partial/", views.secator_workflows_table_partial, name="workflows_table_partial"),
    path("workflows/add/", views.add_workflow, name="add_workflow"),
    path("workflows/<int:workflow_id>/", views.secator_workflow_detail, name="workflow_detail"),
    path("workflows/<int:workflow_id>/update/", views.update_workflow, name="update_workflow"),
    path("workflows/<int:workflow_id>/delete/", views.delete_workflow, name="delete_workflow"),
    path("tasks/", views.secator_tasks, name="tasks"),
    path("tasks/partial/", views.secator_tasks_table_partial, name="tasks_table_partial"),
    path("tasks/<int:task_id>/", views.secator_task_detail, name="task_detail"),
    # Profile Integration URLs
    path("profiles/", views.secator_profiles, name="profiles"),
    path("profiles/add/", views.add_profile, name="add_profile"),
    path("profiles/<int:profile_id>/", views.secator_profile_detail, name="profile_detail"),
    path("profiles/<int:profile_id>/update/", views.update_profile, name="update_profile"),
    path("profiles/<int:profile_id>/set-default/", views.set_default_profile, name="set_default_profile"),
    path("profiles/<int:profile_id>/delete/", views.delete_profile, name="delete_profile"),
    path("scans/", views.secator_scans, name="scans"),
    path("scans/add/", views.add_scan, name="add_scan"),
    path("scans/<int:scan_id>/", views.secator_scan_detail, name="scan_detail"),
    path("scans/<int:scan_id>/update/", views.update_scan, name="update_scan"),
    path("scans/<int:scan_id>/delete/", views.delete_scan, name="delete_scan"),
    # Secator workers (remote deployment)
    path("workers/", views.worker_list, name="worker_list"),
    path("workers/add/", views.worker_add, name="worker_add"),
    path("workers/<int:worker_id>/update/", views.worker_update, name="worker_update"),
]
