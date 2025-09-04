from django.urls import path

from . import views

urlpatterns = [
    path("<slug:slug>/<int:id>", views.detail_scan, name="detail_scan"),
    path("<slug:slug>/<int:id>/create_report", views.create_report, name="create_report"),
    path("<slug:slug>/<int:id>/delete", views.delete_scan, name="delete_scan"),
    path("<slug:slug>/endpoints", views.all_endpoints, name="all_endpoints"),
    path("<slug:slug>/<int:scan_id>/endpoints/export", views.export_endpoints, name="export_endpoints"),
    path("<slug:slug>/<str:id>/stop", views.stop_scan, name="stop_scan"),
    path("<slug:slug>/<int:scan_id>/subdomains/export", views.export_subdomains, name="export_subdomains"),
    path("<slug:slug>/<int:scan_id>/urls/export", views.export_urls, name="export_http_urls"),
    path("<slug:slug>/<int:id>/visualise", views.visualise, name="visualise"),
    path("<slug:slug>/history", views.scan_history, name="scan_history"),
    path("<slug:slug>/multiple/start", views.start_multiple_scan, name="start_multiple_scan"),
    path("<slug:slug>/multiple/delete", views.delete_scans, name="delete_multiple_scans"),
    path(
        "<slug:slug>/organization/schedule/<int:id>",
        views.schedule_organization_scan,
        name="schedule_organization_scan",
    ),
    path("<slug:slug>/organization/start/<int:id>", views.start_organization_scan, name="start_organization_scan"),
    path("<slug:slug>/target/start/<int:domain_id>", views.start_scan_ui, name="start_scan"),
    path("<slug:slug>/target/schedule/<int:host_id>", views.schedule_scan, name="schedule_scan"),
    path("<slug:slug>/scheduled", views.scheduled_scan_view, name="scheduled_scan_view"),
    path("<slug:slug>/scheduled_task/delete/<int:id>", views.delete_scheduled_task, name="delete_scheduled_task"),
    path(
        "<slug:slug>/scheduled_task/toggle/<int:id>",
        views.change_scheduled_task_status,
        name="change_scheduled_task_status",
    ),
    path("<slug:slug>/scan_results/delete", views.delete_all_scan_results, name="delete_all_scan_results"),
    path("<slug:slug>/screenshots/delete", views.delete_all_screenshots, name="delete_all_screenshots"),
    path("<slug:slug>/subdomains", views.all_subdomains, name="all_subdomains"),
    path("<slug:slug>/subscan/history", views.subscan_history, name="subscan_history"),
    path("<slug:slug>/vulnerabilities", views.detail_vuln_scan, name="all_vulns"),
    path("<slug:slug>/vulnerability/<int:id>", views.detail_vuln_scan, name="detail_vuln_scan"),
    path("<slug:slug>/vulnerability/toggle/<int:id>", views.change_vuln_status, name="change_vuln_status"),
]
