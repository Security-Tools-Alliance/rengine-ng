"""
URL patterns for Secator workflow management.
"""

from django.urls import path

from . import views_secator_workflows


urlpatterns = [
    # Workflow management
    path("workflows/", views_secator_workflows.SecatorWorkflowListView.as_view(), name="secator_workflow_list"),
    path(
        "workflows/create/", views_secator_workflows.SecatorWorkflowCreateView.as_view(), name="secator_workflow_create"
    ),
    path(
        "workflows/<str:workflow_id>/<str:workflow_type>/",
        views_secator_workflows.SecatorWorkflowDetailView.as_view(),
        name="secator_workflow_detail",
    ),
    path(
        "workflows/<str:workflow_id>/<str:workflow_type>/edit/",
        views_secator_workflows.SecatorWorkflowEditView.as_view(),
        name="secator_workflow_edit",
    ),
    path(
        "workflows/<str:workflow_id>/<str:workflow_type>/delete/",
        views_secator_workflows.SecatorWorkflowDeleteView.as_view(),
        name="secator_workflow_delete",
    ),
    path(
        "workflows/<str:workflow_id>/<str:workflow_type>/task/<str:task_id>/",
        views_secator_workflows.SecatorWorkflowTaskConfigView.as_view(),
        name="secator_workflow_task_config",
    ),
    # API endpoints
    path("api/workflows/", views_secator_workflows.SecatorWorkflowAPIView.as_view(), name="secator_workflow_api"),
]
