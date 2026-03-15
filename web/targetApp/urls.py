from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="targetIndex"),
    path("<slug:slug>/add", views.add_target, name="add_target"),
    path("<slug:slug>/delete/<int:id>", views.delete_target, name="delete_target"),
    path("<slug:slug>/multiple/delete", views.delete_targets, name="delete_multiple_targets"),
    path("<slug:slug>/list", views.list_target, name="list_target"),
    path("<slug:slug>/summary/<int:id>", views.target_summary, name="target_summary"),
    path("<slug:slug>/update/<int:id>", views.update_target, name="update_target"),
    path("<slug:slug>/organization/add", views.add_organization, name="add_organization"),
    path("<slug:slug>/organization/delete/<int:id>", views.delete_organization, name="delete_organization"),
    path("<slug:slug>/organization/list", views.list_organization, name="list_organization"),
    path("<slug:slug>/organization/update/<int:id>", views.update_organization, name="update_organization"),
    path(
        "<slug:slug>/organization/<int:organization_id>/dashboard/",
        views.organization_dashboard,
        name="organization_dashboard",
    ),
    # Scope
    path("<slug:slug>/scope/list", views.list_scope, name="list_scope"),
    path("<slug:slug>/scope/add", views.add_scope, name="add_scope"),
    path("<slug:slug>/scope/update/<int:id>", views.update_scope, name="update_scope"),
    path("<slug:slug>/scope/delete/<int:id>", views.delete_scope, name="delete_scope"),
    path("<slug:slug>/scope/detail/<int:id>", views.scope_detail, name="scope_detail"),
    path("<slug:slug>/scope/normalize", views.scope_normalize, name="scope_normalize"),
    path("<slug:slug>/scope/normalize/apply", views.scope_normalize_apply, name="scope_normalize_apply"),
]
