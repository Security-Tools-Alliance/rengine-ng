from django.contrib import admin
from django.urls import include, path
from reNgine.settings import UI_DEBUG

from . import views

urlpatterns = [
    path(
        '',
        views.onboarding,
        name='onboarding'),
    path(
        'dashboard/<slug:slug>',
        views.index,
        name='dashboardIndex'),
    path(
        'profile/',
        views.profile,
        name='profile'),
    path(
        'admin_interface/',
        views.admin_interface,
        name='admin_interface'),
    path(
        'admin_interface/update',
        views.admin_interface_update,
        name='admin_interface_update'),
    path(
        'search',
        views.search,
        name='search'),
    path(
        '404/',
        views.four_oh_four,
        name='four_oh_four'),
    path(
        'project/list',
        views.projects,
        name='list_projects'),
    path(
        'project/delete/<int:id>',
        views.delete_project,
        name='delete_project'),
    path(
        'project/edit/<slug:slug>',
        views.edit_project,
        name='edit_project'),
    path(
        'project/set_current/<slug:slug>',
        views.set_current_project,
        name='set_current_project'),
]

if UI_DEBUG:
    urlpatterns.append(path("__debug__/", include("debug_toolbar.urls")))