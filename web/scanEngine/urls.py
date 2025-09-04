from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="scan_engine_index"),
    path("add/", views.add_engine, name="add_engine"),
    path("delete/<int:id>", views.delete_engine, name="delete_engine_url"),
    path("update/<int:id>", views.update_engine, name="update_engine"),
    path("api_vault", views.api_vault, name="api_vault"),
    path("api_vault/delete", views.api_vault_delete, name="api_vault_delete"),
    path("hackerone_settings", views.hackerone_settings, name="hackerone_settings"),
    path("interesting/lookup", views.interesting_lookup, name="interesting_lookup"),
    path("llm_toolkit", views.llm_toolkit_section, name="llm_toolkit"),
    path("notification_settings", views.notification_settings, name="notification_settings"),
    path("proxy_settings", views.proxy_settings, name="proxy_settings"),
    path("rengine_settings", views.rengine_settings, name="rengine_settings"),
    path("report_settings", views.report_settings, name="report_settings"),
    path("testHackerone", views.test_hackerone, name="testHackerone"),
    path("tool_arsenal", views.tool_arsenal_section, name="tool_arsenal"),
    path("tool_arsenal/add", views.add_tool, name="add_tool"),
    path("tool_arsenal/update/<int:id>", views.modify_tool_in_arsenal, name="update_tool_in_arsenal"),
    path("tool_settings", views.tool_specific_settings, name="tool_settings"),
    path("wordlist", views.wordlist_list, name="wordlist_list"),
    path("wordlist/delete/<int:id>", views.delete_wordlist, name="delete_wordlist"),
    path("wordlist/add", views.add_wordlist, name="add_wordlist"),
]
