from django.contrib import admin

from dashboard.models import NetlasAPIKey, OllamaSettings, OpenAiAPIKey, Project, SearchHistory

admin.site.register(SearchHistory)
admin.site.register(Project)
admin.site.register(OllamaSettings)
admin.site.register(OpenAiAPIKey)
admin.site.register(NetlasAPIKey)
