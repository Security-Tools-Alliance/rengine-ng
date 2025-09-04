from django.contrib import admin

from scanEngine.models import (
    Configuration,
    EngineType,
    InstalledExternalTool,
    InterestingLookupModel,
    Notification,
    VulnerabilityReportSetting,
    Wordlist,
)

# Register your models here.
admin.site.register(EngineType)
admin.site.register(Wordlist)
admin.site.register(Configuration)
admin.site.register(InterestingLookupModel)
admin.site.register(Notification)
admin.site.register(VulnerabilityReportSetting)
admin.site.register(InstalledExternalTool)
