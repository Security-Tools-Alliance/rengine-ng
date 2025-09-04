from django.contrib import admin

from .models import (
    Domain,
    DomainInfo,
    DomainRegistration,
    Organization,
    Registrar,
    RelatedDomain,
)

admin.site.register(Domain)
admin.site.register(Organization)
admin.site.register(RelatedDomain)
# admin.site.register(RelatedTLD)
# admin.site.register(NameServers)
admin.site.register(Registrar)
admin.site.register(DomainRegistration)
admin.site.register(DomainInfo)
