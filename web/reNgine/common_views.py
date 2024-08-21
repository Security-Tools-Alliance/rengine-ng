from django.conf import settings
from django.shortcuts import render
from django.template import RequestContext
from django.utils.module_loading import import_string

def permission_denied(request, slug):
    context = RequestContext(request)
    
    # Applying manually the context processors
    for processor in settings.TEMPLATES[0]['OPTIONS']['context_processors']:
        if isinstance(processor, str):
            processor = import_string(processor)
        context.update(processor(request))
    
    return render(request, 'common/permission_denied.html', context.flatten(), status=403)