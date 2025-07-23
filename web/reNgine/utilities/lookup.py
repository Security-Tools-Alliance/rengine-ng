from celery.utils.log import get_task_logger
from scanEngine.models import InterestingLookupModel

logger = get_task_logger(__name__)


#--------------------------------#
# InterestingLookupModel queries #
#--------------------------------#

def get_lookup_keywords():
    """Get lookup keywords from InterestingLookupModel.

    Returns:
        list: Lookup keywords.
    """
    lookup_model = InterestingLookupModel.objects.first()
    lookup_obj = InterestingLookupModel.objects.filter().order_by('-id').first()
    custom_lookup_keywords = []
    default_lookup_keywords = []
    if lookup_model:
        default_lookup_keywords = [
            key.strip()
            for key in lookup_model.keywords.split(',')]
    if lookup_obj:
        custom_lookup_keywords = [
            key.strip()
            for key in lookup_obj.keywords.split(',')
        ]
    lookup_keywords = default_lookup_keywords + custom_lookup_keywords
    lookup_keywords = list(filter(None, lookup_keywords)) # remove empty strings from list
    return lookup_keywords 