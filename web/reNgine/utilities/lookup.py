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
    lookup_obj = InterestingLookupModel.objects.order_by('-id').first()
    if not lookup_obj:
        return []
    
    lookup_keywords = [
        key.strip()
        for key in lookup_obj.keywords.split(',')
    ]
    return list(filter(None, lookup_keywords))  # remove empty strings from list 