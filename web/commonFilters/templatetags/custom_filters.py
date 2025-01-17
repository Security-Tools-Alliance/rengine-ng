from urllib.parse import urlparse

from django import template
from dashboard.utils import get_user_groups
register = template.Library()


@register.filter(name='split')
def split(value, key):
    return [x.strip() for x in value.split(key)]

@register.filter(name='map')
def map_filter(value, arg):
    return [getattr(item, arg) for item in value]

@register.filter(name='count')
def count(value):
    return len(value.split(','))


@register.filter(name='getpath')
def getpath(value):
    parsed_url = urlparse(value)
    if parsed_url.query:
        return f"{parsed_url.path}?{parsed_url.query}"
    else:
        return parsed_url.path


@register.filter(name='none_or_never')
def none_or_never(value):
    return 'Never' if value is None else value


# https://stackoverflow.com/a/32801096
@register.filter
def next(some_list, current_index):
    """
    Returns the next element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) + 1] # access the next element
    except:
        return '' # return empty string in case of exception

@register.filter
def previous(some_list, current_index):
    """
    Returns the previous element of the list using the current index if it exists.
    Otherwise returns an empty string.
    """
    try:
        return some_list[int(current_index) - 1] # access the previous element
    except:
        return '' # return empty string in case of exception

@register.filter(name='get_user_role')
def get_user_role(user):
    return get_user_groups(user)
