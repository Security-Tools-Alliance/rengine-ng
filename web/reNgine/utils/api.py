from dashboard.models import OpenAiAPIKey, NetlasAPIKey

def get_open_ai_key():
    """Get OpenAI API key from database"""
    try:
        api_key = OpenAiAPIKey.objects.first()
        return api_key.key if api_key else None
    except Exception:
        return None 

def get_netlas_key():
    """Get Netlas API key from database"""
    try:
        api_key = NetlasAPIKey.objects.first()
        return api_key.key if api_key else None
    except Exception:
        return None 