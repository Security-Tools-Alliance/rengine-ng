import requests
from bs4 import BeautifulSoup
from celery.utils.log import get_task_logger
from dashboard.models import OpenAiAPIKey, NetlasAPIKey

logger = get_task_logger(__name__)


#-----------------#
# External Services #
#-----------------#

def reverse_whois(lookup_keyword):
    domains = []
    '''
        This function will use viewdns to fetch reverse whois info
        Input: lookup keyword like email or registrar name
        Returns a list of domains as string.
    '''
    url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://viewdns.info/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
    }
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, 'lxml')
    table = soup.find("table", {"border" : "1"})
    for row in table or []:
        dom = row.findAll('td')[0].getText()
        created_on = row.findAll('td')[1].getText()
        if dom == 'Domain Name':
            continue
        domains.append({'name': dom, 'created_on': created_on})
    return domains


def get_domain_historical_ip_address(domain):
    ips = []
    '''
        This function will use viewdns to fetch historical IP address
        for a domain
    '''
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    headers = {
        "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Linux\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Referer": "https://viewdns.info/",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
    }
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.content, 'lxml')
    table = soup.find("table", {"border" : "1"})
    for row in table or []:
        ip = row.findAll('td')[0].getText()
        location = row.findAll('td')[1].getText()
        owner = row.findAll('td')[2].getText()
        last_seen = row.findAll('td')[2].getText()
        if ip == 'IP Address':
            continue
        ips.append(
            {
                'ip': ip,
                'location': location,
                'owner': owner,
                'last_seen': last_seen,
            }
        )
    return ips


def get_open_ai_key():
    openai_key = OpenAiAPIKey.objects.all()
    return openai_key[0] if openai_key else None


def get_netlas_key():
    netlas_key = NetlasAPIKey.objects.all()
    return netlas_key[0] if netlas_key else None


# TODO Implement associated domains
def get_associated_domains(keywords):
    return [] 