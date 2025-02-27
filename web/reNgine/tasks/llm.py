from urllib.parse import urlparse

from reNgine.celery import app
from reNgine.utils.logger import Logger
from reNgine.gpt import (
    GPTVulnerabilityReportGenerator
)
from reNgine.utils.utils import (
    get_gpt_vuln_input_description,
)
from startScan.models import (
    GPTVulnerabilityReport,
    Vulnerability,
    VulnerabilityReference,
)

logger = Logger(True)

@app.task(name='llm_vulnerability_description', bind=False, queue='gpt_queue')
def llm_vulnerability_description(vulnerability_id):
    """Generate and store Vulnerability Description using GPT.

    Args:
        vulnerability_id (Vulnerability Model ID): Vulnerability ID to fetch Description.
    """
    from reNgine.utils.db import add_gpt_description_db

    logger.info('Getting GPT Vulnerability Description')
    try:
        lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
        lookup_url = urlparse(lookup_vulnerability.http_url)
        path = lookup_url.path
    except Exception as e:
        return {
            'status': False,
            'error': str(e)
        }

    if (
        stored := GPTVulnerabilityReport.objects.filter(url_path=path)
        .filter(title=lookup_vulnerability.name)
        .first()
    ):
        response = {
            'status': True,
            'description': stored.description,
            'impact': stored.impact,
            'remediation': stored.remediation,
            'references': [url.url for url in stored.references.all()]
        }
    else:
        vulnerability_description = get_gpt_vuln_input_description(
            lookup_vulnerability.name,
            path
        )
        # One can add more description here later

        gpt_generator = GPTVulnerabilityReportGenerator()
        response = gpt_generator.get_vulnerability_description(vulnerability_description)
        add_gpt_description_db(
            lookup_vulnerability.name,
            path,
            response.get('description'),
            response.get('impact'),
            response.get('remediation'),
            response.get('references', [])
        )

    # For all vulnerabilities with the same vulnerability name this description has to be stored.
    # Also the condition is that the url must contain a part of this.
    for vuln in Vulnerability.objects.filter(name=lookup_vulnerability.name, http_url__icontains=path):
        vuln.description = response.get('description', vuln.description)
        vuln.impact = response.get('impact')
        vuln.remediation = response.get('remediation')
        vuln.is_gpt_used = True
        vuln.save()

        for url in response.get('references', []):
            ref, created = VulnerabilityReference.objects.get_or_create(url=url)
            vuln.references.add(ref)
            vuln.save()

    return response
