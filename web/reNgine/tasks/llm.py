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
from django.db import transaction

logger = Logger(True)

@app.task(name='llm_vulnerability_description', bind=False, queue='cpu_queue')
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

    # Perform all DB operations in a single transaction for better performance
    with transaction.atomic():
        # Get all matching vulnerabilities at once
        vulns_to_update = list(Vulnerability.objects.filter(
            name=lookup_vulnerability.name, 
            http_url__icontains=path
        ))

        if not vulns_to_update:
            logger.info(f"No vulnerabilities found matching name={lookup_vulnerability.name} and path={path}")
            return response

        # Pre-create all references at once to avoid repeated get_or_create calls
        reference_urls = response.get('references', [])
        ref_objects = {}

        if reference_urls:
            # First, get existing references
            existing_refs = VulnerabilityReference.objects.filter(url__in=reference_urls)
            for ref in existing_refs:
                ref_objects[ref.url] = ref

            if missing_urls := [
                url for url in reference_urls if url not in ref_objects
            ]:
                new_refs = [VulnerabilityReference(url=url) for url in missing_urls]
                VulnerabilityReference.objects.bulk_create(new_refs, ignore_conflicts=True)

                # Get the newly created references
                for ref in VulnerabilityReference.objects.filter(url__in=missing_urls):
                    ref_objects[ref.url] = ref

        # Update all vulnerabilities
        for vuln in vulns_to_update:
            vuln.description = response.get('description', vuln.description)
            vuln.impact = response.get('impact')
            vuln.remediation = response.get('remediation')
            vuln.is_gpt_used = True

            if reference_urls:
                # Add all references at once
                refs_to_add = [ref_objects[url] for url in reference_urls]
                vuln.references.add(*refs_to_add)

        # Save all vulnerabilities in bulk if possible
        # Note: Since we're modifying a M2M relationship, we can't use bulk_update
        # We need to save each object individually, but at least we batch the adds
        for vuln in vulns_to_update:
            vuln.save()

    logger.info(f"Updated {len(vulns_to_update)} vulnerabilities with GPT-generated information")
    return response
