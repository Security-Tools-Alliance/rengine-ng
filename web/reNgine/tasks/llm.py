from urllib.parse import urlparse

from celery.utils.log import get_task_logger

from reNgine.celery import app
from reNgine.llm.llm import LLMVulnerabilityReportGenerator
from reNgine.llm.utils import get_llm_vuln_input_description, convert_markdown_to_html
from startScan.models import Vulnerability, LLMVulnerabilityReport

logger = get_task_logger(__name__)


@app.task(name='llm_vulnerability_report', bind=False, queue='cpu_queue')
def llm_vulnerability_report(vulnerability_id=None, vuln_tuple=None):
    """
    Generate and store Vulnerability Report using LLM.
    Can be called either with a vulnerability_id or a vuln_tuple (title, path)

    Args:
        vulnerability_id (int, optional): Vulnerability ID to fetch Description
        vuln_tuple (tuple, optional): Tuple containing (title, path)
    
    Returns:
        dict: LLM response containing description, impact, remediation and references
    """
    logger.info('Getting LLM Vulnerability Description')
    try:
        # Get title and path from either vulnerability_id or vuln_tuple
        if vulnerability_id:
            lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
            lookup_url = urlparse(lookup_vulnerability.http_url)
            title = lookup_vulnerability.name
            path = lookup_url.path
        elif vuln_tuple:
            title, path = vuln_tuple
        else:
            raise ValueError("Either vulnerability_id or vuln_tuple must be provided")

        logger.info(f'Processing vulnerability: {title}, PATH: {path}')

        if stored := LLMVulnerabilityReport.objects.filter(
            url_path=path, title=title
        ).first():
            response = {
                'status': True,
                'description': stored.formatted_description,
                'impact': stored.formatted_impact,
                'remediation': stored.formatted_remediation,
                'references': stored.formatted_references,
            }
            logger.info(f'Found stored report: {stored}')
        else:
            # Generate new report
            vulnerability_description = get_llm_vuln_input_description(title, path)
            llm_generator = LLMVulnerabilityReportGenerator()
            response = llm_generator.get_vulnerability_report(vulnerability_description)

            # Store new report in database
            llm_report = LLMVulnerabilityReport()
            llm_report.url_path = path
            llm_report.title = title
            llm_report.description = response.get('description')
            llm_report.impact = response.get('impact')
            llm_report.remediation = response.get('remediation')
            llm_report.references = response.get('references')
            llm_report.save()
            logger.info('Added new report to database')

        # Update all matching vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(
            name=title,
            http_url__icontains=path
        )

        for vuln in vulnerabilities:
            # Update vulnerability fields
            vuln.description = response.get('description', vuln.description)
            vuln.impact = response.get('impact')
            vuln.remediation = response.get('remediation')
            vuln.is_llm_used = True
            vuln.references = response.get('references')

            vuln.save()
            logger.info(f'Updated vulnerability {vuln.id} with LLM report')

        response['description'] = convert_markdown_to_html(response.get('description', ''))
        response['impact'] = convert_markdown_to_html(response.get('impact', ''))
        response['remediation'] = convert_markdown_to_html(response.get('remediation', ''))
        response['references'] = convert_markdown_to_html(response.get('references', ''))

        return response

    except Exception as e:
        error_msg = f"Error in get_vulnerability_report: {str(e)}"
        logger.error(error_msg)
        return {
            'status': False,
            'error': error_msg
        } 