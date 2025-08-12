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

        stored = LLMVulnerabilityReport.objects.filter(
            url_path=path, title=title
        ).first()

        def _is_empty_text(value) -> bool:
            try:
                if value is None:
                    return True
                text = str(value).strip()
                if not text:
                    return True
                # Treat list-like empties as empty as well
                normalized = text.replace('\n', '').replace('\r', '').replace(' ', '')
                if normalized in ('[]', '[\"\"]', '[\'\']', 'null', 'None'):
                    return True
                return False
            except Exception:
                return True

        def _is_empty_report(model_obj: LLMVulnerabilityReport) -> bool:
            try:
                fields = [
                    model_obj.description,
                    model_obj.impact,
                    model_obj.remediation,
                    model_obj.references,
                ]
                return all(_is_empty_text(f) for f in fields)
            except Exception:
                return True

        if stored and not _is_empty_report(stored):
            response = {
                'status': True,
                'description': stored.formatted_description,
                'impact': stored.formatted_impact,
                'remediation': stored.formatted_remediation,
                'references': stored.formatted_references,
            }
            logger.info(f'Found stored report: {stored}')
        else:
            # Generate or regenerate report when not found or empty
            vulnerability_description = get_llm_vuln_input_description(title, path)
            llm_generator = LLMVulnerabilityReportGenerator()
            response = llm_generator.get_vulnerability_report(vulnerability_description)

            # Only persist non-empty successful responses
            raw_description = response.get('description')
            raw_impact = response.get('impact')
            raw_remediation = response.get('remediation')
            raw_references = response.get('references')

            # Normalize list-like empty references
            if _is_empty_text(raw_references):
                raw_references = ''

            has_content = any(not _is_empty_text(v) for v in [raw_description, raw_impact, raw_remediation, raw_references])

            if response.get('status') and has_content:
                if stored:
                    # Update existing empty record
                    stored.description = raw_description
                    stored.impact = raw_impact
                    stored.remediation = raw_remediation
                    stored.references = raw_references
                    stored.save()
                    logger.info('Updated existing empty LLM report in database')
                else:
                    # Store new report
                    llm_report = LLMVulnerabilityReport(
                        url_path=path,
                        title=title,
                        description=raw_description,
                        impact=raw_impact,
                        remediation=raw_remediation,
                        references=raw_references,
                    )
                    llm_report.save()
                    logger.info('Added new report to database')
            else:
                logger.warning('LLM report generation returned empty content; skipping DB save')
                # Ensure response reports failure to trigger UI fallback instead of showing empty fields
                response = {
                    'status': False,
                    'error': 'LLM returned empty response. Please try again or choose a different model.'
                }

        # Update all matching vulnerabilities
        vulnerabilities = Vulnerability.objects.filter(
            name=title,
            http_url__icontains=path
        )

        for vuln in vulnerabilities:
            # Update vulnerability fields only when present
            if isinstance(response.get('description'), str) and not _is_empty_text(response.get('description')):
                vuln.description = response.get('description')
            if isinstance(response.get('impact'), str) and not _is_empty_text(response.get('impact')):
                vuln.impact = response.get('impact')
            if isinstance(response.get('remediation'), str) and not _is_empty_text(response.get('remediation')):
                vuln.remediation = response.get('remediation')
            if isinstance(response.get('references'), str) and not _is_empty_text(response.get('references')):
                vuln.references = response.get('references')
            vuln.is_llm_used = True

            vuln.save()
            logger.info(f'Updated vulnerability {vuln.id} with LLM report')

        if response.get('status'):
            # Normalize list-like empty references again for rendering
            if _is_empty_text(response.get('references')):
                response['references'] = ''
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