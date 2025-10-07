from copy import deepcopy
import json
import os
from pathlib import Path

from celery import chain, group
from celery.utils.log import get_task_logger
import yaml

from reNgine.celery import app
from reNgine.celery_custom_task import RengineTask
from reNgine.definitions import (
    OSINT,
    OSINT_CUSTOM_DORK,
    OSINT_DEFAULT_CONFIG,
    OSINT_DISCOVER,
    OSINT_DORK,
)
from reNgine.tasks.command import run_command
from reNgine.utilities.database import save_email, save_employee
from reNgine.utilities.external import get_and_save_dork_results
from scanEngine.models import Proxy
from startScan.models import ScanHistory


logger = get_task_logger(__name__)


@app.task(name="osint", queue="group_queue", base=RengineTask, bind=True)
def osint(self, host=None, ctx=None, description=None):
    """Run Open-Source Intelligence tools on selected domain.

    Args:
        host (str): Hostname to scan.

    Returns:
        dict: Results from osint discovery and dorking.
    """
    if ctx is None:
        ctx = {}
    config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
    results = {}

    grouped_tasks = []

    if "discover" in config:
        logger.info("Starting OSINT Discovery")
        custom_ctx = deepcopy(ctx)
        custom_ctx["track"] = False
        _task = osint_discovery.si(
            config=config,
            host=self.scan.domain.name,
            scan_history_id=self.scan.id,
            activity_id=self.activity_id,
            results_dir=self.results_dir,
            ctx=custom_ctx,
        )
        grouped_tasks.append(_task)

    if OSINT_DORK in config or OSINT_CUSTOM_DORK in config:
        logger.info("Starting OSINT Dorking")
        _task = dorking.si(
            config=config, host=self.scan.domain.name, scan_history_id=self.scan.id, results_dir=self.results_dir
        )
        grouped_tasks.append(_task)

    # Launch OSINT tasks and wait for completion to ensure proper workflow ordering
    if grouped_tasks:
        celery_group = group(grouped_tasks)
        job = celery_group.apply_async()
        logger.info(f"Started {len(grouped_tasks)} OSINT tasks")

        # Wait for all OSINT tasks to complete using allow_join_result to avoid deadlocks
        from celery.result import allow_join_result

        with allow_join_result():
            try:
                results = job.get(propagate=False)  # Don't propagate exceptions
                logger.info("All OSINT tasks completed")

                # Check individual task results and log any failures
                # Convert any exceptions to serializable format
                processed_results = []
                for i, task_result in enumerate(results):
                    if isinstance(task_result, Exception):
                        error_msg = f"{type(task_result).__name__}: {str(task_result)}"
                        logger.error(f"OSINT task {i} failed: {error_msg}")
                        processed_results.append({"error": error_msg, "success": False})
                    else:
                        processed_results.append(task_result)

                results = processed_results

            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                logger.error(f"OSINT tasks group failed: {error_msg}")
                results = {"error": error_msg, "success": False}

    else:
        logger.info("No OSINT tasks to run")
        results = {"success": True, "message": "No OSINT tasks configured"}

    return results


@app.task(name="osint_discovery", queue="io_queue", bind=False)
def osint_discovery(config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run OSINT discovery.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        dict: osint metadat and theHarvester and h8mail results.
    """
    if ctx is None:
        ctx = {}
    # scan_history = ScanHistory.objects.get(pk=scan_history_id)
    osint_lookup = config.get(OSINT_DISCOVER, [])
    # osint_intensity = config.get(INTENSITY, "normal")
    # documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)

    # Get and save meta info
    # if "metainfo" in osint_lookup:
    #     logger.info("Saving Metainfo")
    #     if osint_intensity == "normal":
    #         meta_dict = DottedDict(
    #             {"osint_target": host, "domain": host, "scan_id": scan_history_id, "documents_limit": documents_limit}
    #         )
    #        meta_info = [save_metadata_info(meta_dict)]
    #        TODO: disabled for now
    #        elif osint_intensity == 'deep':
    #        	subdomains = Subdomain.objects
    #        	if self.scan:
    #        		subdomains = subdomains.filter(scan_history=self.scan)
    #        	for subdomain in subdomains:
    #        		meta_dict = DottedDict({
    #        			'osint_target': subdomain.name,
    #        			'domain': self.domain,
    #        			'scan_id': self.scan_id,
    #        			'documents_limit': documents_limit
    #        		})
    #        		meta_info.append(save_metadata_info(meta_dict))

    # Collect tasks - note that theHarvester must run before h8mail
    # to create the emails.txt file that h8mail needs
    sequential_tasks = []
    harvester_task = None
    h8mail_task = None

    if "employees" in osint_lookup:
        logger.info("Lookup for employees")
        custom_ctx = deepcopy(ctx)
        custom_ctx["track"] = False
        harvester_task = the_harvester.si(
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=custom_ctx,
        )
        sequential_tasks.append(harvester_task)

    if "emails" in osint_lookup:
        logger.info("Lookup for emails")
        h8mail_task = h8mail.si(
            config=config,
            host=host,
            scan_history_id=scan_history_id,
            activity_id=activity_id,
            results_dir=results_dir,
            ctx=ctx,
        )
        sequential_tasks.append(h8mail_task)

    # Launch OSINT discovery tasks and wait for completion to ensure proper workflow ordering
    if sequential_tasks:
        # Use chain to execute tasks sequentially (theHarvester first, then h8mail)
        # This ensures emails.txt is created before h8mail tries to read it
        task_chain = chain(sequential_tasks)
        job = task_chain.apply_async()
        logger.info(f"Started {len(sequential_tasks)} OSINT discovery tasks sequentially")

        # Wait for all OSINT discovery tasks to complete using allow_join_result to avoid deadlocks
        from celery.result import allow_join_result

        with allow_join_result():
            try:
                results = job.get(propagate=False)  # Don't propagate exceptions
                logger.info("All OSINT discovery tasks completed")

                # Check individual task results and log any failures
                # Convert any exceptions to serializable format
                processed_results = []
                for i, task_result in enumerate(results):
                    if isinstance(task_result, Exception):
                        error_msg = f"{type(task_result).__name__}: {str(task_result)}"
                        logger.error(f"OSINT discovery task {i} failed: {error_msg}")
                        processed_results.append({"error": error_msg, "success": False})
                    else:
                        processed_results.append(task_result)

                results = processed_results

            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                logger.error(f"OSINT discovery tasks group failed: {error_msg}")
                results = {"error": error_msg, "success": False}

    else:
        logger.info("No OSINT discovery tasks to run")
        results = {"success": True, "message": "No OSINT discovery tasks configured"}

    return results


@app.task(name="dorking", bind=False, queue="io_queue")
def dorking(config, host, scan_history_id, results_dir):
    """Run Google dorks.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        results_dir (str): Path to store scan results

    Returns:
        list: Dorking results for each dork ran.
    """
    # Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    dorks = config.get(OSINT_DORK, [])
    custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
    results = []

    def safe_dork_execution(dork_func, dork_name, dork_config=None):
        """Execute dork function safely with error handling."""
        try:
            return dork_func()
        except Exception as e:
            logger.warning(f"{dork_name} failed: {e}")
            return []

    def execute_dork_with_error_handling(**kwargs):
        """Execute get_and_save_dork_results and return only results."""
        result = get_and_save_dork_results(**kwargs)
        return result.get("results", [])

    # custom dorking has higher priority
    for custom_dork in custom_dorks:

        def execute_custom_dork():
            lookup_target = custom_dork.get("lookup_site")
            # replace with original host if _target_
            lookup_target = host if lookup_target == "_target_" else lookup_target
            if "lookup_extensions" in custom_dork:
                result = get_and_save_dork_results(
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type="custom_dork",
                    lookup_extensions=custom_dork.get("lookup_extensions"),
                    scan_history=scan_history,
                )
                return result.get("results", [])
            elif "lookup_keywords" in custom_dork:
                result = get_and_save_dork_results(
                    lookup_target=lookup_target,
                    results_dir=results_dir,
                    type="custom_dork",
                    lookup_keywords=custom_dork.get("lookup_keywords"),
                    scan_history=scan_history,
                )
                return result.get("results", [])
            return []

        results.extend(safe_dork_execution(execute_custom_dork, f"Custom dork {custom_dork}"))

    # default dorking
    for dork in dorks:
        logger.info(f"Getting dork information for {dork}")

        def execute_dork():
            if dork == "stackoverflow":
                return execute_dork_with_error_handling(
                    lookup_target="stackoverflow.com",
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords=host,
                    scan_history=scan_history,
                )
            elif dork == "login_pages":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/login/,login.html",
                    page_count=5,
                    scan_history=scan_history,
                )
            elif dork == "admin_panels":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/admin/,admin.html",
                    page_count=5,
                    scan_history=scan_history,
                )
            elif dork == "dashboard_pages":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/dashboard/,dashboard.html",
                    page_count=5,
                    scan_history=scan_history,
                )
            elif dork == "social_media":
                social_websites = ["tiktok.com", "facebook.com", "twitter.com", "youtube.com", "reddit.com"]
                dork_results = []
                for site in social_websites:
                    dork_results.extend(
                        execute_dork_with_error_handling(
                            lookup_target=site,
                            results_dir=results_dir,
                            type=dork,
                            lookup_keywords=host,
                            scan_history=scan_history,
                        )
                    )
                return dork_results
            elif dork == "project_management":
                project_websites = ["trello.com", "atlassian.net"]
                dork_results = []
                for site in project_websites:
                    dork_results.extend(
                        execute_dork_with_error_handling(
                            lookup_target=site,
                            results_dir=results_dir,
                            type=dork,
                            lookup_keywords=host,
                            scan_history=scan_history,
                        )
                    )
                return dork_results
            elif dork == "code_sharing":
                project_websites = ["github.com", "gitlab.com", "bitbucket.org"]
                dork_results = []
                for site in project_websites:
                    dork_results.extend(
                        execute_dork_with_error_handling(
                            lookup_target=site,
                            results_dir=results_dir,
                            type=dork,
                            lookup_keywords=host,
                            scan_history=scan_history,
                        )
                    )
                return dork_results
            elif dork == "config_files":
                config_file_exts = [
                    "env",
                    "xml",
                    "conf",
                    "toml",
                    "yml",
                    "yaml",
                    "cnf",
                    "inf",
                    "rdp",
                    "ora",
                    "txt",
                    "cfg",
                    "ini",
                ]
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(config_file_exts),
                    page_count=4,
                    scan_history=scan_history,
                )
            elif dork == "jenkins":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="Jenkins",
                    page_count=1,
                    scan_history=scan_history,
                )
            elif dork == "wordpress_files":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="/wp-content/,/wp-includes/",
                    page_count=5,
                    scan_history=scan_history,
                )
            elif dork == "php_error":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_keywords="PHP Parse error,PHP Warning,PHP Error",
                    page_count=5,
                    scan_history=scan_history,
                )
            elif dork == "exposed_documents":
                docs_file_ext = ["doc", "docx", "odt", "pdf", "rtf", "sxw", "psw", "ppt", "pptx", "pps", "csv"]
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions=",".join(docs_file_ext),
                    page_count=7,
                    scan_history=scan_history,
                )
            elif dork == "db_files":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions="sql,db,dbf,mdb",
                    page_count=1,
                    scan_history=scan_history,
                )
            elif dork == "git_exposed":
                return execute_dork_with_error_handling(
                    lookup_target=host,
                    results_dir=results_dir,
                    type=dork,
                    lookup_extensions="git",
                    page_count=1,
                    scan_history=scan_history,
                )
            return []

        results.extend(safe_dork_execution(execute_dork, f"Dork {dork}"))
    return results


@app.task(name="theHarvester", queue="run_command_queue", bind=False)
def the_harvester(config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run theHarvester to get save emails, hosts, employees found in domain.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        dict: Dict of emails, employees, hosts and ips found during crawling.
    """
    from reNgine.utilities.database import save_endpoint, validate_and_save_subdomain
    from reNgine.utilities.url import get_subdomain_from_url

    if ctx is None:
        ctx = {}
    scan_history = ScanHistory.objects.get(pk=scan_history_id)
    output_path_json = str(Path(results_dir) / "theHarvester.json")
    the_harvester_dir = str(Path.home() / ".config" / "theHarvester")
    history_file = str(Path(results_dir) / "commands.txt")

    # Create empty JSON file if it doesn't exist, handling race conditions atomically
    try:
        with open(output_path_json, "x") as f:
            json.dump({"emails": [], "hosts": [], "ips": [], "employees": []}, f)
    except FileExistsError:
        # File was created by another process in the meantime, safe to ignore
        pass

    cmd = f"theHarvester -d {host} -f {output_path_json} -b baidu,bevigil,bing,bingapi,bufferoverun,brave,censys,certspotter,criminalip,crtsh,dnsdumpster,duckduckgo,fullhunt,hackertarget,hunter,hunterhow,intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,securityTrails,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,tomba,urlscan,virustotal,yahoo,zoomeye"

    # Update proxies.yaml
    proxy_query = Proxy.objects.all()
    if proxy_query.exists():
        proxy = proxy_query.first()
        if proxy.use_proxy:
            proxy_list = proxy.proxies.splitlines()
            yaml_data = {"http": proxy_list}
            with open(Path(the_harvester_dir) / "proxies.yaml", "w") as file:
                yaml.dump(yaml_data, file)

    # Run cmd
    run_command(
        cmd,
        shell=False,
        cwd=the_harvester_dir,
        history_file=history_file,
        scan_id=scan_history_id,
        activity_id=activity_id,
    )

    # Get file location
    if not os.path.isfile(output_path_json):
        logger.error(f"Could not open {output_path_json}")
        return {}

    # Load theHarvester results
    try:
        with open(output_path_json, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to read or parse theHarvester output file: {e}")
        raise

    # Re-indent theHarvester JSON
    try:
        with open(output_path_json, "w") as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        logger.error(f"Failed to re-indent theHarvester output file: {e}")
        # Continue anyway as we have the data loaded

    emails = data.get("emails", [])

    # Save emails to database
    for email_address in emails:
        email, _ = save_email(email_address, scan_history=scan_history)
        # if email:
        # 	self.notify(fields={'Emails': f'• `{email.address}`'})

    # Create emails.txt file for h8mail to use
    emails_txt_path = str(Path(results_dir) / "emails.txt")
    try:
        with open(emails_txt_path, "w") as emails_file:
            for email_address in emails:
                emails_file.write(f"{email_address}\n")
        logger.info(f"Created emails.txt with {len(emails)} email(s) at {emails_txt_path}")
    except IOError as e:
        logger.error(f"Failed to create emails.txt file: {e}")

    linkedin_people = data.get("linkedin_people", [])
    for people in linkedin_people:
        employee, _ = save_employee(people, designation="linkedin", scan_history=scan_history)
        # if employee:
        # 	self.notify(fields={'LinkedIn people': f'• {employee.name}'})

    twitter_people = data.get("twitter_people", [])
    for people in twitter_people:
        employee, _ = save_employee(people, designation="twitter", scan_history=scan_history)
        # if employee:
        # 	self.notify(fields={'Twitter people': f'• {employee.name}'})

    hosts = data.get("hosts", [])
    for host in hosts:
        split = tuple(host.split(":"))
        http_url = split[0]
        subdomain_name = get_subdomain_from_url(http_url)
        subdomain, _ = validate_and_save_subdomain(subdomain_name, ctx=ctx)
        if subdomain is None:
            continue
        endpoint, _ = save_endpoint(http_url, ctx=ctx, subdomain=subdomain)
        # if endpoint:
        # 	urls.append(endpoint.http_url)
        # self.notify(fields={'Hosts': f'• {endpoint.http_url}'})

    # TODO: Lots of ips unrelated with our domain are found, disabling
    # this for now.
    # ips = data.get('ips', [])
    # for ip_address in ips:
    # 	ip, created = save_ip_address(
    # 		ip_address,
    # 		subscan=subscan)
    # 	if ip:
    # 		send_task_notif.delay(
    # 			'osint',
    # 			scan_history_id=scan_history_id,
    # 			subscan_id=subscan_id,
    # 			severity='success',
    # 			update_fields={'IPs': f'{ip.address}'})
    return data


@app.task(name="h8mail", queue="run_command_queue", bind=False)
def h8mail(config, host, scan_history_id, activity_id, results_dir, ctx=None):
    """Run h8mail.

    Args:
        config (dict): yaml_configuration
        host (str): target name
        scan_history_id (startScan.ScanHistory): Scan History ID
        activity_id: ScanActivity ID
        results_dir (str): Path to store scan results
        ctx (dict): context of scan

    Returns:
        list[dict]: List of credentials info.
    """
    if ctx is None:
        ctx = {}
    logger.warning("Getting leaked credentials")
    # scan_history = ScanHistory.objects.get(pk=scan_history_id)
    input_path = str(Path(results_dir) / "emails.txt")
    output_file = str(Path(results_dir) / "h8mail.json")

    # Check if emails.txt file exists
    if not os.path.isfile(input_path):
        logger.error(f"Emails file not found at {input_path}. Aborting h8mail scan.")
        raise FileNotFoundError(f"Emails file not found at {input_path}")

    # Check if emails.txt is empty
    if os.path.getsize(input_path) == 0:
        logger.error(f"Emails file is empty at {input_path}. Aborting h8mail scan.")
        raise ValueError(f"Emails file is empty at {input_path}")

    cmd = f"h8mail -t {input_path} --json {output_file}"
    history_file = str(Path(results_dir) / "commands.txt")

    run_command(cmd, history_file=history_file, scan_id=scan_history_id, activity_id=activity_id)

    # Check if output file exists before trying to open it
    if not os.path.isfile(output_file):
        logger.error(f"h8mail output file not found at {output_file}. The command may have failed.")
        raise FileNotFoundError(f"h8mail output file not found at {output_file}. The command may have failed.")

    try:
        with open(output_file) as f:
            data = json.load(f)
            creds = data.get("targets", [])
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to read or parse h8mail output file: {e}")
        return []

    # TODO: go through h8mail output and save emails to DB
    # for cred in creds:
    #     logger.warning(cred)
    #     email_address = cred["target"]
    #     pwn_num = cred["pwn_num"]
    #     pwn_data = cred.get("data", [])
    #     email, created = save_email(email_address, scan_history=scan_history)
    #     if email:
    #    	self.notify(fields={'Emails': f'• `{email.address}`'})
    return creds
