from pathlib import Path
import shlex

from reNgine.definitions import USE_SUBFINDER_CONFIG
from reNgine.utils.logger import default_logger as logger
from reNgine.utils.api import get_netlas_key

class CommandBuilder:
    """Secure command builder that prevents shell injection"""
    
    def __init__(self, base_command):
        """Initialize with base command
        
        Args:
            base_command (str): Base command to execute
        """
        self.command = [base_command]
        self.options = []
        self.redirection = None
        self.arguments = []
        
    def add_raw_option(self, option):
        """Add raw command-line option without value"""
        self.options.append(option)
        return self

    def add_option(self, option, value=None, condition=True):
        """Add a command line option if condition is met
        
        Args:
            option (str): Option flag (e.g. "-p")
            value (str, optional): Option value if any
            condition (bool, optional): Only add if True
            
        Returns:
            CommandBuilder: Self for chaining
        """
        if not condition:
            return self
            
        if value is not None:
            # Add as separate arguments to prevent injection
            self.options.append(option)
            self.options.append(str(value))
        else:
            self.options.append(option)
            
        return self

    def add_redirection(self, operator, filename):
        """Add an output redirection
        
        Args:
            operator (str): Redirection operator (e.g. '>', '>>')
            filename (str): File to redirect output to
            
        Returns:
            CommandBuilder: Self for chaining
        """
        self.redirection = (operator, filename)
        return self
    
    def build_list(self):
        """Build command as a list for subprocess
        
        Returns:
            list: Command as list of arguments
        """
        # Start with the base command
        cmd = [self.command[0]]
        
        # Add all options as individual arguments
        for option in self.options:
            if isinstance(option, list):
                cmd.extend(option)
            else:
                cmd.append(option)
        
        # Add redirection if present
        if self.redirection:
            cmd.extend([self.redirection[0], self.redirection[1]])
        
        # Add arguments
        cmd.extend(self.arguments)
        
        logger.debug(f"🔍 Build list Command: {cmd}")
        return cmd
        
    def build_string(self):
        """Build command as a string (only for display, not execution)
        
        Returns:
            str: Command as properly quoted string
        """
        # Start with the base command
        cmd_parts = [shlex.quote(self.command[0])]

        # Add all options as individual quoted arguments
        for option in self.options:
            if isinstance(option, list):
                cmd_parts.extend([shlex.quote(str(part)) for part in option])
            else:
                cmd_parts.append(shlex.quote(str(option)))

        # Add redirection if present
        if self.redirection:
            cmd_parts.append(self.redirection[0])
            cmd_parts.append(shlex.quote(self.redirection[1]))

        # Add arguments
        cmd_parts.extend(shlex.quote(arg) for arg in self.arguments)
        # Join all parts with spaces
        cmd_string = ' '.join(cmd_parts)
        logger.debug(f"🔍 Build string Command: {cmd_string}")
        return cmd_string

    def set_env(self, env_var, value):
        """Set an environment variable for the command"""
        self.options.append(f'{env_var}={value}')
        return self

def build_piped_command(commands, output_file=None, append=False):
    """Build a piped command securely using CommandBuilder.
    
    Args:
        commands (list): List of CommandBuilder objects to pipe together
        output_file (str, optional): File to output to (using tee)
        append (bool, optional): Whether to append to output file 
        
    Returns:
        CommandBuilder: Final piped command
    """
    import shlex
    import tempfile
    
    # Build each command
    command_strings = []
    for cmd_builder in commands:
        cmd_list = cmd_builder.build_list()
        # Escape each argument individually
        escaped_args = [shlex.quote(arg) for arg in cmd_list]
        # Join the escaped arguments
        command_strings.append(" ".join(escaped_args))
    
    # Join commands with pipes
    base_cmd = " | ".join(command_strings)
    
    # Add output redirection if needed
    if output_file:
        if append:
            base_cmd += f" >> {shlex.quote(output_file)}"
        else:
            base_cmd += f" | tee {shlex.quote(output_file)}"
    
    # Create a temporary shell script
    temp_script = tempfile.NamedTemporaryFile(delete=False, suffix='.sh')
    temp_script.write(f"#!/bin/bash\n{base_cmd}\n".encode())
    temp_script.close()
    
    # Make script executable
    import os
    os.chmod(temp_script.name, 0o755)
    
    # Return a CommandBuilder for running the script
    return CommandBuilder("bash").add_option(temp_script.name) 

def generate_header_param(custom_header, tool_name=None):
    """
    Generate command-line parameters for a specific tool based on the custom header.

    Args:
        custom_header (dict, str, None): Dictionary, string or None
        tool_name (str, optional): Name of the tool. Defaults to None.

    Returns:
        str: Command-line parameter for the specified tool
    """
    from reNgine.utils.parsers import parse_custom_header

    # Early return for empty input
    if not custom_header:
        logger.debug("No custom headers provided")
        return ''

    # Validate input type before processing
    if not isinstance(custom_header, (dict, str)):
        logger.warning(f"⚠️ Invalid header type: {type(custom_header)}. Expected dict/str")
        return ''

    logger.debug(f"Generating header parameters for tool: {tool_name}")
    
    try:
        parsed_header = parse_custom_header(custom_header)
        if not parsed_header:
            return ''
    except ValueError as e:
        logger.exception(f"🚨 Header parsing failed: {str(e)}")
        return ''

    # Common formats
    common_headers = [f"{key}: {value}" for key, value in parsed_header.items()]
    semi_colon_headers = ';;'.join(common_headers)
    colon_headers = [f"{key}:{value}" for key, value in parsed_header.items()]

    # Define format mapping for each tool
    format_mapping = {
        'common': ' '.join([f' -H "{header}"' for header in common_headers]),
        'dalfox': ' '.join([f' -H "{header}"' for header in colon_headers]),
        'hakrawler': f' -h "{semi_colon_headers}"',
        'gospider': generate_gospider_params(parsed_header),
    }

    # Get the appropriate format based on the tool name
    result = format_mapping.get(tool_name, format_mapping.get('common'))
    logger.debug(f"Selected format for {tool_name}: {result}")

    # Return the corresponding parameter for the specified tool or default to common_headers format
    return result

def generate_gospider_params(custom_header):
    """
    Generate command-line parameters for gospider based on the custom header.

    Args:
        custom_header (dict): Dictionary containing the custom headers.

    Returns:
        str: Command-line parameters for gospider.
    """
    params = []
    for key, value in custom_header.items():
        if key.lower() == 'user-agent':
            params.append(f' -u "{value}"')
        elif key.lower() == 'cookie':
            params.append(f' --cookie "{value}"')
        else:
            params.append(f' -H "{key}:{value}"')
    return ' '.join(params)

def build_fetch_url_commands(config):
    """Build commands for different web crawlers
    
    Args:
        config (TaskConfig): Task configuration
        
    Returns:
        dict: Dictionary of commands for different crawlers
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    
    proxy = main_config.get('proxy', '')
    custom_header = task_config.get('custom_header', '')
    follow_redirect = task_config.get('follow_redirect', True)
    threads = task_config.get('threads', 0)
    
    # Initialize command builders for each tool
    gau_builder = CommandBuilder('gau')

    gospider_builder = CommandBuilder('gospider')
    gospider_builder.add_option('--js')
    gospider_builder.add_option('-d', 2)
    gospider_builder.add_option('--sitemap')
    gospider_builder.add_option('--robots')
    gospider_builder.add_option('-w')
    gospider_builder.add_option('-r')
    gospider_builder.add_option('-a')

    hakrawler_builder = CommandBuilder('hakrawler')
    hakrawler_builder.add_option('-subs')
    hakrawler_builder.add_option('-u')

    katana_builder = CommandBuilder('katana')
    katana_builder.add_option('-silent')
    katana_builder.add_option('-jc')
    katana_builder.add_option('-kf')
    katana_builder.add_option('all')
    katana_builder.add_option('-d')
    katana_builder.add_option('3')
    katana_builder.add_option('-fs')
    katana_builder.add_option('rdn')
    
    # Add proxy if provided
    if proxy:
        gau_builder.add_option('--proxy', proxy)
        gospider_builder.add_option('-p', proxy)
        hakrawler_builder.add_option('-proxy', proxy)
        katana_builder.add_option('-proxy', proxy)
    
    # Add threads if provided
    if threads > 0:
        gau_builder.add_option('--threads', threads)
        gospider_builder.add_option('-t', threads)
        hakrawler_builder.add_option('-t', threads)
        katana_builder.add_option('-c', threads)
    
    # Add custom headers if provided
    if custom_header:
        if header_param := generate_header_param(custom_header, 'gospider'):
            gospider_builder.add_option(header_param)
        if header_param := generate_header_param(custom_header, 'hakrawler'):
            hakrawler_builder.add_option(header_param)
        if header_param := generate_header_param(custom_header, 'common'):
            katana_builder.add_option(header_param)
    
    # Set follow_redirect option
    if not follow_redirect:
        gospider_builder.add_option('--no-redirect')
        hakrawler_builder.add_option('-dr')
        katana_builder.add_option('-dr')
    
    # Build the commands and return as dict
    return {
        'gau': gau_builder,
        'gospider': gospider_builder,
        'hakrawler': hakrawler_builder,
        'katana': katana_builder,
    }

def build_nmap_cmd(input_file, args=None, host=None, ports=None, output_file=None, script=None, script_args=None, max_rate=None, flags=None):
    from reNgine.utils.command_builder import CommandBuilder
    
    # Initialize builder
    cmd_builder = CommandBuilder('nmap')
    
    # Add options conditionally
    cmd_builder.add_option('--max-rate', max_rate, max_rate is not None)
    cmd_builder.add_option('-oX', output_file, output_file is not None)
    cmd_builder.add_option('--script', script, script is not None)
    cmd_builder.add_option('--script-args', script_args, script_args is not None)
    
    # Add flags
    if flags:
        for flag in flags:
            cmd_builder.add_option(flag)
    
    # Add ports if provided and -p not in args
    if ports and (not args or '-p' not in args):
        cmd_builder.add_option('-p', ports)
    
    # Add service detection if not in args
    if not args or '-sV' not in args:
        cmd_builder.add_option('-sV')
    
    # Add Pn if not in args
    if not args or '-Pn' not in args:
        cmd_builder.add_option('-Pn')
    
    # Add input source
    if input_file:
        cmd_builder.add_option('-iL', input_file)
    elif host:
        cmd_builder.add_option(host)
    
    # Add existing args if provided
    # Note: This is not ideal as args could contain shell commands
    # Better to parse args and add them individually
    if args:
        for arg in args.split():
            cmd_builder.add_option(arg)
    
    # Return list format for secure execution
    return cmd_builder.build_list()

def build_naabu_cmd(config, hosts):
    main_config = config.get_main_config()
    task_config = config.get_task_config()

    # Build cmd using the secure builder
    cmd_builder = CommandBuilder('naabu')
    cmd_builder.add_option('-json')
    cmd_builder.add_option('-exclude-cdn')
    cmd_builder.add_option('-list', task_config['input_path'], len(hosts) > 0)
    cmd_builder.add_option('-host', hosts[0], len(hosts) == 0)

    # Port configuration
    if 'full' in task_config['ports'] or 'all' in task_config['ports']:
        cmd_builder.add_option('-p', '-')
    elif 'top-100' in task_config['ports']:
        cmd_builder.add_option('-top-ports', '100')
    elif 'top-1000' in task_config['ports']:
        cmd_builder.add_option('-top-ports', '1000')
    else:
        ports_str = ','.join(task_config['ports'])
        cmd_builder.add_option('-p', ports_str)

    # Add remaining options
    cmd_builder.add_option('-config', str(Path.home() / '.config' / 'naabu' / 'config.yaml'), task_config['use_naabu_config'])
    cmd_builder.add_option('-proxy', main_config['proxy'], bool(main_config['proxy']))
    cmd_builder.add_option('-c', task_config['threads'], bool(task_config['threads']))
    cmd_builder.add_option('-rate', task_config['rate_limit'], task_config['rate_limit'] > 0)
    cmd_builder.add_option('-timeout', task_config['timeout']*1000, task_config['timeout'] > 0)
    cmd_builder.add_option('-passive', condition=task_config['passive'])
    cmd_builder.add_option('-exclude-ports', task_config['exclude_ports'], bool(task_config['exclude_ports']))
    cmd_builder.add_option('-silent')

    # Execute command more securely using list mode
    return cmd_builder.build_list()

def build_wafw00f_cmd(config):
    main_config = config.get_main_config()
    task_config = config.get_task_config()

    cmd_builder = CommandBuilder('wafw00f')
    cmd_builder.add_option('-i', task_config['input_path'])
    cmd_builder.add_option('-o', main_config['working_dir'])
    cmd_builder.add_option('-f', 'json')
    return cmd_builder.build_list()

def build_cmsseek_cmd(url):
    cmd_builder = CommandBuilder('cmseek')
    cmd_builder.add_option('--random-agent')
    cmd_builder.add_option('--batch')
    cmd_builder.add_option('--follow-redirect')
    cmd_builder.add_option('-u', url)
    return cmd_builder.build_list()

def build_ffuf_cmd(config):
    """Build FFUF command for directory and file fuzzing
    
    Args:
        config (TaskConfig): Task configuration
        
    Returns:
        list: Command as list of arguments
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('ffuf')
    cmd_builder.add_option('-json')
    cmd_builder.add_option('-x', main_config['proxy'], condition=bool(main_config['proxy']))
    cmd_builder.add_option('-w', task_config['wordlist_path'])
    cmd_builder.add_option('-e', task_config['extensions_str'], condition=bool(task_config['extensions']))
    cmd_builder.add_option('-maxtime', task_config['max_time'], condition=task_config['max_time'] > 0)
    cmd_builder.add_option('-p', task_config['delay'], condition=task_config['delay'] > 0)
    
    if task_config['recursive_level'] > 0:
        cmd_builder.add_option('-recursion')
        cmd_builder.add_option('-recursion-depth', task_config['recursive_level'])
        
    cmd_builder.add_option('-t', task_config['threads'], condition=task_config['threads'] and task_config['threads'] > 0)
    cmd_builder.add_option('-timeout', task_config['timeout'], condition=task_config['timeout'] and task_config['timeout'] > 0)
    cmd_builder.add_option('-se', condition=task_config['stop_on_error'])
    cmd_builder.add_option('-fr', condition=task_config['follow_redirect'])
    cmd_builder.add_option('-ac', condition=task_config['auto_calibration'])
    cmd_builder.add_option('-mc', task_config['match_codes'], condition=bool(task_config['match_codes']))
    cmd_builder.add_option(task_config['custom_header'], condition=bool(task_config['custom_header']))
    
    return cmd_builder

def build_harvester_cmd(host, output_path_json):
    """Build theHarvester command for OSINT
    
    Args:
        host (str): Target host
        output_path_json (str): Output file path
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('theHarvester')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-f', output_path_json)
    cmd_builder.add_option('-b', 'anubis,baidu,bevigil,binaryedge,bing,bingapi,bufferoverun,brave,censys,certspotter,criminalip,crtsh,dnsdumpster,duckduckgo,fullhunt,hackertarget,hunter,hunterhow,intelx,netlas,onyphe,otx,pentesttools,projectdiscovery,rapiddns,rocketreach,securityTrails,sitedossier,subdomaincenter,subdomainfinderc99,threatminer,tomba,urlscan,virustotal,yahoo,zoomeye')
    
    return cmd_builder.build_list()

def build_h8mail_cmd(input_path, output_file):
    """Build h8mail command for email OSINT
    
    Args:
        input_path (str): Input file path
        output_file (str): Output file path
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('h8mail')
    cmd_builder.add_option('-t', input_path)
    cmd_builder.add_option('--json', output_file)
    
    return cmd_builder.build_list()

def build_eyewitness_cmd(config):
    """Build EyeWitness command for screenshots
    
    Args:
        config (TaskConfig): Task configuration
        
    Returns:
        list: Command as list of arguments
    """
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('EyeWitness')
    cmd_builder.add_option('-f', task_config['alive_endpoints_file'])
    cmd_builder.add_option('-d', task_config['screenshots_path'])
    cmd_builder.add_option('--no-prompt')
    cmd_builder.add_option('--timeout', task_config['timeout'], task_config['timeout'] > 0)
    cmd_builder.add_option('--threads', task_config['threads'], task_config['threads'] > 0)
    
    return cmd_builder.build_list()

def build_nuclei_cmd(config, templates=None, update_templates=False):
    """Build Nuclei command for vulnerability scanning
    
    Args:
        config (TaskConfig): Task configuration
        templates (list, optional): List of templates to use
        
    Returns:
        list: Command as list of arguments
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('nuclei')
    if update_templates:
        cmd_builder.add_option('-update-templates')
        return cmd_builder.build_list()

    cmd_builder.add_option('-j')

    # Configuration Nuclei
    if task_config['use_nuclei_conf']:
        config_path = str(Path.home() / '.config' / 'nuclei' / 'config.yaml')
        cmd_builder.add_option('-config', config_path)

    cmd_builder.add_option('-irr')
    cmd_builder.add_option(task_config['custom_header'], condition=bool(task_config['custom_header']))
    cmd_builder.add_option('-l', task_config['input_path'])
    cmd_builder.add_option('-c', str(task_config['concurrency']), condition=task_config['concurrency'] > 0)
    cmd_builder.add_option('-proxy', main_config['proxy'], condition=bool(main_config['proxy']))
    cmd_builder.add_option('-retries', task_config['retries'], condition=task_config['retries'] > 0)
    cmd_builder.add_option('-rl', task_config['rate_limit'], condition=task_config['rate_limit'] > 0)
    cmd_builder.add_option('-timeout', str(task_config['timeout']), condition=task_config['timeout'] and task_config['timeout'] > 0)
    cmd_builder.add_option('-tags', task_config['tags'], condition=bool(task_config['tags']))
    cmd_builder.add_option('-silent')
    
    # Add templates if provided
    if templates:
        for template in templates:
            cmd_builder.add_option('-t', template)
    
    return cmd_builder.build_list()

def build_dalfox_cmd(config):
    """Build Dalfox command for XSS scanning
    
    Args:
        config (TaskConfig): Task configuration
        
    Returns:
        list: Command as list of arguments
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('dalfox')
    cmd_builder.add_option('--silence')
    cmd_builder.add_option('--no-color')
    cmd_builder.add_option('--no-spinner')
    cmd_builder.add_option('--only-poc', 'r')
    cmd_builder.add_option('--ignore-return', '302,404,403')
    cmd_builder.add_option('--skip-bav')
    cmd_builder.add_option('file', task_config['input_path'])
    cmd_builder.add_option('--proxy', main_config['proxy'], condition=bool(main_config['proxy']))
    cmd_builder.add_option('--waf-evasion', condition=task_config['is_waf_evasion'])
    cmd_builder.add_option('-b', task_config['blind_xss_server'], condition=bool(task_config['blind_xss_server']))
    cmd_builder.add_option('--delay', task_config['delay'], condition=bool(task_config['delay']))
    cmd_builder.add_option('--timeout', task_config['timeout'], condition=bool(task_config['timeout']))
    cmd_builder.add_option('--user-agent', task_config['user_agent'], condition=bool(task_config['user_agent']))
    cmd_builder.add_option(task_config['custom_header'], condition=bool(task_config['custom_header']))
    cmd_builder.add_option('--worker', task_config['concurrency'], condition=bool(task_config['concurrency']))
    cmd_builder.add_option('--format', 'json')
    
    return cmd_builder.build_list()

def build_crlfuzz_cmd(config):
    """Build CRLFuzz command for CRLF injection scanning
    
    Args:
        config (TaskConfig): Task configuration
        
    Returns:
        list: Command as list of arguments
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('crlfuzz')
    cmd_builder.add_option('-s')
    cmd_builder.add_option('-l', task_config['crlfuzz_input_path'])
    cmd_builder.add_option('-x', main_config['proxy'], bool(main_config['proxy']))

    # Add user-agent as header if specified
    if task_config['user_agent']:
        cmd_builder.add_option('-H', f'User-Agent: {task_config["user_agent"]}')

    if header_param := generate_header_param(task_config['custom_header'], 'crlfuzz'):
        cmd_builder.add_option(header_param)

    cmd_builder.add_option('-o', main_config['working_dir'])
    cmd_builder.add_option('-c', task_config['concurrency'], bool(task_config['concurrency']))
    
    return cmd_builder.build_list()

def build_s3scanner_cmd(config, provider):
    """Build S3Scanner command for S3 bucket scanning
    
    Args:
        config (TaskConfig): Task configuration
        provider (str): Cloud provider to scan
        
    Returns:
        list: Command as list of arguments
    """
    task_config = config.get_task_config()
    
    cmd_builder = CommandBuilder('s3scanner')
    cmd_builder.add_option('-bucket-file', task_config['input_path'])
    cmd_builder.add_option('-enumerate')
    cmd_builder.add_option('-provider', provider)
    cmd_builder.add_option('-threads', task_config['concurrency'])
    cmd_builder.add_option('-json')
    
    return cmd_builder.build_list()

def build_httpx_cmd(config, urls, method=None, threads=None):
    """Build command for httpx tool.
    
    Args:
        threads (int): Number of threads to use
        proxy (str): Proxy to use
        custom_header (str): Custom HTTP header
        urls (list): List of URLs to scan
        input_path (str): Path to file containing URLs
        method (str): HTTP method to use
        follow_redirect (bool): Whether to follow redirects
        
    Returns:
        str: Constructed command
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()  

    cmd_builder = CommandBuilder('httpx')
    cmd_builder.add_option('-cl')
    cmd_builder.add_option('-ct')
    cmd_builder.add_option('-rt')
    cmd_builder.add_option('-location')
    cmd_builder.add_option('-td')
    cmd_builder.add_option('-websocket')
    cmd_builder.add_option('-cname')
    cmd_builder.add_option('-asn')
    cmd_builder.add_option('-cdn')
    cmd_builder.add_option('-probe')
    cmd_builder.add_option('-random-agent')
    
    if threads and threads > 0:
        cmd_builder.add_option('-t', str(threads))
    if main_config['proxy']:
        cmd_builder.add_option('-proxy', main_config['proxy'])
    if task_config['custom_header']:
        cmd_builder.add_option(task_config['custom_header'])
    
    cmd_builder.add_option('-json')
    
    if len(urls) == 1:
        cmd_builder.add_option('-u', urls[0])
    else:
        cmd_builder.add_option('-l', task_config['input_path'])
    
    if method:
        cmd_builder.add_option('-x', method)
    
    cmd_builder.add_option('-silent')
    
    if task_config['follow_redirect']:
        cmd_builder.add_option('-fr')
    
    return cmd_builder.build_string()

def build_amass_passive_command(host, results_dir, config=None):
    """Build command for amass passive enumeration mode.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict, optional): Configuration options for amass
        
    Returns:
        list: Command as list of arguments
    """
    use_amass_config = config.get('USE_AMASS_CONFIG', False) if config else False
    
    cmd_builder = CommandBuilder('amass')
    cmd_builder.add_option('enum')
    cmd_builder.add_option('-passive')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', config.get_working_dir(filename='subdomains_amass.txt'))
    
    if use_amass_config:
        cmd_builder.add_option('-config', str(Path.home() / '.config' / 'amass' / 'config.ini'))
    
    return cmd_builder.build_list()

def build_amass_active_command(host, results_dir, config=None):
    """Build command for amass active enumeration mode.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict, optional): Configuration options for amass
        
    Returns:
        list: Command as list of arguments
    """
    use_amass_config = config.get('USE_AMASS_CONFIG', False) if config else False
    amass_wordlist_name = config.get('AMASS_WORDLIST', 'default') if config else 'default'
    wordlist_path = str(Path('AMASS_DEFAULT_WORDLIST_PATH') / f'{amass_wordlist_name}.txt')
    
    cmd_builder = CommandBuilder('amass')
    cmd_builder.add_option('enum')
    cmd_builder.add_option('-active')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', config.get_working_dir(filename='subdomains_amass.txt'))
    
    if use_amass_config:
        cmd_builder.add_option('-config', str(Path.home() / '.config' / 'amass' / 'config.ini'))
    
    cmd_builder.add_option('-brute')
    cmd_builder.add_option('-w', wordlist_path)
    
    return cmd_builder.build_list()

def build_sublist3r_command(host, results_dir, config):
    """Build command for sublist3r subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        threads (int, optional): Number of threads to use
        
    Returns:
        list: Command as list of arguments
    """
    task_config = config.get_task_config()

    cmd_builder = CommandBuilder('sublist3r')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-t', task_config['threads'], bool(task_config['threads']))
    cmd_builder.add_option('-o', config.get_working_dir(filename='subdomains_sublister.txt'))
    
    return cmd_builder.build_list()

def build_subfinder_command(host, results_dir, config=None):
    """Build command for subfinder subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict, optional): Configuration options
        
    Returns:
        list: Command as list of arguments
    """
    main_config = config.get_main_config()
    task_config = config.get_task_config()
    use_subfinder_config = task_config[USE_SUBFINDER_CONFIG]
    
    cmd_builder = CommandBuilder('subfinder')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', config.get_working_dir(filename='subdomains_subfinder.txt'))
    cmd_builder.add_option('-config', str(Path.home() / '.config' / 'subfinder' / 'config.yaml'), use_subfinder_config)
    cmd_builder.add_option('-proxy', main_config['proxy'], bool(main_config['proxy']))
    cmd_builder.add_option('-timeout', task_config['timeout'], bool(task_config['timeout']))
    cmd_builder.add_option('-t', task_config['threads'], bool(task_config['threads']))
    cmd_builder.add_option('-silent')
    
    return cmd_builder.build_list()

def build_oneforall_command(host, results_dir, config):
    """Build command for OneForAll subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # OneForAll requires shell=True for concatenated commands
    use_shell = True
    
    cmd_builder = CommandBuilder('cd /usr/src/oneforall && python3 oneforall.py')
    cmd_builder.add_option('--target', host)
    cmd_builder.add_option('--path', config.get_working_dir(filename='subdomains_oneforall.txt'))
    cmd_builder.add_option('run')
    
    return cmd_builder.build_string(), use_shell

def build_ctfr_command(host, results_dir, config):
    """Build command for CTFR subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # CTFR requires shell=True for command concatenation
    use_shell = True
    
    results_file = config.get_working_dir(filename='subdomains_ctfr.txt')
    
    cmd_builder = CommandBuilder('ctfr')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', results_file)
    
    ctfr_cmd = cmd_builder.build_string()
    quoted_results_file = shlex.quote(results_file)
    
    cmd_extract = f"cat {quoted_results_file} | sed 's/\\*.//g' | tail -n +12 | uniq | sort > {quoted_results_file}"
    cmd = f'{ctfr_cmd} && {cmd_extract}'
    
    return cmd, use_shell

def build_tlsx_command(host, results_dir, config):
    """Build command for tlsx subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # tlsx requires shell=True for pipes and regex
    use_shell = True
    
    results_file = config.get_working_dir(filename='subdomains_tlsx.txt')
    
    cmd_builder = CommandBuilder('tlsx')
    cmd_builder.add_option('-san')
    cmd_builder.add_option('-cn')
    cmd_builder.add_option('-silent')
    cmd_builder.add_option('-ro')
    cmd_builder.add_option('-host', host)
    
    tlsx_cmd = cmd_builder.build_string()
    quoted_results_file = shlex.quote(results_file)
    
    cmd = f"{tlsx_cmd} | sed -n '/^\\([a-zA-Z0-9]\\([-a-zA-Z0-9]*[a-zA-Z0-9]\\)\\?\\.\\)\\+{host}$/p' | uniq | sort > {quoted_results_file}"
    
    return cmd, use_shell

def build_netlas_command(host, results_dir, config):
    """Build command for netlas subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # netlas requires shell=True for pipes
    use_shell = True
    
    results_file = config.get_working_dir(filename='subdomains_netlas.txt')
    netlas_key = get_netlas_key()
    
    if not netlas_key:
        raise ValueError("Netlas API key not configured. Please set NETLAS_API_KEY in environment variables.")
    
    cmd_builder = CommandBuilder('netlas')
    cmd_builder.add_option('search')
    cmd_builder.add_option('-d', 'domain')
    cmd_builder.add_option('-i', 'domain')
    cmd_builder.add_option(f'domain:"*.{host}"')
    cmd_builder.add_option('-f', 'json')
    
    # Security of the API key
    if netlas_key:
        # Use of an ephemeral environment variable
        cmd_builder.set_env('NETLAS_API_KEY', netlas_key)
        cmd_builder.add_option('-a', '$NETLAS_API_KEY')
    
    netlas_cmd = cmd_builder.build_string()
    quoted_results_file = shlex.quote(results_file)
    
    cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\\.)+{host}'"
    cmd = f'{netlas_cmd} | {cmd_extract} > {quoted_results_file}'
    
    return cmd, use_shell

def build_custom_tool_command(tool, host, results_dir, config):
    """Build command for a custom subdomain tool.
    
    Args:
        tool (str): Name of the custom tool
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict): Configuration options
        
    Returns:
        tuple: (command as string, error message if any)
    """
    tool_query = None
    try:
        from startScan.models import InstalledExternalTool
        tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
    except ImportError:
        return None, f"Could not import InstalledExternalTool model. Skipping {tool}."
    
    if not tool_query.exists():
        return None, f"{tool} configuration does not exist. Skipping."
    
    custom_tool = tool_query.first()
    cmd = custom_tool.subdomain_gathering_command
    
    if '{TARGET}' not in cmd:
        return None, f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.'
    
    if '{OUTPUT}' not in cmd:
        return None, f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.'
    
    cmd = cmd.replace('{TARGET}', host)
    cmd = cmd.replace('{OUTPUT}', config.get_working_dir(filename=f'subdomains_{tool}.txt'))
    
    if '{PATH}' in cmd:
        cmd = cmd.replace('{PATH}', custom_tool.github_clone_path)
    
    return cmd, None

def build_subdomain_tool_commands(tool, host, ctx=None, config=None):
    """Build command for specified subdomain discovery tool.
    
    Args:
        tool (str): Tool to use for subdomain discovery
        host (str): Target host
        ctx (dict, optional): Context dictionary
        config (dict, optional): Configuration options
        
    Returns:
        tuple: (command as string or list, use_shell boolean, error message string or None)
    """
    cmd = None
    use_shell = False
    error_msg = None
    results_dir = ctx.get('results_dir')

    task_config = config.get_task_config()
    
    if tool == 'amass-passive':
        cmd = build_amass_passive_command(host, results_dir, config)
    
    elif tool == 'amass-active':
        cmd = build_amass_active_command(host, results_dir, config)
    
    elif tool == 'sublist3r':
        cmd = build_sublist3r_command(host, results_dir, config)
    
    elif tool == 'subfinder':
        cmd = build_subfinder_command(host, results_dir, config)
    
    elif tool == 'oneforall':
        cmd, use_shell = build_oneforall_command(host, results_dir, config)
    
    elif tool == 'ctfr':
        cmd, use_shell = build_ctfr_command(host, results_dir, config)
    
    elif tool == 'tlsx':
        cmd, use_shell = build_tlsx_command(host, results_dir, config)
    
    elif tool == 'netlas':
        cmd, use_shell = build_netlas_command(host, results_dir, config)
    
    elif tool in task_config['custom_subdomain_tools']:
        cmd, error_msg = build_custom_tool_command(tool, host, results_dir, config)
    
    else:
        error_msg = f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.'
    
    return cmd, use_shell, error_msg

def build_gofuzz_cmd(lookup_target, delay, page_count, lookup_extensions=None, lookup_keywords=None, results_dir=None, config=None):
    """Build GoFuzz command for fuzzing
    
    Args:
        lookup_target (str): Target to fuzz
        delay (int): Delay between requests
        page_count (int): Number of pages to retrieve
        lookup_extensions (str, optional): Extensions to scan
        lookup_keywords (str, optional): Keywords to use
        results_dir (str, optional): Results directory path
        
    Returns:
        list: Command as list of arguments
    """
    # Create the builder with the execution path as the base command
    cmd_builder = CommandBuilder('GooFuzz')
    cmd_builder.add_option('-t', lookup_target)
    cmd_builder.add_option('-d', delay)
    cmd_builder.add_option('-p', page_count)

    # Add conditional options
    if lookup_extensions:
        cmd_builder.add_option('-e', lookup_extensions)
    elif lookup_keywords:
        cmd_builder.add_option('-w', lookup_keywords)

    # Define the output file if results directory provided
    if results_dir:
        output_file = config.get_working_dir(filename='gofuzz.txt')
        cmd_builder.add_option('-o', output_file)
    
    return cmd_builder.build_string()

def build_infoga_cmd(domain_name, output_file):
    """Build Infoga command for email gathering
    
    Args:
        domain_name (str): Domain name to scan
        output_file (str): Output file path
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('infoga')
    cmd_builder.add_option('--domain', domain_name)
    cmd_builder.add_option('--source', 'all')
    cmd_builder.add_option('--report', output_file)
    
    return cmd_builder.build_list()

def build_tlsx_cmd(domain, output_path):
    """Build tlsx command for SSL/TLS information gathering
    
    Args:
        domain (str): Domain to scan
        output_path (str): Output file path
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('tlsx')
    cmd_builder.add_option('-san')
    cmd_builder.add_option('-cn')
    cmd_builder.add_option('-silent')
    cmd_builder.add_option('-ro')
    cmd_builder.add_option('-host', domain)
    cmd_builder.add_option('-o', output_path)
    
    return cmd_builder.build_list()

def build_whois_cmd(domain):
    """Build whois command for domain information
    
    Args:
        domain (str): Domain to query
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('whois')
    cmd_builder.add_option(domain)
    
    return cmd_builder.build_list()