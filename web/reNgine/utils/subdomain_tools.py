import shlex
from pathlib import Path

from reNgine.utils.api import get_netlas_key
from reNgine.utils.logger import Logger
from reNgine.utils.command_builder import CommandBuilder

logger = Logger(True)

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
    cmd_builder.add_option('-o', str(Path(results_dir) / 'subdomains_amass.txt'))
    
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
    cmd_builder.add_option('-o', str(Path(results_dir) / 'subdomains_amass.txt'))
    
    if use_amass_config:
        cmd_builder.add_option('-config', str(Path.home() / '.config' / 'amass' / 'config.ini'))
    
    cmd_builder.add_option('-brute')
    cmd_builder.add_option('-w', wordlist_path)
    
    return cmd_builder.build_list()

def build_sublist3r_command(host, results_dir, threads=None):
    """Build command for sublist3r subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        threads (int, optional): Number of threads to use
        
    Returns:
        list: Command as list of arguments
    """
    cmd_builder = CommandBuilder('sublist3r')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-t', threads, bool(threads))
    cmd_builder.add_option('-o', str(Path(results_dir) / 'subdomains_sublister.txt'))
    
    return cmd_builder.build_list()

def build_subfinder_command(host, results_dir, config=None, proxy=None, timeout=None, threads=None):
    """Build command for subfinder subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict, optional): Configuration options
        proxy (str, optional): Proxy to use
        timeout (int, optional): Timeout value
        threads (int, optional): Number of threads to use
        
    Returns:
        list: Command as list of arguments
    """
    use_subfinder_config = config.get('USE_SUBFINDER_CONFIG', False) if config else False
    
    cmd_builder = CommandBuilder('subfinder')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', str(Path(results_dir) / 'subdomains_subfinder.txt'))
    cmd_builder.add_option('-config', str(Path.home() / '.config' / 'subfinder' / 'config.yaml'), use_subfinder_config)
    cmd_builder.add_option('-proxy', proxy, bool(proxy))
    cmd_builder.add_option('-timeout', timeout, bool(timeout))
    cmd_builder.add_option('-t', threads, bool(threads))
    cmd_builder.add_option('-silent')
    
    return cmd_builder.build_list()

def build_oneforall_command(host, results_dir):
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
    cmd_builder.add_option('--path', str(Path(results_dir) / 'subdomains_oneforall.txt'))
    cmd_builder.add_option('run')
    
    return cmd_builder.build_string(), use_shell

def build_ctfr_command(host, results_dir):
    """Build command for CTFR subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # CTFR requires shell=True for command concatenation
    use_shell = True
    
    results_file = str(Path(results_dir) / 'subdomains_ctfr.txt')
    
    cmd_builder = CommandBuilder('ctfr')
    cmd_builder.add_option('-d', host)
    cmd_builder.add_option('-o', results_file)
    
    ctfr_cmd = cmd_builder.build_string()
    quoted_results_file = shlex.quote(results_file)
    
    cmd_extract = f"cat {quoted_results_file} | sed 's/\\*.//g' | tail -n +12 | uniq | sort > {quoted_results_file}"
    cmd = f'{ctfr_cmd} && {cmd_extract}'
    
    return cmd, use_shell

def build_tlsx_command(host, results_dir):
    """Build command for tlsx subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # tlsx requires shell=True for pipes and regex
    use_shell = True
    
    results_file = str(Path(results_dir) / 'subdomains_tlsx.txt')
    
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

def build_netlas_command(host, results_dir):
    """Build command for netlas subdomain tool.
    
    Args:
        host (str): Target host
        results_dir (str): Directory to store results
        
    Returns:
        tuple: (command as string, use_shell flag)
    """
    # netlas requires shell=True for pipes
    use_shell = True
    
    results_file = str(Path(results_dir) / 'subdomains_netlas.txt')
    netlas_key = get_netlas_key()
    
    cmd_builder = CommandBuilder('netlas')
    cmd_builder.add_option('search')
    cmd_builder.add_option('-d', 'domain')
    cmd_builder.add_option('-i', 'domain')
    cmd_builder.add_option(f'domain:"*.{host}"')
    cmd_builder.add_option('-f', 'json')
    cmd_builder.add_option('-a', netlas_key, bool(netlas_key))
    
    netlas_cmd = cmd_builder.build_string()
    quoted_results_file = shlex.quote(results_file)
    
    cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\\.)+{host}'"
    cmd = f'{netlas_cmd} | {cmd_extract} > {quoted_results_file}'
    
    return cmd, use_shell

def build_custom_tool_command(tool, host, results_dir, custom_subdomain_tools):
    """Build command for a custom subdomain tool.
    
    Args:
        tool (str): Name of the custom tool
        host (str): Target host
        results_dir (str): Directory to store results
        custom_subdomain_tools (QuerySet): Database objects for custom tools
        
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
    cmd = cmd.replace('{OUTPUT}', str(Path(results_dir) / f'subdomains_{tool}.txt'))
    
    if '{PATH}' in cmd:
        cmd = cmd.replace('{PATH}', custom_tool.github_clone_path)
    
    return cmd, None

def build_subdomain_tool_command(tool, host, results_dir, config=None, proxy=None, timeout=None, 
                              threads=None, custom_subdomain_tools=None):
    """Build command for specified subdomain discovery tool.
    
    Args:
        tool (str): Tool to use for subdomain discovery
        host (str): Target host
        results_dir (str): Directory to store results
        config (dict, optional): Configuration options
        proxy (str, optional): Proxy to use
        timeout (int, optional): Timeout value
        threads (int, optional): Number of threads to use
        custom_subdomain_tools (QuerySet, optional): Database objects for custom tools
        
    Returns:
        tuple: (command as string or list, use_shell boolean, error message string or None)
    """
    cmd = None
    use_shell = False
    error_msg = None
    
    if tool == 'amass-passive':
        cmd = build_amass_passive_command(host, results_dir, config)
    
    elif tool == 'amass-active':
        cmd = build_amass_active_command(host, results_dir, config)
    
    elif tool == 'sublist3r':
        cmd = build_sublist3r_command(host, results_dir, threads)
    
    elif tool == 'subfinder':
        cmd = build_subfinder_command(host, results_dir, config, proxy, timeout, threads)
    
    elif tool == 'oneforall':
        cmd, use_shell = build_oneforall_command(host, results_dir)
    
    elif tool == 'ctfr':
        cmd, use_shell = build_ctfr_command(host, results_dir)
    
    elif tool == 'tlsx':
        cmd, use_shell = build_tlsx_command(host, results_dir)
    
    elif tool == 'netlas':
        cmd, use_shell = build_netlas_command(host, results_dir)
    
    elif tool in custom_subdomain_tools:
        cmd, error_msg = build_custom_tool_command(tool, host, results_dir, custom_subdomain_tools)
    
    else:
        error_msg = f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.'
    
    return cmd, use_shell, error_msg