from pathlib import Path
import shlex

from reNgine.utils.logger import Logger
from reNgine.utils.parsers import parse_custom_header

logger = Logger(True)

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
        logger.error(f"🚨 Header parsing failed: {str(e)}")
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

def build_url_fetch_commands(tools, host, output_path, threads=0, proxy=None, custom_header=None, follow_redirect=True):
    """Build command strings for URL fetching tools.
    
    Args:
        tools (list): List of tool names to use
        host (str): Target host
        output_path (str): Path to save output
        threads (int): Number of threads to use
        proxy (str): Proxy URL
        custom_header (str): Custom HTTP headers
        follow_redirect (bool): Whether to follow HTTP redirects
        
    Returns:
        dict: Dictionary mapping tool names to command strings
    """
    
    # Base commands for each tool
    cmd_map = {
        'gau': 'gau --config ' + str(Path.home() / '.config' / 'gau' / 'config.toml'),
        'hakrawler': 'hakrawler -subs -u',
        'waybackurls': 'waybackurls',
        'gospider': 'gospider --js -d 2 --sitemap --robots -w -r -a',
        'katana': 'katana -silent -jc -kf all -d 3 -fs rdn',
    }
    
    # Add proxy if provided
    if proxy:
        cmd_map['gau'] += f' --proxy "{proxy}"'
        cmd_map['gospider'] += f' -p {proxy}'
        cmd_map['hakrawler'] += f' -proxy {proxy}'
        cmd_map['katana'] += f' -proxy {proxy}'
    
    # Add threads if provided
    if threads > 0:
        cmd_map['gau'] += f' --threads {threads}'
        cmd_map['gospider'] += f' -t {threads}'
        cmd_map['hakrawler'] += f' -t {threads}'
        cmd_map['katana'] += f' -c {threads}'
    
    # Add custom headers if provided
    if custom_header:
        cmd_map['gospider'] += generate_header_param(custom_header, 'gospider')
        cmd_map['hakrawler'] += generate_header_param(custom_header, 'hakrawler')
        cmd_map['katana'] += generate_header_param(custom_header, 'common')
    
    # Set follow_redirect option
    if follow_redirect is False:
        cmd_map['gospider'] += ' --no-redirect'
        cmd_map['hakrawler'] += ' -dr'
        cmd_map['katana'] += ' -dr'
    
    # Only return commands for requested tools
    return {tool: cmd_map.get(tool, '') for tool in tools if tool in cmd_map}

def get_nmap_cmd(input_file, args=None, host=None, ports=None, output_file=None, script=None, script_args=None, max_rate=None, flags=None):
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

def build_cmd(cmd, options, flags, sep=" "):
    for k,v in options.items():
        if not v:
            continue
        cmd += f" {k}{sep}{v}"

    for flag in flags:
        if not flag:
            continue
        cmd += f" --{flag}"

    return cmd