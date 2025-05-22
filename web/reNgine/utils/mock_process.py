import contextlib
import datetime
import json
import os
import threading
import time
from urllib.parse import urlparse
import re

from reNgine.utils.logger import default_logger as logger
from reNgine.utils.mock_datas import MockData
from reNgine.utils.debug import debug

class MockProcess:
    def __init__(self, cmd, stream_mode, context=None):
        #debug()
        self.cmd = cmd
        self.stream_mode = stream_mode
        self._finished = False
        self._returncode = 0
        self.context = context or {}
        
        # Create pipe for stdout simulation
        self.read_fd, self.write_fd = os.pipe()
        self.stdout = os.fdopen(self.read_fd, 'rb')
        self.stderr = open(os.devnull, 'rb')
        
        # Start output generation thread
        self.writer_thread = threading.Thread(
            target=self._generate_stream_output if stream_mode else self._generate_buffer_output,
            args=(self.write_fd,),
            daemon=True
        )
        self.writer_thread.start()
    
    def _get_command_type(self, cmd_str):
        """Determine the command type from command string
        
        Args:
            cmd_str (str): Command string
            
        Returns:
            str: Command type identifier
        """
        if 'httpx' in cmd_str or 'http_crawl' in cmd_str:
            return 'httpx'
        elif 'nuclei' in cmd_str:
            return 'nuclei'
        elif 'naabu' in cmd_str or 'port_scan' in cmd_str:
            return 'port_scan'
        elif 'nmap' in cmd_str:
            return 'nmap'
        elif 'dalfox' in cmd_str:
            return 'dalfox'
        elif 's3scanner' in cmd_str:
            return 's3scanner'
        elif 'crlfuzz' in cmd_str:
            return 'crlfuzz'
        elif 'gobuster' in cmd_str or 'dirsearch' in cmd_str or 'ffuf' in cmd_str:
            for tool in ['gobuster', 'dirsearch', 'ffuf']:
                if tool in cmd_str:
                    return tool
        elif 'osint' in cmd_str:
            return 'osint'
        return 'generic'
    
    def _prepare_urls_and_context(self):
        """Common method to extract target info and prepare URLs
        
        Returns:
            tuple: (urls, command_type, context)
        """
        # Extract domain and context information
        target_domain, single_url_mode, context = self._extract_target_info()

        # Initialize MockData with the enhanced context
        mock_data = MockData(context=context)
        cmd_str = ' '.join(self.cmd)

        # Different URL generation strategy based on command type
        if single_url_mode:
            if url_match := re.search(r'-u\s+(\S+)', cmd_str) or re.search(
                r'--url\s+(\S+)', cmd_str
            ):
                urls = [url_match.group(1)]
                logger.info(f"Using single target URL: {urls[0]}")
            else:
                urls = []
        elif target_domain:
            # For domain-based scans, generate URLs for that domain
            urls = mock_data._generate_urls(count=5, base_domains=[target_domain], subdomains=True)
            logger.info(f"🧪 Generated {len(urls)} mock URLs for dry run testing")
        else:
            # Fallback to context URLs
            urls = mock_data.get_target_urls(ctx=context)

        logger.debug(f"Mock URLs retrieved: {len(urls)} URLs")
        command_type = self._get_command_type(cmd_str)

        return urls, command_type, context
    
    def _generate_stream_output(self, write_fd):
        """Simulate real-time output based on command and input URLs"""
        try:
            self._prepare_command_from_context(write_fd, True)
        except Exception as e:
            logger.error(f"Error in mock output generation: {str(e)}")
            error_entry = {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.datetime.now().isoformat()
            }
            with contextlib.suppress(Exception):
                os.write(write_fd, (json.dumps(error_entry) + "\n").encode())
        finally:
            with contextlib.suppress(Exception):
                os.close(write_fd)
            self._finished = True
    
    def _generate_buffer_output(self, write_fd):
        """Generate full output at once for non-stream mode"""
        try:
            self._prepare_command_from_context(write_fd, False)
        except Exception as e:
            logger.error(f"Error in buffer mock output: {str(e)}")
            os.write(write_fd, f"Error: {str(e)}".encode())
        finally:
            os.close(write_fd)
            self._finished = True

    def _prepare_command_from_context(self, write_fd, streaming):
        urls, command_type, context = self._prepare_urls_and_context()
        mock_data = MockData(context=context)
        self._process_command_output(
            write_fd, command_type, urls, mock_data, streaming=streaming
        )
    
    def _process_command_output(self, write_fd, command_type, urls, mock_data, streaming=False):
        """Process command output based on command type
        
        Args:
            write_fd: File descriptor to write to
            command_type (str): Type of command
            urls (list): List of URLs
            mock_data (MockData): MockData instance
            streaming (bool): Whether to output in streaming mode
        """
        cmd_str = ' '.join(self.cmd)

        if command_type == 'httpx':
            mock_data._generate_httpx_output(urls)
        elif command_type == 'nuclei':
            mock_data.mock_nuclei_scan(urls)
        elif command_type == 'port_scan':
            mock_data.mock_port_scan(None, {'urls': urls}, None, self.context)
        elif command_type == 'nmap':
            mock_data.mock_nmap(None, {'host': urls[0] if urls else 'example.com', 'ports': [80, 443]}, None, self.context)
        elif command_type == 'dalfox':
            mock_data.mock_dalfox_scan(urls) 
        elif command_type == 's3scanner':
            mock_data.mock_s3scanner()
        elif command_type == 'crlfuzz':
            mock_data.mock_crlfuzz_scan(urls)
        elif command_type in ['ffuf']:
            mock_data.mock_dir_file_fuzz(None, {'urls': urls}, None, self.context)
        elif command_type == 'osint':
            mock_data.mock_osint(None, {'host': urls[0] if urls else 'example.com'}, None, self.context)
        elif streaming:
            self._stream_generic_output(write_fd, urls, cmd_str)
        else:
            output = f"Mock output for {cmd_str}\n" + '\n'.join(urls)
            os.write(write_fd, output.encode())

    @property
    def returncode(self):
        """Always return 0 for successful dry runs"""
        return self._returncode
    
    def _stream_generic_output(self, write_fd, urls, cmd_str):
        """Stream generic output for unknown commands"""
        os.write(write_fd, f"Mock output for command: {cmd_str}\n".encode())
        time.sleep(0.3)
        
        for i, url in enumerate(urls):
            os.write(write_fd, f"Processing {i+1}/{len(urls)}: {url}\n".encode())
            time.sleep(0.2)
        
        os.write(write_fd, f"Mock process completed with {len(urls)} items\n".encode())
    
    def wait(self):
        """Simulate process completion wait"""
        if self.writer_thread.is_alive():
            self.writer_thread.join(timeout=5.0)
        self._finished = True
        return self._returncode
    
    def poll(self):
        """Mock process status check"""
        return self._returncode if self._finished else None
    
    def communicate(self):
        return (self.stdout.read(), self.stderr.read())
    
    def __del__(self):
        """Clean up resources with error handling"""
        with contextlib.suppress(AttributeError, OSError):
            self.stdout.close()
            self.stderr.close()
            
            if self.writer_thread.is_alive():
                self.writer_thread.join(timeout=0.1)

    def _extract_target_info(self):
        """Extract target domain and other info from command.
        
        Returns:
            tuple: (domain_name, single_url_mode, context)
        """
        cmd_str = ' '.join(self.cmd)
        target_domain = None
        single_url_mode = False

        # Try to extract domain from URL parameter
        url_match = re.search(r'-u\s+(\S+)', cmd_str) or re.search(r'--url\s+(\S+)', cmd_str)
        if url_match:
            url = url_match.group(1)
            parsed_url = urlparse(url)
            target_domain = parsed_url.netloc.split(':')[0]  # Remove port if present

            # Check if this is a single URL scan (like in http_crawl)
            if 'httpx' in cmd_str and not re.search(r'-l\s+\S+', cmd_str):
                single_url_mode = True

        # Extract domain using other common patterns if not found
        if not target_domain:
            if domain_match := re.search(r'-d\s+(\S+)', cmd_str) or re.search(
                r'--domain\s+(\S+)', cmd_str
            ):
                target_domain = domain_match.group(1)

        # Create context with the target domain
        context = self.context or {}
        if target_domain:
            context['domain_name'] = target_domain

        logger.debug(f"Extracted target domain: {target_domain}, single URL mode: {single_url_mode}")
        return target_domain, single_url_mode, context
