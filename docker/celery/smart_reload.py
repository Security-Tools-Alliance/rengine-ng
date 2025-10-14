#!/usr/bin/env python3
"""
Smart reload script for reNgine development.
Based on watchdog best practices with proper debouncing.
"""

import os
import sys
import time
import subprocess
import logging
from pathlib import Path
from threading import Timer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DebouncedReloadHandler(FileSystemEventHandler):
    """
    Handler with debouncing to prevent rapid-fire restarts.
    Only monitors actual file modifications, not reads or access.
    """
    
    def __init__(self, restart_callback):
        self.restart_callback = restart_callback
        self.timer = None
        self.debounce_delay = 2.0  # 2 seconds debounce delay
        self.file_timestamps = {}  # Track file modification times
        
    def on_modified(self, event):
        """Handle file modification events only."""
        if event.is_directory or not event.src_path.endswith('.py'):
            return
            
        # Ignore certain files that are frequently modified by the system
        if self._should_ignore_file(event.src_path):
            return
            
        # Check if file was actually modified by comparing timestamps
        if not self._is_file_actually_modified(event.src_path):
            return
            
        # Cancel existing timer if any
        if self.timer:
            self.timer.cancel()
            
        # Start new timer
        self.timer = Timer(self.debounce_delay, self._handle_event, args=[event])
        self.timer.start()
        
    def _should_ignore_file(self, file_path):
        """Check if file should be ignored based on path patterns."""
        ignore_patterns = [
            '__pycache__',
            '.pyc',
            '.pyo',
            '.pyd',
            '.git',
            '.svn',
            '.hg',
            'node_modules',
            '.DS_Store',
            'Thumbs.db',
            '.coverage',
            '.pytest_cache',
            '.mypy_cache',
            '.tox',
            'venv',
            'env',
            '.env'
        ]
        
        return any(pattern in file_path for pattern in ignore_patterns)
        
    def _is_file_actually_modified(self, file_path):
        """Check if file was actually modified by comparing timestamps."""
        try:
            import os
            current_mtime = os.path.getmtime(file_path)
            
            # If we've seen this file before, compare timestamps
            if file_path in self.file_timestamps:
                if current_mtime <= self.file_timestamps[file_path]:
                    # File hasn't been modified since last check
                    return False
            
            # Update timestamp and return True
            self.file_timestamps[file_path] = current_mtime
            return True
            
        except (OSError, IOError):
            # If we can't get file info, assume it was modified
            return True
        
    def _handle_event(self, event):
        """Actually handle the event after debounce delay."""
        logger.info(f"🔄 File changed: {event.src_path}")
        logger.info("🔄 Restarting worker...")
        self.restart_callback()


def start_smart_reload():
    """Start the smart reload system with proper debouncing."""
    logger.info("🚀 Starting reNgine development worker with smart reload...")
    logger.info("📁 Watching: ./reNgine/**/*.py")
    logger.info("⏱️  Debounce delay: 2 seconds")
    logger.info("")
    
    # Current worker process
    worker_process = None
    last_restart_time = 0
    min_restart_interval = 30  # Minimum 30 seconds between restarts
    
    def start_worker():
        """Start the Secator worker."""
        nonlocal worker_process
        
        # For celery multi, we don't need to manage the parent process
        # as it terminates after starting workers
        
        # Start new worker using the correct secator environment
        cmd = [
            "/home/rengine/.local/share/pipx/venvs/secator/bin/secator", 
            "worker",
            "--concurrency=3",
            "--dev"
        ]
        
        logger.info(f"▶️  Starting: {' '.join(cmd)}")
        
        # Pass environment variables to Secator
        env = os.environ.copy()
        env.update({
            'SECATOR_QUIET': '0',
            'SECATOR_WITHOUT_GOSSIP': '1',
            'SECATOR_CONCURRENCY': '3',
            'SECATOR_WITHOUT_MINGLE': '1',
            'SECATOR_DEV_MODE': '1'
        })
        
        # Use shell=False and proper process handling
        try:
            worker_process = subprocess.Popen(
                cmd, 
                env=env,
                # Don't capture stdout/stderr to avoid blocking
                stdout=None,
                stderr=None
            )
            logger.info(f"✅ Worker started with PID: {worker_process.pid}")
            return worker_process
        except Exception as e:
            logger.error(f"❌ Failed to start worker: {e}")
            return None
    
    def restart_worker():
        """Restart the worker."""
        nonlocal last_restart_time
        
        current_time = time.time()
        if current_time - last_restart_time < min_restart_interval:
            logger.info(f"⏳ Skipping restart (too soon, {min_restart_interval}s interval)")
            return
            
        last_restart_time = current_time
        
        # Stop existing workers first
        stop_workers()
        start_worker()
    
    def stop_workers():
        """Stop all Celery workers."""
        try:
            # First, try to stop celery multi workers gracefully
            subprocess.run([
                "/home/rengine/.local/share/pipx/venvs/secator/bin/secator",
                "worker", "--stop"
            ], capture_output=True, timeout=5)
            logger.info("🛑 Stopped existing workers gracefully")
        except Exception as e:
            logger.warning(f"⚠️  Error stopping workers gracefully: {e}")
        
        # Always force kill any remaining celery processes to ensure clean state
        try:
            logger.info("🧹 Force killing any remaining Celery processes...")
            subprocess.run(['pkill', '-f', 'celery.*worker'], timeout=5)
            # Wait a bit for processes to actually die
            time.sleep(2)
            logger.info("✅ Cleaned up Celery processes")
        except Exception as e:
            logger.warning(f"⚠️  Error force killing workers: {e}")
    
    def check_worker_health():
        """Check if worker is still running and restart if needed."""
        nonlocal worker_process, last_restart_time
        
        # Don't check health if we just restarted recently
        current_time = time.time()
        if current_time - last_restart_time < min_restart_interval:
            return
        
        # For celery multi, the parent process terminates after starting workers
        # We need to check if the actual Celery workers are running
        import os
        import subprocess
        
        try:
            # First, check if we have any celery worker processes running
            result = subprocess.run(['pgrep', '-f', 'celery.*worker'], capture_output=True, text=True)
            
            if result.returncode != 0 or not result.stdout.strip():
                logger.warning("⚠️  No Celery worker processes found, restarting...")
                restart_worker()
                return
            
            # Count the number of worker processes
            worker_count = len(result.stdout.strip().split('\n'))
            logger.debug(f"✅ Found {worker_count} Celery worker processes")
            
            # Only restart if we have too few workers (less than 3)
            if worker_count < 3:
                logger.warning(f"⚠️  Only {worker_count} workers found, restarting...")
                restart_worker()
            else:
                logger.debug("✅ Sufficient Celery workers are running")
                
        except Exception as e:
            logger.error(f"❌ Error checking worker health: {e}")
            # If we can't check, assume workers are dead and restart
            restart_worker()
    
    # Start initial worker
    start_worker()
    
    # Wait a bit for workers to fully start before starting health checks
    logger.info("⏳ Waiting for workers to fully start...")
    time.sleep(5)
    
    # Setup file watcher with debounced handler
    event_handler = DebouncedReloadHandler(restart_worker)
    observer = Observer()
    
    # Watch reNgine directory
    watch_path = Path("./reNgine")
    if watch_path.exists():
        observer.schedule(event_handler, str(watch_path), recursive=True)
        observer.start()
        
        logger.info("👀 File watcher started. Press Ctrl+C to stop.")
        
        try:
            last_health_check = time.time()  # Start health checks after initial delay
            while True:
                time.sleep(1)
                # Check worker health every 10 seconds
                current_time = time.time()
                if current_time - last_health_check >= 10:
                    check_worker_health()
                    last_health_check = current_time
        except KeyboardInterrupt:
            logger.info("\n🛑 Stopping...")
            observer.stop()
            if worker_process:
                worker_process.terminate()
                worker_process.wait()
        
        observer.join()
    else:
        logger.error("❌ Error: ./reNgine directory not found!")
        sys.exit(1)


if __name__ == "__main__":
    start_smart_reload()
