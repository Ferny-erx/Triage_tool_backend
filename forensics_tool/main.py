from __future__ import annotations

import platform
import sys
import os
import argparse
import socket
import hashlib
import logging
import datetime
import json
import psutil
import yara
import plotly.express as px
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, List, Union, Any
from functools import lru_cache, wraps
import configparser
from scapy.all import ARP, Ether, srp
from rich.console import Console
from dataclasses import dataclass, field
from tenacity import retry, stop_after_attempt, wait_exponential
import string
import glob

# Enhanced Constants
class ForensicsConfig:
    """Centralized configuration management"""
    MAX_RETRIES: int = 3
    BATCH_SIZE: int = 1000
    SCAN_TIMEOUT: int = 300  # 5 minutes
    PROTECTED_PATHS: List[str] = [
        "\\Windows\\System32\\config\\",
        "\\Windows\\System32\\catroot2\\",
        "\\Windows\\System32\\winevt\\",
        "\\System Volume Information\\"
    ]
    LOG_LEVEL: str = 'INFO'
    RESULTS_BASE_DIR: str = 'results'
    YARA_RULES_DIR: str = 'yara_rules'  # Default YARA rules directory

def log_exception(func):
    """Decorator for logging exceptions with context"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Exception in {func.__name__}: {e}", exc_info=True)
            raise
    return wrapper

@dataclass
class ScanResult:
    """Enhanced data class for scan results with more robust typing"""
    success: bool = False
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)

class FileAnalyzer:
    """Handles file analysis operations with improved error handling"""

    @staticmethod
    @log_exception
    @lru_cache(maxsize=1000)
    def hash_file(file_path: str, hash_algorithm: str = 'sha256') -> Optional[str]:
        """
        Generate file hash with enhanced security and error handling

        Args:
            file_path (str): Path to the file to hash
            hash_algorithm (str): Hashing algorithm to use

        Returns:
            Optional[str]: Hexadecimal hash or special status strings
        """
        if any(protected_path in file_path for protected_path in ForensicsConfig.PROTECTED_PATHS):
            logging.info(f"Skipping protected system file: {file_path}")
            return "PROTECTED_SYSTEM_FILE"
            
        try:
            hash_obj = hashlib.new(hash_algorithm)
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash_obj.update(byte_block)
            return hash_obj.hexdigest()
        except PermissionError:
            logging.warning(f"Permission denied for file: {file_path}")
            return "ACCESS_DENIED"
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            return "FILE_NOT_FOUND"
        except Exception as e:
            logging.error(f"Unexpected error hashing file {file_path}: {e}")
            return None

    @classmethod
    @log_exception
    def process_file_batch(cls, files: List[str], max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Process files in parallel with configurable worker count

        Args:
            files (List[str]): List of file paths to process
            max_workers (Optional[int]): Maximum number of worker threads

        Returns:
            List[Dict[str, Any]]: Processed file metadata
        """
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(cls.process_single_file, file): file 
                for file in files
            }
            for future in as_completed(future_to_file):
                result = future.result()
                if result:
                    results.append(result)
        return results

    @staticmethod
    @log_exception
    def process_single_file(file_path: str) -> Optional[Dict[str, Any]]:
        """
        Process individual file with comprehensive metadata extraction

        Args:
            file_path (str): Path to the file to process

        Returns:
            Optional[Dict[str, Any]]: File metadata dictionary
        """
        try:
            file_stat = os.stat(file_path)
            file_hash = FileAnalyzer.hash_file(file_path)
            file_info = {
                'file_path': file_path,
                'sha256_hash': file_hash,
                'size_bytes': file_stat.st_size,
                'created_at': datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                'modified_at': datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                'accessed_at': datetime.datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                'is_executable': os.access(file_path, os.X_OK)
            }

            # YARA scanning
            if ForensicsTriageTool.yara_rules:
                matches = ForensicsTriageTool.yara_rules.match(file_path)
                file_info['yara_matches'] = [match.rule for match in matches] if matches else []

            return file_info
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")
            return None

class NetworkAnalyzer:
    """Enhanced network analysis with more robust error handling"""

    @retry(
        stop=stop_after_attempt(ForensicsConfig.MAX_RETRIES), 
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    @log_exception
    def perform_arp_scan(
        self, 
        target: Optional[str] = None, 
        timeout: float = 2.0
    ) -> List[Dict[str, str]]:
        """
        Perform ARP network scan with enhanced error handling

        Args:
            target (Optional[str]): Network target to scan
            timeout (float): Scan timeout in seconds

        Returns:
            List[Dict[str, str]]: List of discovered network devices
        """
        if not target:
            logging.error("No target specified for ARP scan.")
            return []
        
        try:
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            answered, _ = srp(packet, timeout=timeout, verbose=False)
            
            results = [
                {
                    'ip': received.psrc, 
                    'mac': received.hwsrc,
                    'timestamp': datetime.datetime.now().isoformat()
                } 
                for sent, received in answered
            ]
            
            logging.info(f"ARP scan discovered {len(results)} devices")
            return results
        
        except Exception as e:
            logging.error(f"Comprehensive ARP scan error: {e}")
            return []

    @log_exception
    def get_network_info(self) -> Dict[str, Union[int, str]]:
        """
        Retrieve comprehensive network information

        Returns:
            Dict[str, Union[int, str]]: Detailed network statistics
        """
        try:
            net_io = psutil.net_io_counters()
            network_interfaces = psutil.net_if_addrs()
            
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'scan_time': datetime.datetime.now().isoformat(),
                'active_interfaces': list(network_interfaces.keys())
            }
        except Exception as e:
            logging.error(f"Error retrieving network information: {e}")
            return {}

class MemoryAnalyzer:
    """Advanced memory analysis with enhanced error handling"""

    @staticmethod
    @log_exception
    def analyze_running_processes() -> List[Dict[str, Any]]:
        """
        Analyze running processes with comprehensive information

        Returns:
            List[Dict[str, Any]]: Detailed process information
        """
        processes: List[Dict[str, Any]] = []
        try:
            for proc in psutil.process_iter([
                'pid', 'name', 'username', 'cmdline', 
                'memory_percent', 'cpu_percent', 'status'
            ]):
                try:
                    process_info = proc.info.copy()
                    process_info.update({
                        'memory_percent': proc.memory_percent(),
                        'cpu_percent': proc.cpu_percent(interval=0.1),
                        'open_files': [f.path for f in proc.open_files()] if proc.open_files else [],
                        'connections': [
                            {
                                'fd': conn.fd, 
                                'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                                'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                                'status': conn.status
                            } 
                            for conn in proc.connections(kind='all') if conn.laddr
                        ]
                    })
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            logging.info(f"Analyzed {len(processes)} running processes")
            return processes
        
        except Exception as e:
            logging.error(f"Comprehensive process analysis error: {e}")
            return []

    @staticmethod
    @log_exception
    def analyze_loaded_modules() -> List[Dict[str, Any]]:
        """
        Analyze system loaded modules with enhanced information

        Returns:
            List[Dict[str, Any]]: Detailed module information
        """
        modules: List[Dict[str, Any]] = []
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    memory_maps = proc.memory_maps()
                    for mmap in memory_maps:
                        modules.append({
                            'pid': proc.pid,
                            'process_name': proc.name(),
                            'path': mmap.path,
                            'rss': mmap.rss,
                            'size': mmap.size,
                            'timestamp': datetime.datetime.now().isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            logging.info(f"Analyzed {len(modules)} loaded modules")
            return modules
        
        except Exception as e:
            logging.error(f"Comprehensive module analysis error: {e}")
            return []

class ForensicsTriageTool:
    def __init__(
        self,
        config_path: Optional[str] = None,
        custom_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize ForensicsTriageTool with flexible configuration options.

        Args:
            config_path (Optional[str]): Path to configuration file.
            custom_config (Optional[Dict[str, Any]]): Custom configuration dictionary.
        """
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = self.setup_results_directory()

        # Initialize configuration
        self.config = {}
        if config_path:
            self.config.update(self.load_config(config_path))
        if custom_config:
            self.config.update(custom_config)

        self.setup_logging()  # Ensure logging setup comes after config initialization

        self.system_info = self.get_system_info()
        self.console = Console()
        self.yara_rules = self.load_yara_rules()

        # Initialize analyzers
        self.file_analyzer = FileAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.memory_analyzer = MemoryAnalyzer()


    @log_exception
    def setup_results_directory(self) -> str:
        """
        Create a timestamped results directory

        Returns:
            str: Path to the created results directory
        """
        results_dir = os.path.join(ForensicsConfig.RESULTS_BASE_DIR, self.timestamp)
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        return results_dir

    @log_exception
    def setup_logging(self) -> None:
        """Configure logging with file and console handlers"""
        log_file = os.path.join(self.results_dir, 'triage_tool.log')
        logging.basicConfig(
            level=getattr(logging, self.config.get('log_level', ForensicsConfig.LOG_LEVEL)),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        logging.info(f"Starting forensics triage session at {self.timestamp}")

    @log_exception
    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from file with enhanced error handling

        Args:
            config_path (str): Path to configuration file

        Returns:
            Dict[str, Any]: Parsed configuration dictionary
        """
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            
            # Convert ConfigParser to dictionary
            config_dict = {section: dict(config[section]) for section in config.sections()}
            logging.info(f"Configuration loaded from {config_path}")
            return config_dict
        except Exception as e:
            logging.error(f"Error loading config file {config_path}: {e}")
            return {}

    @log_exception
    def get_system_info(self) -> Dict[str, Any]:
        """
        Retrieve comprehensive system information

        Returns:
            Dict[str, Any]: Detailed system metadata
        """
        try:
            disk_partitions = []
            if os.name == 'nt':
                drives = [f"{d}:" for d in string.ascii_uppercase if os.path.exists(f"{d}:")]
                for drive in drives:
                    usage = psutil.disk_usage(drive)
                    disk_partitions.append({
                        'mountpoint': drive,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
            else:
                partitions = psutil.disk_partitions()
                for partition in partitions:
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        disk_partitions.append({
                            'mountpoint': partition.mountpoint,
                            'total': usage.total,
                            'used': usage.used,
                            'free': usage.free,
                            'percent': usage.percent
                        })
                    except PermissionError:
                        continue

            return {
                'hostname': socket.gethostname(),
                'platform': platform.platform(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'system_time': datetime.datetime.now().isoformat(),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': disk_partitions
            }
        except Exception as e:
            logging.error(f"Error retrieving system information: {e}")
            return {}

    @log_exception
    def load_yara_rules(self, rules_dir: Optional[str] = None) -> Optional[yara.Rules]:
        """
        Load YARA rules from specified directory

        Args:
            rules_dir (Optional[str]): Directory containing YARA rule files

        Returns:
            Optional[yara.Rules]: Compiled YARA rules or None
        """
        try:
            rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), ForensicsConfig.YARA_RULES_DIR)
            rule_files = glob.glob(os.path.join(rules_dir, '*.yar'))
            
            if not rule_files:
                logging.warning(f"No YARA rule files found in {rules_dir}")
                return None
            
            compiled_rules = yara.compile(filepaths={
                os.path.splitext(os.path.basename(rf))[0]: rf 
                for rf in rule_files
            })
            
            logging.info(f"Loaded {len(rule_files)} YARA rule files")
            return compiled_rules
        except Exception as e:
            logging.error(f"Error loading YARA rules: {e}")
            return None

    @log_exception
    def system_scan(
        self, 
        paths: Optional[List[str]] = None, 
        max_depth: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Perform comprehensive system scan

        Args:
            paths (Optional[List[str]]): Paths to scan
            max_depth (int): Maximum directory traversal depth

        Returns:
            List[Dict[str, Any]]: Scan results
        """
        if not paths:
            if os.name == 'nt':
                paths = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            else:
                paths = [os.path.expanduser('~'), '/']
        
        scan_results = []
        for base_path in paths:
            try:
                for root, dirs, files in os.walk(base_path):
                    # Limit directory depth
                    current_depth = root[len(base_path):].count(os.sep)
                    if current_depth > max_depth:
                        del dirs[:]
                        continue
                    
                    file_paths = [os.path.join(root, f) for f in files]
                    batch_results = self.file_analyzer.process_file_batch(file_paths)
                    scan_results.extend(batch_results)
            except Exception as e:
                logging.error(f"Error scanning path {base_path}: {e}")
        
        logging.info(f"System scan completed with {len(scan_results)} files processed.")
        return scan_results

    @log_exception
    def network_scan(
        self, 
        target: str = "192.168.1.0/24", 
        timeout: float = 2.0
    ) -> Dict[str, Any]:
        """
        Perform network scan with ARP and network information gathering

        Args:
            target (str): Network range to scan
            timeout (float): Scan timeout

        Returns:
            Dict[str, Any]: Network scan results
        """
        try:
            arp_results = self.network_analyzer.perform_arp_scan(target, timeout)
            network_info = self.network_analyzer.get_network_info()
            
            logging.info("Network scan completed.")
            return {
                'arp_scan': arp_results,
                'network_info': network_info,
                'scan_timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Comprehensive network scan error: {e}")
            return {}

    @log_exception
    def memory_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive memory analysis

        Returns:
            Dict[str, Any]: Memory analysis results
        """
        try:
            processes = self.memory_analyzer.analyze_running_processes()
            modules = self.memory_analyzer.analyze_loaded_modules()
            
            logging.info("Memory analysis completed.")
            return {
                'processes': processes,
                'modules': modules,
                'analysis_timestamp': datetime.datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Comprehensive memory analysis error: {e}")
            return {}

    @log_exception
    def save_results(
        self, 
        system_results: List[Dict[str, Any]], 
        network_results: Dict[str, Any], 
        memory_results: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Save forensics scan results to JSON and create visualizations

        Args:
            system_results (List[Dict[str, Any]]): System scan results
            network_results (Dict[str, Any]): Network scan results
            memory_results (Optional[Dict[str, Any]]): Memory analysis results
        """
        try:
            # Save raw results
            results_file = os.path.join(self.results_dir, 'forensics_results.json')
            with open(results_file, 'w') as f:
                json.dump({
                    'system_scan': system_results,
                    'network_scan': network_results,
                    'memory_analysis': memory_results or {}
                }, f, indent=2)
            
            logging.info(f"Results saved to {results_file}")

            # Create visualizations
            self.create_visualizations({
                'system_scan': system_results,
                'network_scan': network_results,
                'memory_analysis': memory_results or {}
            })
            
        except Exception as e:
            logging.error(f"Error saving forensics results: {e}")

    def create_visualizations(self, results: Dict[str, Any]) -> None:
        """
        Create comprehensive visualizations for scan results

        Args:
            results (Dict[str, Any]): Forensics scan results
        """
        try:
            self.create_system_visualizations(results.get('system_scan', []))
            self.create_network_visualizations(results.get('network_scan', {}))
            self.create_memory_visualizations(results.get('memory_analysis', {}))
        except Exception as e:
            logging.error(f"Error creating visualizations: {e}")

    def create_system_visualizations(self, results: List[Dict[str, Any]]) -> None:
        """
        Create visualizations related to system scan results

        Args:
            results (List[Dict[str, Any]]): System scan results
        """
        try:
            # File Size Distribution
            file_sizes = [file['size_bytes'] for file in results if isinstance(file.get('size_bytes'), int)]
            if file_sizes:
                fig = px.histogram(file_sizes, nbins=50, title='File Size Distribution')
                fig.update_layout(xaxis_title='File Size (Bytes)', yaxis_title='Number of Files')
                fig.write_html(os.path.join(self.results_dir, 'file_size_distribution.html'))
                logging.info("System visualization: File Size Distribution created.")

            # Disk Usage Pie Chart
            disk_info = self.system_info.get('disk', [])
            if disk_info:
                labels = [disk['mountpoint'] for disk in disk_info]
                values = [disk['used'] for disk in disk_info]
                fig = px.pie(names=labels, values=values, title='Disk Usage by Partition')
                fig.write_html(os.path.join(self.results_dir, 'disk_usage_pie_chart.html'))
                logging.info("System visualization: Disk Usage Pie Chart created.")
        except Exception as e:
            logging.error(f"Error creating system visualizations: {e}")

    def create_network_visualizations(self, results: Dict[str, Any]) -> None:
        """
        Create visualizations related to network scan results

        Args:
            results (Dict[str, Any]): Network scan results
        """
        try:
            arp_scan = results.get('arp_scan', [])
            if arp_scan:
                # Create a simple table visualization for discovered devices
                df = pd.DataFrame(arp_scan)
                fig = px.scatter_geo(df, lat='latitude', lon='longitude', hover_name='ip', title='Discovered Network Devices')
                # Note: To create an actual geographical map, additional data like geolocation is required.
                # For simplicity, we are not including geolocation in this example.
                fig.write_html(os.path.join(self.results_dir, 'network_devices_map.html'))
                logging.info("Network visualization: Discovered Network Devices Map created.")
        except ImportError:
            logging.warning("Plotly is required for network visualizations but is not installed.")
        except Exception as e:
            logging.error(f"Error creating network visualizations: {e}")

    def create_memory_visualizations(self, results: Dict[str, Any]) -> None:
        """
        Create visualizations related to memory analysis results

        Args:
            results (Dict[str, Any]): Memory analysis results
        """
        try:
            processes = results.get('processes', [])
            if processes:
                # Top 10 processes by CPU usage
                top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:10]
                df_cpu = pd.DataFrame(top_cpu)
                fig_cpu = px.bar(df_cpu, x='name', y='cpu_percent', title='Top 10 Processes by CPU Usage')
                fig_cpu.update_layout(xaxis_title='Process Name', yaxis_title='CPU Usage (%)')
                fig_cpu.write_html(os.path.join(self.results_dir, 'top_cpu_processes.html'))
                logging.info("Memory visualization: Top CPU Processes created.")

                # Top 10 processes by Memory usage
                top_mem = sorted(processes, key=lambda x: x.get('memory_percent', 0), reverse=True)[:10]
                df_mem = pd.DataFrame(top_mem)
                fig_mem = px.bar(df_mem, x='name', y='memory_percent', title='Top 10 Processes by Memory Usage')
                fig_mem.update_layout(xaxis_title='Process Name', yaxis_title='Memory Usage (%)')
                fig_mem.write_html(os.path.join(self.results_dir, 'top_memory_processes.html'))
                logging.info("Memory visualization: Top Memory Processes created.")
        except ImportError:
            logging.warning("Plotly is required for memory visualizations but is not installed.")
        except Exception as e:
            logging.error(f"Error creating memory visualizations: {e}")

import pandas as pd  # Imported here to avoid potential import issues if Plotly is not installed

def main():
    """
    Main entry point for the Forensics Triage Tool

    Provides a command-line interface for performing various forensic scans
    """
    parser = argparse.ArgumentParser(
        description='Advanced Forensics Triage Tool',
        epilog='Perform comprehensive system, network, and memory forensics'
    )
    
    # Configuration and Scanning Options
    parser.add_argument(
        '--config', 
        type=str, 
        help='Path to custom configuration file'
    )
    parser.add_argument(
        '--scan-type', 
        choices=['system', 'network', 'memory', 'all'], 
        default='all', 
        help='Type of forensic scan to perform'
    )
    parser.add_argument(
        '--target', 
        type=str, 
        default='192.168.1.0/24', 
        help='Network target for scanning (for network scan)'
    )
    parser.add_argument(
        '--output-dir', 
        type=str, 
        help='Custom output directory for results'
    )
    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
        default='INFO', 
        help='Set logging verbosity'
    )
    
    # Advanced Options
    parser.add_argument(
        '--max-depth', 
        type=int, 
        default=3, 
        help='Maximum directory depth for system scan'
    )
    parser.add_argument(
        '--timeout', 
        type=float, 
        default=2.0, 
        help='Network scan timeout'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize ForensicsTriageTool with optional configuration
    try:
        forensics_tool = ForensicsTriageTool(
            config_path=args.config,
            custom_config={
                'log_level': args.log_level
            }
        )
        
        # Perform scans based on selected type
        system_results = []
        network_results = {}
        memory_results = {}
        
        if args.scan_type in ['system', 'all']:
            logging.info("Starting system scan...")
            system_results = forensics_tool.system_scan(max_depth=args.max_depth)
        
        if args.scan_type in ['network', 'all']:
            logging.info(f"Starting network scan on target {args.target}...")
            network_results = forensics_tool.network_scan(
                target=args.target, 
                timeout=args.timeout
            )
        
        if args.scan_type in ['memory', 'all']:
            logging.info("Starting memory analysis...")
            memory_results = forensics_tool.memory_analysis()
        
        # Save results
        forensics_tool.save_results(
            system_results, 
            network_results, 
            memory_results
        )
        
        logging.info("Forensics triage completed successfully.")
        
    except Exception as e:
        logging.error(f"Forensics triage failed: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
