#!/usr/bin/env python

'''
Script for DNS testing (Pihile, AdGuard, etc.).

A useful list of blocked domains:

http://hole.cert.pl/domains/domains.txt
https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt
https://raw.githubusercontent.com/austinheap/sophos-xg-block-lists/master/nocoin.txt
https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt
https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt
https://raw.githubusercontent.com/kevinle-1/Windows-telemetry-blocklist/master/windowsblock.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/Ad_filter_list_by_Disconnect.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/adguard_crypto_host.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/adguard_host.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/adguard_mobile_host.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/adservers.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/easy_privacy_host.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/easylist_host.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/gambling-hosts.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/hostfile.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/KADhosts.txt
https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-pihole-filters/SmartTV_ads.txt
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://www.tranzystor.pl/pliki/ads_world.txt
https://www.tranzystor.pl/pliki/fakenews.txt
https://www.tranzystor.pl/pliki/phishing.txt
https://www.tranzystor.pl/pliki/piholl_black_list.txt
'''

import argparse
import sys
import re
import requests
import socket
import subprocess
import time
from typing import List, Tuple, Dict, Any, Optional, TextIO
import os

# Attempt to import necessary libraries
try:
    import colorama
except ImportError:
    colorama = None

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
    
    try:
        DEFAULT_RESOLVERS = dns.resolver.Resolver().nameservers
    except:
        DEFAULT_RESOLVERS = ['8.8.8.8', '1.1.1.1'] 
        
except ImportError:
    DNSPYTHON_AVAILABLE = False
    DEFAULT_RESOLVERS = []


# --- Global Statistics Storage ---
# Tracks {Resolver_IP: count} for all executed DNS lookups.
DNS_RESOLVER_STATS: Dict[str, int] = {}
TEST_DOMAIN_COUNT = 0
TESTS_COMPLETED = 0

# --- Metadata ---
__author__ = "Igor Brzezek"
__email__ = "igor.brzezek@gmail.com"
__github__ = "https://github.com/IgorBrzezek"
__version__ = "1.2.5" # Version incremented for rate suffix logic
__date__ = "12.12.2025"

# --- Constants for Colors ---
class Colors:
    """Class for ANSI color codes."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Custom Argument Action for Rate Limiting ---

class RateAction(argparse.Action):
    """Parses rate limit value, supporting 's' (per second) and 'm' (per minute) suffixes."""
    def __call__(self, parser, namespace, value, option_string=None):
        if isinstance(value, str):
            value = value.lower()
            match = re.match(r'(\d+\.?\d*)([sm]?)$', value)
            if not match:
                raise argparse.ArgumentError(self, f"Invalid rate limit format: '{value}'. Expected format is number followed by optional 's' (per second) or 'm' (per minute).")
            
            rate_val = float(match.group(1))
            unit = match.group(2) or 's' # Default to per second

            if rate_val < 0:
                 raise argparse.ArgumentError(self, "Rate limit cannot be negative.")

            if unit == 'm':
                rate_val /= 60.0 # Convert per minute to per second
            
            setattr(namespace, self.dest, rate_val)
        else:
            setattr(namespace, self.dest, float(value))


# --- Core Utility Functions ---

def colorize(text: str, color_code: str, use_color: bool) -> str:
    """
    Wraps text with ANSI color codes if use_color is True.
    It relies entirely on the --color argument.
    """
    if use_color:
        return f"{color_code}{text}{Colors.ENDC}"
    return text

def safe_print(message: str, args: argparse.Namespace, stream: Optional[TextIO] = None):
    """Prints a message to stdout/stderr unless in batch mode."""
    if not args.batch:
        if stream:
            stream.write(message + '\n')
        else:
            print(message)

def format_duration(seconds: float) -> str:
    """Converts seconds into a human-readable duration (HH:MM:SS or minutes/seconds)."""
    if seconds >= 3600:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{h:02d}:{m:02d}:{s:02d} (HH:MM:SS)"
    elif seconds >= 60:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"{m}m {s}s"
    else:
        return f"{seconds:.2f}s"
        
def print_resolver_stats(args: argparse.Namespace, file_handle: Optional[TextIO]):
    """Prints the final statistics on DNS resolvers used, sorted by query count."""
    global DNS_RESOLVER_STATS, TESTS_COMPLETED, TEST_DOMAIN_COUNT
    
    if not DNS_RESOLVER_STATS:
        return
        
    stats_list = sorted(
        DNS_RESOLVER_STATS.items(), 
        key=lambda item: item[1], 
        reverse=True
    )
    
    total_queries = sum(DNS_RESOLVER_STATS.values())
    
    safe_print(colorize("\n--- DNS Resolver Statistics ---", Colors.BOLD, args.color), args)
    
    status_line = f"Total lookups performed: {total_queries} / {TEST_DOMAIN_COUNT} domains processed."
    if total_queries != TESTS_COMPLETED:
         status_line += f" (Note: Test was interrupted or data inconsistency occurred.)"

    safe_print(status_line, args)
    safe_print("-----------------------------------", args)
    safe_print(f"{'Resolver IP':<25} | {'Queries':<10} | {'Percentage':<10}", args)
    safe_print("-----------------------------------", args)

    if file_handle:
        file_handle.write("\n--- DNS Resolver Statistics ---\n")
        file_handle.write(f"Total lookups performed: {total_queries} / {TEST_DOMAIN_COUNT} domains processed.\n")
        file_handle.write(f"{'Resolver IP':<25} | {'Queries':<10} | {'Percentage':<10}\n")
        file_handle.write("-----------------------------------\n")

    
    for ip, count in stats_list:
        percentage = (count / total_queries) * 100
        output_line = f"{ip:<25} | {count:<10} | {percentage:.2f}%"
        
        safe_print(output_line, args)
        if file_handle:
            file_handle.write(output_line + '\n')
            
    safe_print(colorize("-----------------------------------\n", Colors.BOLD, args.color), args)

# --- Core Logic Functions (Parsing, Loading, Resolving, Pinging) ---

def parse_domain_list(content: List[str]) -> Tuple[List[str], Dict[str, Any]]:
    # [Function content remains the same]
    valid_domains = []
    stats = {
        'total_lines': len(content),
        'comment_lines': 0,
        'valid_domain_lines': 0,
        'ip_domain_lines': 0,
        'domain_only_lines': 0,
        'error_lines': 0,
        'error_details': {}
    }
    ip_domain_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$')
    domain_only_pattern = re.compile(r'^([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$')

    for i, line in enumerate(content):
        line_num = i + 1
        line = line.strip()
        if not line: continue
        if line.startswith('#'):
            stats['comment_lines'] += 1
            continue

        match_ip_domain = ip_domain_pattern.match(line)
        if match_ip_domain:
            domain = match_ip_domain.group(1)
            valid_domains.append(domain)
            stats['valid_domain_lines'] += 1
            stats['ip_domain_lines'] += 1
            continue

        match_domain_only = domain_only_pattern.match(line)
        if match_domain_only:
            domain = match_domain_only.group(1)
            valid_domains.append(domain)
            stats['valid_domain_lines'] += 1
            stats['domain_only_lines'] += 1
            continue
            
        stats['error_lines'] += 1
        stats['error_details'][line_num] = line
    return valid_domains, stats

def print_check_stats(stats: Dict[str, Any], args: argparse.Namespace, file_handle: Optional[TextIO]):
    # [Function content remains the same]
    output = []
    output.append(colorize(f"\n--- File Validation Statistics ---", Colors.BOLD, args.color))
    output.append(f"Total lines processed: {stats['total_lines']}")
    output.append(colorize(f"Comment lines: {stats['comment_lines']}", Colors.OKCYAN, args.color))
    output.append(colorize(f"Valid domain lines: {stats['valid_domain_lines']}", Colors.OKGREEN, args.color))
    output.append(f"  - IP/Domain format: {stats['ip_domain_lines']}")
    output.append(f"  - Domain only format: {stats['domain_only_lines']}")
    output.append(colorize(f"Error lines: {stats['error_lines']}", Colors.FAIL, args.color))

    if stats['error_lines'] > 0:
        output.append(colorize("\nError Details (Line Number: Content):", Colors.WARNING, args.color))
        for i, (line_num, line_content) in enumerate(stats['error_details'].items()):
            if i >= 10:
                output.append(f"... and {stats['error_lines'] - 10} more errors.")
                break
            output.append(f"  {line_num}: {line_content}")
    output.append(colorize("----------------------------------\n", Colors.BOLD, args.color))
    
    for line in output:
        safe_print(line, args)
        if file_handle:
            file_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', line) + '\n') 

def load_file_content(source_path: str, is_url: bool, args: argparse.Namespace) -> Optional[List[str]]:
    # [Function content remains the same]
    try:
        if is_url:
            safe_print(f"Fetching content from URL: {source_path}", args)
            response = requests.get(source_path, timeout=10)
            response.raise_for_status()
            return response.text.splitlines()
        else:
            safe_print(f"Reading content from local file: {source_path}", args)
            with open(source_path, 'r', encoding='utf-8') as f:
                return f.readlines()
    except requests.exceptions.RequestException as e:
        safe_print(colorize(f"Error fetching URL '{source_path}': {e}", Colors.FAIL, True), args, sys.stderr)
        return None
    except FileNotFoundError:
        safe_print(colorize(f"Error: File not found at '{source_path}'", Colors.FAIL, True), args, sys.stderr)
        return None
    except Exception as e:
        safe_print(colorize(f"An unexpected error occurred while loading content from '{source_path}': {e}", Colors.FAIL, True), args, sys.stderr)
        return None

def resolve_dns(domain: str) -> Tuple[Optional[str], str]:
    """
    Attempts to resolve a domain name to an IP address (including 0.0.0.0) 
    and returns the IP and the resolver used.
    Returns (IP_ADDRESS, RESOLVER_IP)
    """
    global DNSPYTHON_AVAILABLE, DEFAULT_RESOLVERS
    
    # 1. Use dnspython if available (for --showdns or better resolver info)
    if DNSPYTHON_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = DEFAULT_RESOLVERS # Use pre-determined list
                 
            answer = resolver.resolve(domain, 'A')
            ip_addr = str(answer[0].address)
            # The name server that answered the query is the first one in the configured list.
            resolver_ip = resolver.nameservers[0]
            
            return ip_addr, resolver_ip
        except (dns.exception.DNSException, Exception):
            # Fall through to system resolver if dnspython fails
            pass
            
    # 2. Use system's built-in resolver (socket)
    try:
        ip_addr = socket.gethostbyname(domain)
        # We cannot reliably determine the resolver IP with standard socket.
        return ip_addr, "System Default"
    except socket.gaierror:
        return None, ""
    except Exception:
        return None, ""

def ping_domain(ip_addr: str, count: int) -> Tuple[bool, Optional[float]]:
    # [Function content remains the same]
    if sys.platform.startswith('win'):
        cmd = ['ping', '-n', str(count), ip_addr]
        avg_time_pattern = re.compile(r'Średnia\s*=\s*(\d+)\s*ms|Average\s*=\s*(\d+)\s*ms') 
    else:
        cmd = ['ping', '-c', str(count), '-W', '1', ip_addr]
        avg_time_pattern = re.compile(r'rtt min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/[\d.]+/\s*[\d.]+\s*ms')

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=count * 2, check=False
        )
        if result.returncode != 0: return False, None
        
        match = avg_time_pattern.search(result.stdout)
        if match:
            avg_time_str = match.group(1) or match.group(2)
            try:
                avg_time = float(avg_time_str)
                return True, avg_time
            except ValueError: return False, None
        else: return True, 0.0
        
    except FileNotFoundError:
        print(colorize("Error: 'ping' command not found. Cannot perform ping tests.", Colors.FAIL, True), file=sys.stderr)
        return False, None
    except subprocess.TimeoutExpired: return False, None
    except Exception as e:
        print(colorize(f"An error occurred during ping: {e}", Colors.FAIL, True), file=sys.stderr)
        return False, None

def run_ping_tests(domains: List[str], args: argparse.Namespace, file_handle: Optional[TextIO]):
    """Executes DNS resolution and ping tests for the list of domains."""
    global DNS_RESOLVER_STATS, TESTS_COMPLETED
    
    total_domains = len(domains)
    ping_count = args.ping
    live_output = args.live
    rate_limit = args.rate
    ignore_0000 = args.noip 
    show_dns = args.showdns
    
    # Calculate delay between queries if rate limiting is active
    delay = 0.0
    expected_duration = "N/A (Max speed)"
    if rate_limit > 0:
        delay = 1.0 / rate_limit
        expected_time_seconds = total_domains * delay
        expected_duration = format_duration(expected_time_seconds)
        safe_print(colorize(f"Rate limit active: Max {rate_limit:.2f} queries per second.", Colors.OKCYAN, args.color), args)

    safe_print(colorize(f"\n--- Starting Ping Tests (Count: {ping_count}, Domains: {total_domains}) ---", Colors.BOLD, args.color), args)
    safe_print(colorize(f"Expected Test Duration (Rate Limit): {expected_duration}", Colors.OKCYAN, args.color), args)
    
    if file_handle:
        file_handle.write(f"\n--- Starting Ping Tests (Count: {ping_count}, Domains: {total_domains}) ---\n")
        file_handle.write(f"Expected Test Duration (Rate Limit): {expected_duration}\n")

    useful_dns_count = 0
    ping_success_count = 0
    
    # Determine column headers and widths
    DOMAIN_WIDTH = 30
    STATUS_WIDTH = 15
    DNS_IP_WIDTH = 25
    
    if live_output or show_dns:
        header_domain = "Domain".ljust(DOMAIN_WIDTH)
        header_status = "Status".ljust(STATUS_WIDTH)
        header_dns = "Resolver IP" if show_dns else ""
        header_line = f"{header_domain} -> {header_status} {header_dns}"
        safe_print(colorize(header_line, Colors.UNDERLINE, args.color), args)

    
    for i, domain in enumerate(domains):
        start_time = time.time()
        
        ip_addr, resolver_ip = resolve_dns(domain)
        status_text = "UNKNOWN"
        
        # Update global resolver stats
        if resolver_ip:
            DNS_RESOLVER_STATS[resolver_ip] = DNS_RESOLVER_STATS.get(resolver_ip, 0) + 1
        
        resolver_output = resolver_ip.ljust(DNS_IP_WIDTH) if show_dns else ""

        if ip_addr:
            # Check for 0.0.0.0 logic
            if ip_addr == '0.0.0.0' and not ignore_0000:
                status_text = "BLOCKED (0.0.0.0)"
                status_colored = colorize(status_text, Colors.WARNING, args.color)
            else:
                # Valid IP (or 0.0.0.0 and --noip is set)
                useful_dns_count += 1
                
                is_success, avg_time = ping_domain(ip_addr, ping_count)
                
                if is_success:
                    ping_success_count += 1
                    status_text = f"{avg_time:.2f}ms"
                    status_colored = colorize(status_text, Colors.OKGREEN, args.color)
                else:
                    status_text = "NO RESPONSE"
                    status_colored = colorize(status_text, Colors.WARNING, args.color)
        else:
            # DNS resolution failed entirely
            status_text = "NO DNS NAME"
            status_colored = colorize(status_text, Colors.FAIL, args.color)
            
        # Adjust status text if it was 0.0.0.0 but we are counting it as resolved
        if ip_addr == '0.0.0.0' and ignore_0000:
            status_text = f"RESOLVED (0.0.0.0)"
            status_colored = colorize(status_text, Colors.OKCYAN, args.color)
            useful_dns_count = i + 1 # Re-adjust count in case of 0.0.0.0 adjustment needed

        
        domain_output = domain.ljust(DOMAIN_WIDTH)
        status_output = status_colored.ljust(STATUS_WIDTH + len(status_colored) - len(status_text)) # Handle color padding
        
        output_line = f"{domain_output} -> {status_output} {resolver_output}"
        file_line = f"Domain: {domain.ljust(DOMAIN_WIDTH)} | Status: {status_text.ljust(STATUS_WIDTH)} | Resolver: {resolver_ip}"

        if live_output or args.dns_only or show_dns:
            safe_print(output_line, args)
        
        if file_handle:
            file_handle.write(file_line + '\n')
            
        TESTS_COMPLETED = i + 1 # Update completion count
            
        # Apply rate limiting delay
        elapsed_time = time.time() - start_time
        if delay > elapsed_time:
            time.sleep(delay - elapsed_time)

    # Print statistics
    stats_output = []
    stats_output.append(colorize("\n--- Ping Test Statistics ---", Colors.BOLD, args.color))
    stats_output.append(f"Total domains tested: {total_domains}")
    
    dns_percentage = (useful_dns_count/total_domains)*100 if total_domains else 0
    stats_output.append(f"Domains with successful DNS resolution (excluding 0.0.0.0, unless --noip): {useful_dns_count} " + 
          colorize(f"({dns_percentage:.2f}%)", Colors.OKCYAN, args.color))
    
    ping_percentage = (ping_success_count/total_domains)*100 if total_domains else 0
    stats_output.append(f"Domains successfully pinged: {ping_success_count} " +
          colorize(f"({ping_percentage:.2f}%)", Colors.OKGREEN, args.color))
    
    stats_output.append(colorize("----------------------------\n", Colors.BOLD, args.color))

    for line in stats_output:
        safe_print(line, args)
        if file_handle:
            file_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', line) + '\n')
            
    print_resolver_stats(args, file_handle)


def run_dns_only_tests(domains: List[str], args: argparse.Namespace, file_handle: Optional[TextIO]):
    """Executes only DNS resolution tests for the list of domains."""
    global DNS_RESOLVER_STATS, TESTS_COMPLETED
    
    total_domains = len(domains)
    dns_success_count = 0
    rate_limit = args.rate
    ignore_0000 = args.noip
    show_dns = args.showdns


    # Calculate delay between queries if rate limiting is active
    delay = 0.0
    expected_duration = "N/A (Max speed)"
    if rate_limit > 0:
        delay = 1.0 / rate_limit
        expected_time_seconds = total_domains * delay
        expected_duration = format_duration(expected_time_seconds)
        safe_print(colorize(f"Rate limit active: Max {rate_limit:.2f} queries per second.", Colors.OKCYAN, args.color), args)

    
    safe_print(colorize(f"\n--- Starting DNS Resolution Tests (Domains: {total_domains}) ---", Colors.BOLD, args.color), args)
    safe_print(colorize(f"Expected Test Duration (Rate Limit): {expected_duration}", Colors.OKCYAN, args.color), args)

    if file_handle:
        file_handle.write(f"\n--- Starting DNS Resolution Tests (Domains: {total_domains}) ---\n")
        file_handle.write(f"Expected Test Duration (Rate Limit): {expected_duration}\n")

    # Determine column headers and widths
    DOMAIN_WIDTH = 30
    STATUS_WIDTH = 25
    DNS_IP_WIDTH = 25
    
    header_domain = "Domain".ljust(DOMAIN_WIDTH)
    header_status = "Status".ljust(STATUS_WIDTH)
    header_dns = "Resolver IP" if show_dns else ""
    header_line = f"{header_domain} -> {header_status} {header_dns}"
    safe_print(colorize(header_line, Colors.UNDERLINE, args.color), args)


    for i, domain in enumerate(domains):
        start_time = time.time()
        
        ip_addr, resolver_ip = resolve_dns(domain)
        
        # Update global resolver stats
        if resolver_ip:
            DNS_RESOLVER_STATS[resolver_ip] = DNS_RESOLVER_STATS.get(resolver_ip, 0) + 1
        
        resolver_output = resolver_ip.ljust(DNS_IP_WIDTH) if show_dns else ""
        
        if ip_addr:
            if ip_addr == '0.0.0.0' and not ignore_0000:
                # Default behavior: 0.0.0.0 is treated as a failed/blocked resolution
                status_text = "BLOCKED (0.0.0.0)"
                status_colored = colorize(status_text, Colors.WARNING, args.color)
            else:
                # Valid IP (or 0.0.0.0 and --noip is set)
                dns_success_count += 1
                status_text = f"RESOLVED to {ip_addr}"
                status_colored = colorize(status_text, Colors.OKGREEN, args.color)
        else:
            status_text = "NO DNS NAME"
            status_colored = colorize(status_text, Colors.FAIL, args.color)
        
        # Adjust status text if it was 0.0.0.0 but we are counting it as resolved
        if ip_addr == '0.0.0.0' and ignore_0000:
            status_text = f"RESOLVED (0.0.0.0)"
            status_colored = colorize(status_text, Colors.OKCYAN, args.color)

        
        domain_output = domain.ljust(DOMAIN_WIDTH)
        status_output = status_colored.ljust(STATUS_WIDTH + len(status_colored) - len(status_text)) # Handle color padding

        output_line = f"{domain_output} -> {status_output} {resolver_output}"
        file_line = f"Domain: {domain.ljust(DOMAIN_WIDTH)} | Status: {status_text.ljust(STATUS_WIDTH)} | Resolver: {resolver_ip}"
        
        safe_print(output_line, args)
        if file_handle:
            file_handle.write(file_line + '\n')
            
        TESTS_COMPLETED = i + 1 # Update completion count
            
        # Apply rate limiting delay
        elapsed_time = time.time() - start_time
        if delay > elapsed_time:
            time.sleep(delay - elapsed_time)

    # Print statistics
    stats_output = []
    stats_output.append(colorize("\n--- DNS Test Statistics ---", Colors.BOLD, args.color))
    stats_output.append(f"Total domains tested: {total_domains}")
    
    dns_percentage = (dns_success_count/total_domains)*100 if total_domains else 0
    stats_output.append(f"Domains with successful DNS resolution (excluding 0.0.0.0, unless --noip): {dns_success_count} " + 
          colorize(f"({dns_percentage:.2f}%)", Colors.OKCYAN, args.color))
    
    stats_output.append(colorize("-----------------------------\n", Colors.BOLD, args.color))

    for line in stats_output:
        safe_print(line, args)
        if file_handle:
            file_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', line) + '\n')
            
    print_resolver_stats(args, file_handle)


def process_source(source_path: str, is_url: bool, args: argparse.Namespace, file_handle: Optional[TextIO]):
    """Handles the main processing logic for a single file/URL."""
    global TEST_DOMAIN_COUNT
    
    content = load_file_content(source_path, is_url, args)
    if not content:
        return

    valid_domains, stats = parse_domain_list(content)
    TEST_DOMAIN_COUNT = len(valid_domains) # Set total domain count for stats

    # 1. Check/Validation
    if args.check:
        is_stat = args.check == 'stat'
        safe_print(colorize(f"\nProcessing Source: {source_path}", Colors.HEADER, args.color), args)
        safe_print(f"File structure is {'valid' if stats['error_lines'] == 0 else 'invalid'}.", args)
        if is_stat or stats['error_lines'] > 0:
            print_check_stats(stats, args, file_handle)
        
        if not (args.ping or args.dns_only):
            return

    if not valid_domains:
        safe_print(colorize(f"No valid domains found in {source_path} to perform tests.", Colors.WARNING, args.color), args)
        return

    # 2. Action (Ping or DNS)
    if args.ping:
        run_ping_tests(valid_domains, args, file_handle)
    
    elif args.dns_only:
        run_dns_only_tests(valid_domains, args, file_handle)


def process_list_file(args: argparse.Namespace, file_handle: Optional[TextIO]):
    """Handles the processing of a list file containing URLs."""
    url_list_content = load_file_content(args.list_file, is_url=False, args=args)
    if not url_list_content:
        sys.exit(1)
    
    urls = [line.strip() for line in url_list_content if line.strip() and not line.strip().startswith('#')]
    
    if not urls:
        safe_print(colorize(f"The list file '{args.list_file}' contains no valid URLs.", Colors.WARNING, args.color), args)
        sys.exit(0)
        
    header = colorize(f"\n--- Processing {len(urls)} URLs from list file: {args.list_file} ---", Colors.HEADER + Colors.BOLD, args.color)
    safe_print(header, args)
    if file_handle:
        file_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', header) + '\n')
    
    for url in urls:
        process_source(url, is_url=True, args=args, file_handle=file_handle)
        
    footer = colorize(f"--- Finished processing list file: {args.list_file} ---\n", Colors.HEADER + Colors.BOLD, args.color)
    safe_print(footer, args)
    if file_handle:
        file_handle.write(re.sub(r'\x1b\[[0-9;]*m', '', footer) + '\n')

# --- Help Functions (Modified for Column Alignment) ---

def print_help_complex(use_color: bool):
    """Prints the complex help message with column alignment."""
    
    # Column widths for alignment
    C1_WIDTH = 18
    C2_WIDTH = 80

    def format_line(opt: str, desc: str, color_code: str = Colors.OKBLUE):
        opt_colored = colorize(opt, color_code, use_color)
        # Use str.ljust for alignment, compensating for ANSI color codes length
        padding = C1_WIDTH + (len(opt) - len(opt_colored.replace(Colors.ENDC, '').replace(color_code, '')))
        return f"  {opt_colored:<{padding}}{desc}"

    print(colorize(f"\n{'='*C2_WIDTH}", Colors.HEADER, use_color))
    print(colorize(f"DOMAIN CHECKER AND PING UTILITY - Detailed Help", Colors.HEADER + Colors.BOLD, use_color))
    print(colorize(f"{'='*C2_WIDTH}\n", Colors.HEADER, use_color))

    print(colorize("Metadata:", Colors.BOLD, use_color))
    print(f"  Author: {__author__}")
    print(f"  Email: {__email__}")
    print(f"  GitHub: {__github__}")
    print(f"  Version: {__version__}")
    print(f"  Date: {__date__}\n")

    print(colorize("Description:", Colors.BOLD, use_color))
    print("This script validates domain lists, checks DNS resolution, and performs ICMP ping tests.")
    print("Accepted domain list formats:")
    print("  1. IP/Domain format: 'IP_ADDRESS DOMAIN_NAME' (e.g., '0.0.0.0 example.com')")
    print("  2. Domain only format: 'DOMAIN_NAME' (e.g., 'example.com')")
    print("Lines starting with '#' are treated as comments and ignored.\n")

    print(colorize("Usage:", Colors.BOLD, use_color))
    print("  python script_name.py <Source Option> [<Action Option>] [Global Options]\n")

    # 1. Source Options
    print(colorize("1. Source Options (Choose one):", Colors.BOLD + Colors.UNDERLINE, use_color))
    print(format_line("-i <filename>", "Load domain list from a local file.", Colors.OKBLUE))
    print(format_line("-u <url>", "Load domain list from a remote HTTP/HTTPS URL.", Colors.OKBLUE))
    print(format_line("--list <file>", "Load a file containing multiple URLs. Each URL points to a domain list file.", Colors.OKBLUE))
    print()

    # 2. Action Options
    print(colorize("2. Action Options (Choose one action, or use --check alone):", Colors.BOLD + Colors.UNDERLINE, use_color))
    print(format_line("-p <n>", "Perform 'n' ping attempts to each valid domain's IP. Displays full statistics.", Colors.OKGREEN))
    print(format_line("-d", "Check only if DNS name can be resolved to an IP address.", Colors.OKGREEN))
    print(format_line("--check [stat]", "Only validate the structure of the loaded domain list. Use 'stat' for full report.", Colors.OKGREEN))
    print()

    # 3. Output and Control Options
    print(colorize("3. Output and Control Options:", Colors.BOLD + Colors.UNDERLINE, use_color))
    print(format_line("-w <file>", "Write scanning results to the specified file.", Colors.OKCYAN))
    print(format_line("--overwrite", "Use with -w to automatically overwrite the output file without prompting.", Colors.OKCYAN))
    print(format_line("-b, --batch", "Execute everything in the background. Suppresses all console output and implicitly sets --overwrite.", Colors.OKCYAN))
    print(format_line("--live", "Used with -p. Shows live ping results for each domain (Implied/default for -d).", Colors.OKCYAN))
    print(format_line("--rate <x[s/m]>", "Limit query rate to X queries per second (s) or minute (m). Default (0 or omitted) is max speed.", Colors.OKCYAN))
    print(format_line("--noip", "Do NOT ignore '0.0.0.0' resolution; count it as a successful resolution for DNS stats.", Colors.OKCYAN))
    print(format_line("--showdns", "Display the IP address of the DNS server that provided the resolution.", Colors.OKCYAN))
    print(format_line("--color", "Enable ANSI color output for better readability.", Colors.OKCYAN))
    print(format_line("-h / --help", "Display simple (-h) or this complex (--help) help message.", Colors.OKCYAN))
    print()

    print(colorize("Example Usage:", Colors.BOLD, use_color))
    print(f"  1. Ping domains and show DNS resolver IP:")
    print(f"     python script_name.py -i domains.txt -p 4 --showdns --color")
    print(f"  2. Check DNS resolution, counting 0.0.0.0 as success:")
    print(f"     python script_name.py -i domains.txt -d --noip --color")
    print(colorize(f"\n{'='*C2_WIDTH}\n", Colors.HEADER, use_color))


def print_help_simple(use_color: bool):
    """Prints the simple help message with column alignment."""
    
    C1_WIDTH = 18 # Column width

    def format_line(opt: str, desc: str, color_code: str):
        opt_colored = colorize(opt, color_code, use_color)
        padding = C1_WIDTH + (len(opt) - len(opt_colored.replace(Colors.ENDC, '').replace(color_code, '')))
        return f"  {opt_colored:<{padding}}{desc}"

    print(colorize(f"\nDOMAIN CHECKER AND PING UTILITY (v{__version__})", Colors.HEADER + Colors.BOLD, use_color))
    print("Use '--help' for detailed instructions and metadata.\n")
    print(colorize("Usage:", Colors.BOLD, use_color))
    print("  python script_name.py <Source> [<Action>] [Options]\n")
    
    # Source
    print(colorize("Source:", Colors.UNDERLINE, use_color))
    print(format_line('-i <file>', "Load domain list from local file.", Colors.OKBLUE))
    print(format_line('-u <url>', "Load domain list from remote URL.", Colors.OKBLUE))
    print(format_line('--list <file>', "Load list of URLs from a local file.", Colors.OKBLUE))
    print()
    
    # Action
    print(colorize("Action:", Colors.UNDERLINE, use_color))
    print(format_line('-p <n>', "Ping valid domains 'n' times (shows statistics).", Colors.OKGREEN))
    print(format_line('-d', "Check only DNS resolution.", Colors.OKGREEN))
    print(format_line('--check [stat]', "Only check file structure (add 'stat' for full report).", Colors.OKGREEN))
    print()
    
    # Options
    print(colorize("Options:", Colors.UNDERLINE, use_color))
    print(format_line('-w <file>', "Write results to file (prompts overwrite).", Colors.OKCYAN))
    print(format_line('--overwrite', "Suppress overwrite prompt.", Colors.OKCYAN))
    print(format_line('-b, --batch', "Run silently in the background.", Colors.OKCYAN))
    print(format_line('--live', "(With -p) Show live ping results.", Colors.OKCYAN))
    print(format_line('--rate <x[s/m]>', "Limit query rate to X per second/minute.", Colors.OKCYAN))
    print(format_line('--noip', "Count 0.0.0.0 as a successful resolution.", Colors.OKCYAN))
    print(format_line('--showdns', "Display the responding DNS server IP.", Colors.OKCYAN))
    print(format_line('--color', "Enable colorful output.", Colors.OKCYAN))
    print(format_line('-h / --help', "Display this help / detailed help.", Colors.OKCYAN))

# --- Main Execution Flow ---

def main():
    """Main function to setup argument parser and run the script."""
    
    # Preliminary check: Determine if colors should be used in help output 
    USE_COLOR_FOR_HELP = '--color' in sys.argv
    
    # Initialize colorama if available and needed for help
    if colorama and USE_COLOR_FOR_HELP:
        colorama.init()
    
    class SimpleHelpAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            print_help_simple(USE_COLOR_FOR_HELP)
            if colorama and USE_COLOR_FOR_HELP: colorama.deinit()
            parser.exit()
            
    class ComplexHelpAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            print_help_complex(USE_COLOR_FOR_HELP)
            if colorama and USE_COLOR_FOR_HELP: colorama.deinit()
            parser.exit()

    parser = argparse.ArgumentParser(
        description="Domain list validation, DNS, and ping testing utility.",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Source Options ---
    group_source = parser.add_argument_group(colorize('Source Options (Choose one)', Colors.BOLD + Colors.UNDERLINE, USE_COLOR_FOR_HELP))
    group_source.add_argument('-i', dest='input_file', type=str, help='Load domain list from a local file.')
    group_source.add_argument('-u', dest='url', type=str, help='Load domain list from a remote HTTP/HTTPS URL.')
    group_source.add_argument('--list', dest='list_file', type=str, help='Load a file with a list of URLs (one per line) to domain list files.')

    # --- Action Options ---
    group_action = parser.add_argument_group(colorize('Action Options', Colors.BOLD + Colors.UNDERLINE, USE_COLOR_FOR_HELP))
    group_action.add_argument('-p', dest='ping', type=int, help='Send N pings to each valid domain. Requires N > 0.')
    group_action.add_argument('-d', dest='dns_only', action='store_true', help='Check only DNS resolution (domain name to IP).')
    group_action.add_argument('--check', dest='check', nargs='?', const='check', default=None, 
                              choices=['check', 'stat'], help='Only check the file structure. Use --check stat for full statistics.')

    # --- Global Options ---
    group_global = parser.add_argument_group(colorize('Output and Control Options', Colors.BOLD + Colors.UNDERLINE, USE_COLOR_FOR_HELP))
    group_global.add_argument('-w', dest='output_file', type=str, help='Write scanning results to the specified file.')
    group_global.add_argument('--overwrite', action='store_true', help='Use with -w to automatically overwrite the output file.')
    group_global.add_argument('-b', '--batch', action='store_true', help='Execute everything in the background. Suppresses all console output and implicitly sets --overwrite if -w is used.')
    group_global.add_argument('--live', action='store_true', help='Used with -p. Shows live ping results for each domain.')
    group_global.add_argument('--rate', action=RateAction, default=0.0, help='Limit query rate (X per second/minute, e.g., 12s, 720m). Default (0 or omitted) is max speed.')
    group_global.add_argument('--noip', action='store_true', help="Do NOT ignore '0.0.0.0' resolution; count it as a successful resolution for DNS stats.")
    group_global.add_argument('--showdns', action='store_true', help="Display the IP address of the DNS server that provided the resolution.")
    group_global.add_argument('--color', action='store_true', help='Enable ANSI color output.')
    group_global.add_argument('-h', action=SimpleHelpAction, nargs=0, help='Display simple help message.')
    group_global.add_argument('--help', action=ComplexHelpAction, nargs=0, help='Display detailed help message.')

    # Initial check for help/no arguments
    if not (('-i' in sys.argv or '-u' in sys.argv or '--list' in sys.argv) or any(arg in sys.argv for arg in ['-h', '--help'])):
         if len(sys.argv) == 1:
            print_help_simple(USE_COLOR_FOR_HELP)
            sys.exit(1)

    args = parser.parse_args()
    
    # --- Post-Parse Setup & Validation ---
    
    # 1. Initialize colorama based on the actual parsed --color argument
    if colorama and args.color:
        colorama.init(autoreset=True)
    elif colorama and not args.color:
        colorama.deinit()
    elif not colorama and args.color:
        safe_print(colorize("Warning: 'colorama' not installed. Color output might not work correctly on some Windows terminals.", Colors.WARNING, True), args)

    # 2. Display warning if --showdns is used without dnspython
    if args.showdns and not DNSPYTHON_AVAILABLE:
        safe_print(colorize("Warning: 'dnspython' not found. DNS Resolver IP will be shown as 'System Default'. Please install 'dnspython' for accurate resolver detection.", Colors.WARNING, args.color), args)

    # 3. Check for action conflicts
    if args.ping and args.dns_only:
        safe_print(colorize("Error: Options -p and -d cannot be used together. Choose one action.", Colors.FAIL, args.color), args, sys.stderr)
        sys.exit(1)
        
    # 4. Handle file writing setup
    file_handle: Optional[TextIO] = None
    if args.output_file:
        should_overwrite = args.overwrite or args.batch # Batch mode implicitly overwrites
        
        if not should_overwrite and os.path.exists(args.output_file):
            if args.batch:
                should_overwrite = True 
            else:
                user_input = input(colorize(f"Output file '{args.output_file}' exists. Overwrite? (y/N): ", Colors.WARNING, args.color))
                if user_input.lower() not in ['y', 'yes']:
                    safe_print(colorize("File writing aborted by user.", Colors.FAIL, args.color), args)
                    sys.exit(0)
        
        try:
            mode = 'w' # Always overwrite if file exists (after prompt) or if forced
            file_handle = open(args.output_file, mode, encoding='utf-8')
            if not args.batch:
                safe_print(colorize(f"Writing results to: {args.output_file} (Mode: Overwrite)", Colors.OKCYAN, args.color), args)
        except Exception as e:
            safe_print(colorize(f"Error opening file '{args.output_file}': {e}", Colors.FAIL, True), args, sys.stderr)
            sys.exit(1)


    # --- Execution Logic ---
    
    source_provided = args.list_file or args.input_file or args.url
    
    if args.list_file:
        process_list_file(args, file_handle)
    elif args.input_file:
        process_source(args.input_file, is_url=False, args=args, file_handle=file_handle)
    elif args.url:
        process_source(args.url, is_url=True, args=args, file_handle=file_handle)
    
    if not source_provided and (args.check or args.ping or args.dns_only):
         safe_print(colorize("Error: You must provide one of the source options (-i, -u, or --list).", Colors.FAIL, args.color), args, sys.stderr)
         print_help_simple(args.color)
         sys.exit(1)

    if not (args.check or args.ping or args.dns_only) and source_provided:
        safe_print(colorize("Warning: No action selected (--check, -p, or -d). Script only loaded/validated source structure.", Colors.WARNING, args.color), args)

    # --- Cleanup ---
    if file_handle:
        file_handle.close()
    if colorama and args.color:
        colorama.deinit()


if __name__ == '__main__':
    # Store initial args to pass to interrupt handler if necessary
    
    # We must parse args early to use them in the except block
    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        # Avoid full parsing if only help is requested
        main() 
    else:
        try:
            # Re-parse arguments for the interrupt handler context
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument('-w', dest='output_file', type=str, default=None)
            parser.add_argument('--color', action='store_true', default=False)
            parser.add_argument('-b', '--batch', action='store_true', default=False)
            
            # Simple RateAction check for non-main parsing
            parser.add_argument('--rate', action=RateAction, default=0.0) 
            parser.add_argument('--noip', action='store_true', default=False)
            
            # Ensure parser knows about action flags that set global counters
            parser.add_argument('-p', dest='ping', type=int, default=0)
            parser.add_argument('-d', dest='dns_only', action='store_true', default=False)
            parser.add_argument('--check', default=None)
            
            # Add all source arguments to ensure correct flow when checking for exceptions
            parser.add_argument('-i', dest='input_file', type=str, default=None)
            parser.add_argument('-u', dest='url', type=str, default=None)
            parser.add_argument('--list', dest='list_file', type=str, default=None)
            parser.add_argument('--live', action='store_true', default=False)
            parser.add_argument('--showdns', action='store_true', default=False)
            
            # We must use parse_known_args to avoid errors if main parser validates required args
            # If main() exits early, we want to capture its context.
            # We try to initialize context_args with best effort.
            context_args, _ = parser.parse_known_args()
            
            main()
            
        except KeyboardInterrupt:
            # Handle Ctrl+C interruption gracefully
            # Use stored context_args for output settings
            
            # Re-initialize colorama for the interrupt message
            if colorama and context_args.color:
                colorama.init(autoreset=True)

            safe_print(colorize("\nScript interrupted by user (Ctrl+C).", Colors.FAIL, True), context_args)
            
            # Open file handle for writing interrupt stats, if applicable
            interrupt_file_handle: Optional[TextIO] = None
            if context_args.output_file and (context_args.ping or context_args.dns_only):
                try:
                    # Append interrupt notice and stats to the file
                    interrupt_file_handle = open(context_args.output_file, 'a', encoding='utf-8')
                    interrupt_file_handle.write(f"\n\n--- TEST INTERRUPTED BY USER (Ctrl+C) ---\n")
                    interrupt_file_handle.write(f"Completed {TESTS_COMPLETED} of {TEST_DOMAIN_COUNT} domains.\n")
                    
                    # Print resolver stats to the file only if the test was running
                    if TESTS_COMPLETED > 0:
                        print_resolver_stats(context_args, interrupt_file_handle)
                        
                except Exception as e:
                    safe_print(colorize(f"Error writing interrupt details to file: {e}", Colors.FAIL, True), context_args, sys.stderr)
                finally:
                    if interrupt_file_handle:
                        interrupt_file_handle.close()

            # Display final resolver stats to console
            if TESTS_COMPLETED > 0 and (context_args.ping or context_args.dns_only):
                print_resolver_stats(context_args, None)
                
            if colorama and context_args.color:
                colorama.deinit()
            sys.exit(1)