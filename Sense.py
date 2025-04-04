#!/usr/bin/env python3
import threading
import socket
import argparse
import subprocess
import tempfile
import os
import time
import sys
import ipaddress
import datetime
import concurrent.futures
import math
import shutil
import re
from colorama import Fore, Style, Back, init
from scapy.all import send, IP, TCP, sr1

# Initialize colorama for colored output - autoreset ensures colors don't bleed
init(autoreset=True)

# Global variables
discovered_ips = set()
scan_rate = 1  # packets per second
verbose_level = 1
total_sent = 0
total_received = 0
start_time = time.time()
zmap_available = False  # Will be set during initialization
scan_stats = {
    'start_time': time.time(),
    'last_report_time': time.time(),
    'packets_sent_since_last': 0,
    'packets_received_since_last': 0,
    'open_ports_found': 0,
    'closed_ports_found': 0,
    'filtered_ports_found': 0,
    'errors': 0,
    'ports': []  # Will store the ports being scanned
}

# ASCII Art Logos
LOGO_LARGE = f"""{Fore.CYAN}
  ██████╗██╗██╗  ██╗████████╗██╗  ██╗███████╗███████╗███╗   ██╗███████╗███████╗
 ██╔════╝██║╚██╗██╔╝╚══██╔══╝██║  ██║██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝
 ╚█████╗ ██║ ╚███╔╝    ██║   ███████║███████╗█████╗  ██╔██╗ ██║███████╗█████╗
  ╚═══██╗██║ ██╔██╗    ██║   ██╔══██║╚════██║██╔══╝  ██║╚██╗██║╚════██║██╔══╝
 ██████╔╝██║██╔╝ ██╗   ██║   ██║  ██║███████║███████╗██║ ╚████║███████║███████╗
 ╚═════╝ ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝
                                                                                {Style.RESET_ALL}"""

LOGO_SMALL = f"""
{Fore.CYAN}█▀ █ ▀▄▀ ▀█▀ █ █ █▀ █▀▀ █▄ █ █▀ █▀▀
▄█ █ █ █  █  █▀█ ▄█ ██▄ █ ▀█ ▄█ ██▄{Style.RESET_ALL}
"""

# Animation frames for spinner
SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

def spinner(stop_event, message="Processing"):
    """Display a spinner animation while a task is running"""
    i = 0
    while not stop_event.is_set():
        frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
        sys.stdout.write(f"\r{Fore.CYAN}{frame}{Style.RESET_ALL} {message}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")
    sys.stdout.flush()

def display_title_bar():
    """Display a nice title bar for the interactive mode"""
    terminal_width = shutil.get_terminal_size().columns
    print(f"{Fore.BLACK}{Back.CYAN}{' ' * terminal_width}")
    title = "SixthSense Network Scanner"
    padding = (terminal_width - len(title)) // 2
    print(f"{Fore.BLACK}{Back.CYAN}{' ' * padding}{title}{' ' * (terminal_width - padding - len(title))}")
    print(f"{Fore.BLACK}{Back.CYAN}{' ' * terminal_width}{Style.RESET_ALL}")

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_section_header(title):
    """Print a formatted section header"""
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}    {title}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")

def print_step(step_number, step_name, current_step, total_steps):
    """Print the current step in the wizard"""
    print(f"{Fore.GREEN}Step {step_number}/{total_steps}: {step_name}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'▰' * current_step}{'▱' * (total_steps - current_step)}{Style.RESET_ALL}")

def print_status(message, status="info"):
    """Print a status message with appropriate color"""
    if status == "success":
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    elif status == "error":
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
    elif status == "warning":
        print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")
    else:  # info
        print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")

def animated_print(text, delay=0.01):
    """Print text with a typing animation effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def get_user_input(prompt, valid_options=None, validator=None, default=None, password=False):
    """Get user input with validation"""
    while True:
        if default is not None:
            display_prompt = f"{prompt} [{default}]: "
        else:
            display_prompt = f"{prompt}: "

        try:
            if password:
                import getpass
                user_input = getpass.getpass(prompt=display_prompt)
            else:
                user_input = input(display_prompt)

            # Use default if input is empty
            if not user_input and default is not None:
                return default

            # Validate against valid options if provided
            if valid_options is not None:
                if user_input.lower() in [str(opt).lower() for opt in valid_options]:
                    return user_input
                else:
                    print(f"{Fore.RED}Invalid input. Please choose from: {', '.join(map(str, valid_options))}{Style.RESET_ALL}")
                    continue

            # Use custom validator if provided
            if validator is not None:
                validation_result = validator(user_input)
                if validation_result is True:
                    return user_input
                else:
                    print(f"{Fore.RED}{validation_result}{Style.RESET_ALL}")
                    continue

            return user_input
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(0)

def validate_ports(port_str):
    """Validate port string input"""
    # Allow empty string for default
    if not port_str:
        return True

    # Check for common port syntax
    port_patterns = [
        r'^\d+$',                         # Single port: 80
        r'^\d+,\d+(?:,\d+)*$',            # Comma-separated: 22,80,443
        r'^\d+-\d+$',                     # Range: 1-1000
        r'^\d+(?:,\d+)*(?:,\d+-\d+)*$'    # Mixed: 22,80,100-200
    ]

    for pattern in port_patterns:
        if re.match(pattern, port_str):
            # Additional validation for ranges
            if '-' in port_str:
                for part in port_str.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if start > end:
                            return "Port range start must be less than end"
                        if start < 1 or end > 65535:
                            return "Ports must be between 1 and 65535"

            # Validate individual ports
            for part in port_str.replace('-', ',').split(','):
                if not part.isdigit():
                    continue
                port = int(part)
                if port < 1 or port > 65535:
                    return "Ports must be between 1 and 65535"

            return True

    return "Invalid port format. Use single port (80), comma-separated ports (22,80,443), or port range (1-1000)"

def validate_target(target):
    """Validate target input"""
    # Allow empty string for default
    if not target:
        return True

    # Check if it's a file path
    if os.path.isfile(target):
        return True

    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Check if it's a valid CIDR
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    # Check if it's a valid IP range with space
    if ' ' in target:
        try:
            start, end = target.split()
            ipaddress.ip_address(start)
            ipaddress.ip_address(end)
            return True
        except ValueError:
            pass

    # Check if it's a valid IP range with dash
    if '-' in target:
        try:
            start, end = target.split('-')
            ipaddress.ip_address(start)
            ipaddress.ip_address(end)
            return True
        except ValueError:
            pass

    return "Invalid target format. Use IP address, CIDR notation, IP range, or a file path."

def validate_rate(rate_str):
    """Validate scan rate input"""
    # Allow empty string for default
    if not rate_str:
        return True

    try:
        rate = int(rate_str)
        if rate < 1:
            return "Rate must be a positive integer"
        return True
    except ValueError:
        return "Rate must be a number"

def validate_yes_no(value):
    """Validate yes/no input"""
    if value.lower() in ['y', 'yes', 'n', 'no', '']:
        return True
    return "Please enter 'y' or 'n'"

def check_zmap_availability():
    """Check if zmap is installed and available in the system path."""
    try:
        result = subprocess.run(
            ["zmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        if result.returncode == 0:
            if verbose_level >= 2:
                log(2, f"zmap is available: {result.stdout.strip()}")
            return True
        else:
            if verbose_level >= 2:
                log(2, "zmap is installed but returned an error")
            return False
    except FileNotFoundError:
        if verbose_level >= 2:
            log(2, "zmap is not installed or not in the system path")
        return False

def log(level, message, color=None):
    """Log messages based on verbosity level"""
    if verbose_level >= level:
        if color:
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)
        sys.stdout.flush()

def format_time(seconds):
    """Format seconds into a readable time string"""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        seconds = int(seconds % 60)
        return f"{minutes}m{seconds:02d}s"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h{minutes:02d}m"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days} days, {hours}:{int((seconds % 3600) // 60):02d}"

def print_progress(total_targets):
    """Print progress information in zmap-like format"""
    total_ips = total_targets

    while True:
        time.sleep(1)

        # Calculate statistics
        elapsed_time = time.time() - start_time
        elapsed_str = f"{int(elapsed_time//60)}:{int(elapsed_time%60):02d}"

        # Calculate percentage complete
        percent_complete = (total_sent / (total_ips * len(scan_stats['ports']))) * 100 if total_ips > 0 else 0

        # Calculate estimated time remaining
        if total_sent > 0 and percent_complete > 0:
            total_time_estimate = (elapsed_time / percent_complete) * 100
            time_left = total_time_estimate - elapsed_time

            # Format time remaining
            if time_left > 86400:  # More than a day
                days = int(time_left // 86400)
                hours = int((time_left % 86400) // 3600)
                time_left_str = f"({days}d{hours}h left)"
            elif time_left > 3600:  # More than an hour
                hours = int(time_left // 3600)
                minutes = int((time_left % 3600) // 60)
                time_left_str = f"({hours}h{minutes}m left)"
            else:
                minutes = int(time_left // 60)
                seconds = int(time_left % 60)
                time_left_str = f"({minutes}m{seconds}s left)"
        else:
            time_left_str = ""

        # Calculate rates
        avg_send_rate = total_sent / elapsed_time if elapsed_time > 0 else 0
        avg_recv_rate = total_received / elapsed_time if elapsed_time > 0 else 0
        hit_rate = (total_received / total_sent * 100) if total_sent > 0 else 0

        # Calculate instantaneous rates
        current_time = time.time()
        time_diff = current_time - scan_stats['last_report_time']

        if time_diff >= 1.0:  # Report every second
            # Instantaneous rates in packets per second
            inst_send_rate = scan_stats['packets_sent_since_last'] / time_diff
            inst_recv_rate = scan_stats['packets_received_since_last'] / time_diff
            drop_rate = 0  # We don't track drops explicitly

            # Format output - trying to match the zmap format from the example
            print(f" {elapsed_str} {percent_complete:.0f}% {time_left_str}; "
                  f"send: {total_sent} {inst_send_rate:.1f} p/s ({avg_send_rate/1000:.2f} Kp/s avg); "
                  f"recv: {total_received} {inst_recv_rate:.0f} p/s ({avg_recv_rate:.0f} p/s avg); "
                  f"drops: {drop_rate:.0f} p/s ({drop_rate:.0f} p/s avg); "
                  f"hitrate: {hit_rate:.2f}%", end="\r")

            # Reset counters for next interval
            scan_stats['packets_sent_since_last'] = 0
            scan_stats['packets_received_since_last'] = 0
            scan_stats['last_report_time'] = current_time

            # Flush output to ensure it displays properly
            sys.stdout.flush()

def tcp_syn_scan(ip, port, output_file):
    """Perform a TCP SYN scan on a specific IP and port"""
    global total_sent, total_received
    try:
        src_port = 12345  # Random source port
        syn_packet = IP(dst=ip) / TCP(dport=port, sport=src_port, flags='S')  # SYN flag set

        # Record send attempt
        total_sent += 1
        scan_stats['packets_sent_since_last'] += 1

        # Send the packet and wait for response
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response:
            # Record received response
            total_received += 1
            scan_stats['packets_received_since_last'] += 1

            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    discovered_ips.add(ip)
                    scan_stats['open_ports_found'] += 1

                    if verbose_level >= 2:
                        log(2, f"[+] Port {port} is open on {ip}", Fore.GREEN)

                    if output_file:
                        with open(output_file, 'a') as f:
                            # Only write IP address if not already in the file
                            if ip not in discovered_ips:
                                f.write(f"{ip}\n")

                elif response[TCP].flags == 0x14:  # RST
                    scan_stats['closed_ports_found'] += 1
                    if verbose_level >= 3:
                        log(3, f"[-] Port {port} is closed on {ip}", Fore.RED)
                else:
                    # Other TCP flag combinations
                    scan_stats['filtered_ports_found'] += 1
                    if verbose_level >= 4:
                        log(4, f"[?] Port {port} received unknown response from {ip}: flags={response[TCP].flags}")
            else:
                scan_stats['filtered_ports_found'] += 1
                if verbose_level >= 4:
                    log(4, f"[?] Non-TCP response from {ip}:{port}")
        else:
            scan_stats['filtered_ports_found'] += 1
            if verbose_level >= 4:
                log(4, f"[?] Port {port} is filtered (no response) on {ip}", Fore.YELLOW)

    except Exception as e:
        scan_stats['errors'] += 1
        if verbose_level >= 4:
            log(4, f"Error scanning {ip}:{port} - {e}", Fore.RED)

def scan_target(ip, ports, output_file):
    """Scan a single IP address for multiple ports"""
    for port in ports:
        tcp_syn_scan(ip, port, output_file)
        time.sleep(1 / scan_rate)  # Control the scan rate

def process_target_chunk(targets, ports, output_file, max_workers):
    """Process a chunk of targets using a thread pool to control concurrency"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit scan jobs for each target
        futures = [executor.submit(scan_target, ip, ports, output_file) for ip in targets]

        # Wait for all to complete
        concurrent.futures.wait(futures)

def run_zmap_scan(target, port, bandwidth, output_file=None, max_runtime=None):
    """
    Run zmap to scan a target CIDR or IP for a specific port

    Parameters:
    - target: IP or CIDR to scan
    - port: Port number to scan
    - bandwidth: Bandwidth limit (e.g., "10M", "1G")
    - output_file: File to save results (or None for a temporary file)
    - max_runtime: Maximum runtime in seconds (or None for no limit)

    Returns:
    - Path to output file with results
    - Number of hosts discovered
    """
    # Create a temporary file if no output file specified
    temp_file = False
    if output_file is None:
        temp_fd, output_file = tempfile.mkstemp(prefix="zmap_", suffix=".txt")
        os.close(temp_fd)
        temp_file = True

    # Build the zmap command
    cmd = ["zmap", "-p", str(port)]

    # Add bandwidth limit
    if bandwidth:
        cmd.extend(["--bandwidth", bandwidth])

    # Add runtime limit if specified
    if max_runtime:
        cmd.extend(["--max-runtime", str(max_runtime)])

    # Add output file and target
    cmd.extend(["-o", output_file, target])

    if verbose_level >= 2:
        log(2, f"Running zmap command: {' '.join(cmd)}")

    try:
        # Run zmap and capture output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        # Process real-time output
        for line in iter(process.stderr.readline, ''):
            if verbose_level >= 3 and line.strip():
                log(3, f"zmap: {line.strip()}")

        # Wait for completion
        process.wait()

        # Count hosts found
        with open(output_file, 'r') as f:
            hosts_found = sum(1 for _ in f)

        if verbose_level >= 2:
            log(2, f"zmap found {hosts_found} hosts with port {port} open")

        return output_file, hosts_found

    except Exception as e:
        log(1, f"Error running zmap: {e}", Fore.RED)
        if temp_file and os.path.exists(output_file):
            os.unlink(output_file)
        return None, 0

def read_ip_ranges(filename):
    """Read IP ranges from a file, one per line"""
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip() and not line.startswith('#')]

def parse_ports(port_str):
    """Parse port specification into a list of ports to scan"""
    ports = []
    # Handle comma-separated list
    for part in port_str.split(','):
        if '-' in part:
            # Handle port range (e.g., 80-100)
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            # Handle single port
            ports.append(int(part))
    return ports

def parse_targets(target, yield_ips=True):
    """
    Parse various target formats into IP addresses
    If yield_ips is True, it yields each IP address one at a time to save memory
    If yield_ips is False, it returns a count of IPs for statistics
    """
    ip_count = 0

    if target.endswith(".txt"):
        # Read from a file - only show at the highest verbosity
        if verbose_level >= 5:
            log(5, f"Reading targets from file: {target}")
        file_targets = read_ip_ranges(target)
        for item in file_targets:
            if yield_ips:
                # Recursively yield IPs from each item in the file
                for ip in parse_targets(item, yield_ips=True):
                    yield ip
            else:
                # Just count IPs
                ip_count += parse_targets(item, yield_ips=False)

    elif '/' in target:  # Handle CIDR or single IP
        # Only show at the highest verbosity
        if verbose_level >= 5:
            log(5, f"Parsing CIDR notation: {target}")
        try:
            net = ipaddress.ip_network(target, strict=False)
            if yield_ips:
                # Yield IPs one at a time rather than creating a large set
                for ip in net.hosts():
                    yield str(ip)
            else:
                # Just return the count for statistics
                ip_count += net.num_addresses - 2  # Subtract network and broadcast addresses
                if ip_count < 0:  # Handle /31 and /32 special cases
                    ip_count = 1
        except ValueError as e:
            log(1, f"Error parsing CIDR {target}: {e}", Fore.RED)

    elif ' ' in target:  # Handle IP range with space (e.g., "192.168.1.1 192.168.1.254")
        if verbose_level >= 5:
            log(5, f"Parsing IP range: {target}")
        try:
            start_ip, end_ip = target.split()
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))

            if yield_ips:
                # Yield each IP in the range one at a time
                for ip_int in range(start_int, end_int + 1):
                    yield str(ipaddress.IPv4Address(ip_int))
            else:
                # Just return the count
                ip_count += end_int - start_int + 1
        except ValueError as e:
            log(1, f"Error parsing IP range {target}: {e}", Fore.RED)

    elif '-' in target:  # Handle IP range with dash (e.g., "192.168.1.1-192.168.1.254")
        if verbose_level >= 5:
            log(5, f"Parsing IP range with dash: {target}")
        try:
            start_ip, end_ip = target.split('-')
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))

            if yield_ips:
                # Yield each IP in the range one at a time
                for ip_int in range(start_int, end_int + 1):
                    yield str(ipaddress.IPv4Address(ip_int))
            else:
                # Just return the count
                ip_count += end_int - start_int + 1
        except ValueError as e:
            log(1, f"Error parsing IP range {target}: {e}", Fore.RED)

    else:  # Single IP Address
        try:
            # Validate it's a proper IP
            ipaddress.ip_address(target)
            if yield_ips:
                yield target
            else:
                ip_count += 1
        except ValueError as e:
            log(1, f"Error parsing IP {target}: {e}", Fore.RED)

    if not yield_ips:
        return ip_count

def count_targets(target):
    """Count number of targets without loading them all into memory"""
    ip_count = 0

    if target.endswith(".txt"):
        # Read from a file
        try:
            file_targets = read_ip_ranges(target)
            for item in file_targets:
                ip_count += count_targets(item)
        except Exception as e:
            log(1, f"Error reading target file {target}: {e}", Fore.RED)

    elif '/' in target:  # Handle CIDR
        try:
            net = ipaddress.ip_network(target, strict=False)
            # Calculate number of usable hosts in this network
            count = net.num_addresses - 2  # Subtract network and broadcast addresses
            if count < 0:  # Handle /31 and /32 special cases
                count = 1
            ip_count += count
        except ValueError as e:
            log(1, f"Error parsing CIDR {target}: {e}", Fore.RED)

    elif ' ' in target:  # Handle IP range with space
        try:
            start_ip, end_ip = target.split()
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            ip_count += end_int - start_int + 1
        except ValueError as e:
            log(1, f"Error parsing IP range {target}: {e}", Fore.RED)

    elif '-' in target:  # Handle IP range with dash
        try:
            start_ip, end_ip = target.split('-')
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            ip_count += end_int - start_int + 1
        except ValueError as e:
            log(1, f"Error parsing IP range {target}: {e}", Fore.RED)

    else:  # Single IP Address
        try:
            # Validate it's a proper IP
            ipaddress.ip_address(target)
            ip_count += 1
        except ValueError as e:
            log(1, f"Error parsing IP {target}: {e}", Fore.RED)

    return ip_count

def estimate_scan_time(target_count, ports, scan_rate):
    """Estimate how long the scan will take based on targets, ports, and rate"""
    total_scans = target_count * len(ports)
    estimated_seconds = total_scans / scan_rate
    return format_time(estimated_seconds)

def read_ips_from_file(file_path):
    """Read IPs from a file, one per line"""
    ips = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                ips.append(line)
    return ips

def fast_scan_with_zmap(targets, ports, output_file, bandwidth, max_runtime=None):
    """
    Perform a fast initial scan using zmap to discover live hosts
    """
    port_to_file = {}
    
    # Consolidate CIDRs if possible to reduce the number of zmap runs
    consolidated_targets = []
    for target in targets:
        consolidated_targets.append(target)
    
    # Run zmap for each port
    for port in ports:
        log(2, f"Starting zmap scan for port {port}")
        
        # Create a temporary directory to store results for this port
        temp_dir = tempfile.mkdtemp(prefix=f"zmap_port_{port}_")
        combined_output = os.path.join(temp_dir, "combined_results.txt")
        
        # Scan each target CIDR
        all_responsive_hosts = set()
        for target in consolidated_targets:
            log(3, f"Scanning {target} on port {port}")
            
            # Run zmap for this target and port
            result_file, hosts_found = run_zmap_scan(
                target, 
                port, 
                bandwidth=bandwidth,
                max_runtime=max_runtime
            )
            
            if result_file and hosts_found > 0:
                # Read the responsive hosts
                responsive_hosts = read_ips_from_file(result_file)
                all_responsive_hosts.update(responsive_hosts)
                
                # Clean up the temporary file if it was created by run_zmap_scan
                if result_file.startswith(tempfile.gettempdir()):
                    os.unlink(result_file)
        
        # Always create the combined output file, even if empty
        with open(combined_output, 'w') as f:
            for ip in sorted(all_responsive_hosts):
                f.write(f"{ip}\n")
        
        log(2, f"Found {len(all_responsive_hosts)} hosts with port {port} open")
        port_to_file[port] = combined_output
    
    return port_to_file

def scan_with_sixthsense(targets, ports, output_file, rate, max_workers=10, chunk_size=100):
    """Scan targets using the SixthSense scanner

    Parameters:
    - targets: Iterator yielding IP addresses to scan
    - ports: List of ports to scan on each target
    - output_file: File to save results
    - rate: Scan rate (packets per second)
    - max_workers: Maximum number of concurrent worker threads
    - chunk_size: Size of each batch of IPs to process
    """
    global scan_rate
    scan_rate = rate

    # Process targets in chunks to control memory usage
    current_chunk = []
    targets_processed = 0

    for ip in targets:
        current_chunk.append(ip)

        # When chunk is full, process it
        if len(current_chunk) >= chunk_size:
            process_target_chunk(current_chunk, ports, output_file, max_workers)
            targets_processed += len(current_chunk)

            if verbose_level >= 2:
                log(2, f"Processed {targets_processed} targets")

            current_chunk = []  # Clear the chunk to free memory

    # Process any remaining IPs
    if current_chunk:
        process_target_chunk(current_chunk, ports, output_file, max_workers)
        targets_processed += len(current_chunk)

        if verbose_level >= 2:
            log(2, f"Processed {targets_processed} targets total")

def run_wizard():
    """Interactive wizard for configuring a scan"""
    clear_screen()
    display_title_bar()
    print(LOGO_LARGE)
    print()
    animated_print(f"{Fore.GREEN}Welcome to the SixthSense Network Scanner Wizard!{Style.RESET_ALL}", delay=0.02)
    time.sleep(0.5)
    print(f"{Fore.CYAN}This wizard will guide you through setting up a network scan.{Style.RESET_ALL}")
    time.sleep(0.5)
    print()

    # Configuration dictionary to store wizard selections
    config = {}

    # Total number of steps in the wizard
    total_steps = 6

    # Step 1: Target Selection
    print_step(1, "Target Selection", 1, total_steps)
    print(f"\n{Fore.YELLOW}First, let's specify what to scan.{Style.RESET_ALL}")

    # Option to scan a file or direct target
    target_type = get_user_input(
        "Would you like to scan (1) a single target or (2) targets from a file",
        valid_options=["1", "2"],
        default="1"
    )

    if target_type == "1":
        # Single target option
        print("\nTarget can be a single IP (192.168.1.1), CIDR notation (192.168.1.0/24),")
        print("or an IP range (192.168.1.1-192.168.1.254 or 192.168.1.1 192.168.1.254)")
        config['target'] = get_user_input(
            "Enter target to scan",
            validator=validate_target
        )
        config['input_file'] = None
    else:
        # File input option
        print("\nThe file should contain one target per line (IP, CIDR, or IP range)")
        filepath = get_user_input(
            "Enter path to target file",
            validator=lambda x: os.path.isfile(x) or "File not found"
        )
        config['input_file'] = filepath
        config['target'] = None

    # Step 2: Port Selection
    print_step(2, "Port Selection", 2, total_steps)
    print(f"\n{Fore.YELLOW}Now, let's specify which ports to scan.{Style.RESET_ALL}")

    port_type = get_user_input(
        "Would you like to scan (1) a single port or (2) multiple ports",
        valid_options=["1", "2"],
        default="1"
    )

    if port_type == "1":
        # Single port option
        port = get_user_input(
            "Enter port number to scan",
            validator=lambda x: x.isdigit() and 1 <= int(x) <= 65535 or "Port must be between 1 and 65535",
            default="22"
        )
        config['port'] = int(port)
        config['ports'] = None
    else:
        # Multiple ports option
        print("\nSpecify ports as comma-separated list (22,80,443) or ranges (1-1000)")
        ports = get_user_input(
            "Enter ports to scan",
            validator=validate_ports,
            default="22,80,443"
        )
        config['port'] = None
        config['ports'] = ports

    # Step 3: Scan Speed
    print_step(3, "Scan Speed", 3, total_steps)
    print(f"\n{Fore.YELLOW}Let's set the scan speed.{Style.RESET_ALL}")

    speed_option = get_user_input(
        "Select scan speed: (1) Slow, (2) Normal, (3) Fast, (4) Custom",
        valid_options=["1", "2", "3", "4"],
        default="2"
    )

    if speed_option == "1":
        config['rate'] = 100
        print(f"Scan rate set to {config['rate']} packets per second (slower but stealthier)")
    elif speed_option == "2":
        config['rate'] = 1000
        print(f"Scan rate set to {config['rate']} packets per second (balanced)")
    elif speed_option == "3":
        config['rate'] = 5000
        print(f"Scan rate set to {config['rate']} packets per second (faster but more detectable)")
    else:
        rate = get_user_input(
            "Enter custom scan rate (packets per second)",
            validator=validate_rate,
            default="1000"
        )
        config['rate'] = int(rate)

    config['bytes'] = None  # We'll use rate instead of bandwidth limit for simplicity

    # Step 4: zmap Integration
    print_step(4, "Scan Methodology", 4, total_steps)
    print(f"\n{Fore.YELLOW}SixthSense can use zmap for faster scanning if available.{Style.RESET_ALL}")

    # Check if zmap is installed
    zmap_check_result = check_zmap_availability()

    if zmap_check_result:
        print_status("zmap is installed on this system!", "success")
        use_zmap = get_user_input(
            "Would you like to use zmap for faster scanning (y/n)",
            validator=validate_yes_no,
            default="y"
        )
        config['use_zmap'] = use_zmap.lower() in ['y', 'yes']
    else:
        print_status("zmap is not installed on this system.", "warning")
        print("Using standard scanning method instead.")
        config['use_zmap'] = False

    # Step 5: Output Options
    print_step(5, "Output Options", 5, total_steps)
    print(f"\n{Fore.YELLOW}Let's configure how to save the scan results.{Style.RESET_ALL}")

    save_results = get_user_input(
        "Would you like to save scan results to a file (y/n)",
        validator=validate_yes_no,
        default="y"
    )

    if save_results.lower() in ['y', 'yes']:
        output_file = get_user_input(
            "Enter output file path",
            default="sixthsense_results.txt"
        )
        config['output_file'] = output_file
    else:
        config['output_file'] = None

    # Step 6: Verbosity Level
    print_step(6, "Verbosity Level", 6, total_steps)
    print(f"\n{Fore.YELLOW}Finally, let's set how much information to display during the scan.{Style.RESET_ALL}")

    verbosity_desc = """
Verbosity levels:
1 - Minimal (results only)
2 - Standard (progress and basic info)
3 - Detailed (includes closed ports and more statistics)
4 - Debug (all information including errors)
5 - zmap-like (detailed statistics in zmap format)
"""
    print(verbosity_desc)

    verbosity = get_user_input(
        "Select verbosity level (1-5)",
        valid_options=["1", "2", "3", "4", "5"],
        default="2"
    )
    config['verbose'] = int(verbosity)

    # Advanced options - use defaults for simplicity
    config['force_large_scan'] = False
    config['max_runtime'] = None

    # Summary of scan configuration
    print_section_header("Scan Configuration Summary")

    if config['target']:
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {config['target']}")
    elif config['input_file']:
        print(f"{Fore.CYAN}Target File:{Style.RESET_ALL} {config['input_file']}")

    if config['port']:
        print(f"{Fore.CYAN}Port:{Style.RESET_ALL} {config['port']}")
    elif config['ports']:
        print(f"{Fore.CYAN}Ports:{Style.RESET_ALL} {config['ports']}")

    print(f"{Fore.CYAN}Scan Rate:{Style.RESET_ALL} {config['rate']} packets per second")
    print(f"{Fore.CYAN}Use zmap:{Style.RESET_ALL} {'Yes' if config['use_zmap'] else 'No'}")

    if config['output_file']:
        print(f"{Fore.CYAN}Output File:{Style.RESET_ALL} {config['output_file']}")
    else:
        print(f"{Fore.CYAN}Output:{Style.RESET_ALL} Console only (not saving to file)")

    print(f"{Fore.CYAN}Verbosity Level:{Style.RESET_ALL} {config['verbose']}")

    # Confirm and start scan
    print()
    start_scan = get_user_input(
        "Start the scan with these settings (y/n)",
        validator=validate_yes_no,
        default="y"
    )

    if start_scan.lower() in ['y', 'yes']:
        print_status("Starting scan...", "info")
        return config
    else:
        print_status("Scan cancelled.", "warning")
        return None

def main(args):
    """Main function to run the scanner with the provided arguments"""
    global scan_rate, verbose_level, start_time, zmap_available

    # Handle wizard mode if requested
    if args.wizard:
        wizard_config = run_wizard()
        if wizard_config is None:
            return  # User cancelled the wizard

        # Update args with wizard configuration
        for key, value in wizard_config.items():
            if value is not None:  # Only set non-None values
                setattr(args, key, value)

        # Make sure ports is always a list when using the wizard
        if args.ports is None and args.port is not None:
            args.ports = [args.port]

    verbose_level = args.verbose

    # Check if zmap is available if we want to use it
    if args.use_zmap:
        zmap_available = check_zmap_availability()
        if not zmap_available:
            log(1, "Warning: zmap was requested but is not available. Falling back to standard scanning.", Fore.YELLOW)

    # Store ports in scan_stats for progress tracking
    scan_stats['ports'] = args.ports

    # Print banner based on verbosity
    if verbose_level >= 3:
        print(LOGO_LARGE)
    elif verbose_level >= 2:
        print(LOGO_SMALL)

    if verbose_level >= 2:
        msg = "Enhanced Network Scanner"
        if zmap_available and args.use_zmap:
            msg += " with zmap"
        log(2, f"{msg}")
        log(2, f"Starting scan with verbosity level: {verbose_level}")

    # Prepare targets based on command line args
    target_sources = []
    if args.input_file:
        log(2, f"Reading targets from input file: {args.input_file}")
        target_sources.append(args.input_file)
    elif args.target:
        log(2, f"Parsing target: {args.target}")
        target_sources.append(args.target)

    # If no valid targets, exit
    if not target_sources:
        log(1, "No valid targets specified. Exiting.", Fore.RED)
        sys.exit(1)

    # Show a spinner while counting targets
    stop_spinner = threading.Event()
    spinner_thread = threading.Thread(
        target=spinner,
        args=(stop_spinner, "Analyzing targets, please wait..."),
        daemon=True
    )
    if verbose_level >= 2:
        spinner_thread.start()

    # Count targets for progress reporting and scan time estimation
    try:
        target_count = sum(count_targets(source) for source in target_sources)
    finally:
        # Stop the spinner
        stop_spinner.set()
        if verbose_level >= 2 and spinner_thread.is_alive():
            spinner_thread.join()

    # Check if we have any valid targets
    if target_count == 0:
        log(1, "No valid targets found in the specified sources. Exiting.", Fore.RED)
        sys.exit(1)

    # Show number of targets
    if verbose_level >= 2:
        log(2, f"Total targets to scan: {target_count:,}")

    # Determine scan rate based on which parameter was provided
    if args.bytes is not None:
        # Calculate packet rate based on bytes
        # Assuming an average TCP SYN packet size (considering headers)
        average_tcp_syn_packet_size = 60  # bytes
        scan_rate = (args.bytes * 1024) / average_tcp_syn_packet_size  # Convert KB to bytes and calculate packets per second
        if verbose_level >= 2:
            log(2, f"Bandwidth limited to {args.bytes}KB/s (~ {scan_rate:.2f} packets/second)")
    else:
        # Use the specified rate
        scan_rate = args.rate
        if verbose_level >= 2:
            log(2, f"Scan rate: {scan_rate} packets/second")

    # Show ports and estimate scan time
    if verbose_level >= 2:
        ports_display = ','.join(map(str, args.ports[:5]))
        if len(args.ports) > 5:
            ports_display += '...'
        log(2, f"Ports to scan: {len(args.ports)} ports ({ports_display})")

        # Estimate scan time
        est_time = estimate_scan_time(target_count, args.ports, scan_rate)
        log(2, f"Estimated scan time: {est_time}")

    # For extremely large scans, warn the user
    MAX_TARGETS_PER_SCAN = 10000000  # 10 million IPs is a reasonable limit

    if target_count > MAX_TARGETS_PER_SCAN and not args.use_zmap:
        chunks_needed = math.ceil(target_count / MAX_TARGETS_PER_SCAN)
        log(1, f"{Fore.YELLOW}Warning: You're attempting to scan {target_count:,} IP addresses, which is extremely large.{Style.RESET_ALL}")
        log(1, f"This would be better done with zmap (--use-zmap) or split into approximately {chunks_needed} separate scans.")

        if not args.force_large_scan:
            response = input("Would you like to continue anyway? This may cause system resource issues. (y/n): ")
            if response.lower() != 'y':
                log(1, "Scan aborted. Consider using zmap or a more targeted approach.")
                sys.exit(0)

    # Reset start time just before starting the scan
    start_time = time.time()
    scan_stats['start_time'] = start_time
    scan_stats['last_report_time'] = start_time

    # Start the scan
    log(2, f"Scan started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    scan_start = time.time()

    # Determine if we should use zmap and if it's available
    use_zmap = zmap_available and args.use_zmap

    try:
        # Create output file if it doesn't exist
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write("# SixthSense Scan Results\n")
                f.write(f"# Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# IPs with open ports:\n")

        # Path A: Fast scanning with zmap
        if use_zmap:
            log(1, "Using zmap for fast initial scanning", Fore.CYAN)

            # Read all target ranges/CIDRs to pass to zmap
            target_cidrs = []
            for source in target_sources:
                if source.endswith(".txt"):
                    target_cidrs.extend(read_ip_ranges(source))
                else:
                    target_cidrs.append(source)

            # Calculate an appropriate bandwidth for zmap based on the scan rate
            # Assuming ~60 bytes per packet for SYN scans
            zmap_bandwidth = f"{int(scan_rate * 60 / 1024)}K"  # Convert to KB/s
            if int(scan_rate * 60 / 1024) > 1024:
                zmap_bandwidth = f"{scan_rate * 60 / 1024 / 1024:.1f}M"  # Convert to MB/s

            log(2, f"Using zmap bandwidth: {zmap_bandwidth}")

            # Use zmap to quickly find hosts with the specified ports open
            port_to_file = fast_scan_with_zmap(
                target_cidrs,
                args.ports,
                args.output_file,
                zmap_bandwidth,
                max_runtime=args.max_runtime
            )

            # Consolidate results if we have an output file
            if args.output_file:
                # Gather all responsive IPs from all port scans
                all_responsive_ips = set()
                for port, result_file in port_to_file.items():
                    if os.path.exists(result_file):
                        ips = read_ips_from_file(result_file)
                        log(2, f"Adding {len(ips)} IPs from port {port} scan")
                        all_responsive_ips.update(ips)
                    else:
                        log(2, f"No results file found for port {port}")

                # Write to our output file
                with open(args.output_file, 'a') as f:
                    for ip in sorted(all_responsive_ips):
                        f.write(f"{ip}\n")

                log(1, f"Found {len(all_responsive_ips)} unique IPs with open ports", Fore.GREEN)

            # Clean up temporary files
            for result_file in port_to_file.values():
                if os.path.exists(result_file):
                    temp_dir = os.path.dirname(result_file)
                    if temp_dir.startswith(tempfile.gettempdir()):
                        shutil.rmtree(temp_dir, ignore_errors=True)

        # Path B: Standard scanning with SixthSense
        else:
            # Start the activity report thread - but handle thread creation failure gracefully
            try:
                progress_thread = threading.Thread(target=print_progress, args=(target_count,), daemon=True)
                progress_thread.start()
                have_progress_thread = True
            except RuntimeError:
                # If we can't create a progress thread, we'll just log periodic updates instead
                log(1, "Could not create progress thread due to system limitations. Will log periodic updates.")
                have_progress_thread = False

            log(1, "Starting scan...", Fore.CYAN)

            # Calculate appropriate thread count and chunk size based on target count
            if target_count < 1000:
                max_workers = min(50, os.cpu_count() * 5)
                chunk_size = 1000
            elif target_count < 100000:
                max_workers = min(20, os.cpu_count() * 2)
                chunk_size = 500
            else:
                max_workers = max(1, os.cpu_count())
                chunk_size = 100

            log(2, f"Using {max_workers} worker threads and chunk size of {chunk_size}")

            # Generate targets from all sources
            all_targets = []
            for source in target_sources:
                # Create a generator for this source
                target_gen = parse_targets(source)
                all_targets.append(target_gen)

            # Combine all generators into one
            combined_targets = (ip for gen in all_targets for ip in gen)

            # Perform the scan
            scan_with_sixthsense(
                combined_targets,
                args.ports,
                args.output_file,
                scan_rate,
                max_workers=max_workers,
                chunk_size=chunk_size
            )

        # Calculate scan duration
        scan_duration = time.time() - scan_start

        # Print summary
        print("\n")  # Ensure we move past the progress line
        log(1, f"Scan completed in {format_time(scan_duration)}", Fore.GREEN)

        if not use_zmap:  # Standard scan stats
            log(1, f"Total packets sent: {total_sent}")
            log(1, f"Total responses received: {total_received}")
            log(1, f"Open ports found: {scan_stats['open_ports_found']}")

            if verbose_level >= 2:
                log(2, f"Discovered IPs: {len(discovered_ips)}")

            if verbose_level >= 3 and discovered_ips:
                log(3, "Discovered IPs:")
                for ip in sorted(discovered_ips)[:20]:  # Show first 20 to keep output manageable
                    log(3, f"  {ip}")
                if len(discovered_ips) > 20:
                    log(3, f"  ...and {len(discovered_ips) - 20} more")

        if args.output_file:
            log(1, f"Results saved to: {args.output_file}", Fore.GREEN)
            with open(args.output_file, 'a') as f:
                f.write("\n# Scan Summary:\n")
                f.write(f"# Scan completed in {format_time(scan_duration)}\n")
                if use_zmap:
                    for port in args.ports:
                        if port in port_to_file:
                            hosts_found = len(read_ips_from_file(port_to_file[port]))
                            f.write(f"# Port {port}: {hosts_found} hosts\n")
                else:
                    f.write(f"# Total packets sent: {total_sent}\n")
                    f.write(f"# Total responses received: {total_received}\n")
                    f.write(f"# Open ports found: {scan_stats['open_ports_found']}\n")

    except KeyboardInterrupt:
        print("\n")
        log(1, "Scan interrupted by user. Exiting...", Fore.YELLOW)
        sys.exit(1)

    except Exception as e:
        print("\n")
        log(1, f"Error during scan: {e}", Fore.RED)
        if verbose_level >= 3:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SixthSense - Enhanced Network Scanner with zmap Integration")

    # Target specification
    target_group = parser.add_argument_group("Target Selection")
    target_group.add_argument("-L", "--input-file", help="File with a list of CIDR ranges or IPs to scan (1 per line)")
    target_group.add_argument("--target", help="Target IP address, CIDR, or range (e.g., '192.168.1.1' or '192.168.0.0/24' or '192.168.1.1 192.168.1.254')")

    # Port specification
    port_group = parser.add_argument_group("Port Selection")
    port_mutex_group = port_group.add_mutually_exclusive_group()
    port_mutex_group.add_argument("-p", "--port", type=int, help="Single port to scan (e.g., 80)")
    port_mutex_group.add_argument("-ps", "--ports", type=str, help="Multiple ports to scan (e.g., '22,80,443,8080' or '1-1000')")

    # Scan performance options
    perf_group = parser.add_argument_group("Scan Performance")
    rate_mutex_group = perf_group.add_mutually_exclusive_group()
    rate_mutex_group.add_argument("-r", "--rate", type=int, default=1000, help="Rate of scan in packets per second")
    rate_mutex_group.add_argument("-b", "--bytes", type=int, help="Bandwidth limit in KB/s (e.g., 5 for 5KB/s)")

    # zmap integration options
    zmap_group = parser.add_argument_group("zmap Integration")
    zmap_group.add_argument("--use-zmap", action="store_true", help="Use zmap for faster scanning if available")
    zmap_group.add_argument("--max-runtime", type=int, help="Maximum runtime for each zmap scan in seconds")

    # Output options
    output_group = parser.add_argument_group("Output Control")
    output_group.add_argument("-o", "--output-file", help="Output file to save discovered IPs (one per line)")
    output_group.add_argument("-v", "--verbose", type=int, choices=[1, 2, 3, 4, 5], default=2,
                        help="Verbosity level (1-5): 1=minimal, 2=standard, 3=detailed, 4=debug, 5=zmap-like")

    # Advanced options
    advanced_group = parser.add_argument_group("Advanced Options")
    advanced_group.add_argument("--force-large-scan", action="store_true", help="Force scanning even if target count is extremely large")

    # Wizard mode
    wizard_group = parser.add_argument_group("Interactive Mode")
    wizard_group.add_argument("--wizard", action="store_true", help="Start interactive wizard to configure the scan")

    args = parser.parse_args()

    # If wizard mode is selected, the wizard will set all other parameters
    if not args.wizard:
        # Make sure we have either port or ports
        if args.port is None and args.ports is None:
            parser.error("You must specify either -p/--port or -ps/--ports")

        # Make sure we have either a target or input file
        if args.target is None and args.input_file is None:
            parser.error("You must specify either --target or -L/--input-file")

        # Process ports based on which argument was used
        if args.port is not None:
            # Single port mode
            args.ports = [args.port]
        elif args.ports:
            # Multiple ports mode
            args.ports = parse_ports(args.ports)

        # If bytes is specified, validate the format
        if args.bytes:
            try:
                if isinstance(args.bytes, str):
                    if args.bytes[-2:].lower() == 'kb':
                        args.bytes = int(args.bytes[:-2])  # Convert KB to bytes
                    elif args.bytes[-2:].lower() == 'mb':
                        args.bytes = int(args.bytes[:-2]) * 1024  # Convert MB to bytes
                    else:
                        raise ValueError("Invalid unit for bytes. Use 'KB' or 'MB'.")
            except ValueError as e:
                print(f"Error parsing byte input: {e}")
                sys.exit(1)

        # Validate target inputs
        if args.input_file and args.target:
            parser.error("Specify either --input-file or --target, not both.")

    # Run the main function
    main(args)
