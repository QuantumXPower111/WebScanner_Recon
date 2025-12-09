# web_vuln_scanner_report.py

import re
import csv
import sys
import socket
import argparse
import datetime
import time  # NEW: Import the time module for calculating scan duration
from colorama import init, Fore, Style
from tqdm import tqdm
from jinja2 import Environment, FileSystemLoader
import pandas as pd
import concurrent.futures
import nmap

# Initialize Colorama
init(autoreset=True)

# --- Part 1: URL Extraction Logic (Unchanged) ---
def extract_urls_from_file(file_path):
    """Extracts all HTTP/HTTPS URLs from a given text file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} URL source file '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error reading URL source file: {e}")
        return []
    url_pattern = re.compile(r'https?://[^^\s"\'<]+')
    return url_pattern.findall(content)

def save_urls_to_csv(urls, output_file):
    """Saves a list of URLs to a CSV file."""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['url'])
            for url in urls:
                writer.writerow([url])
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Extracted and saved {len(urls)} URLs to '{output_file}'")
        return True
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not save URLs to CSV: {e}")
        return False

# --- Part 2: Vulnerability Scanner Class (Unchanged) ---
class WebVulnScanner:
    def __init__(self, max_workers, timeout):
        self.nm = nmap.PortScanner()
        self.max_workers = max_workers
        self.timeout = timeout
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Scanner initialized with {max_workers} workers and {timeout}s timeout.")

    def resolve_hostname(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def scan_target(self, target_url, nse_args):
        hostname = target_url.replace('http://', '').replace('https://', '').split('/')[0]
        ip_address = self.resolve_hostname(hostname)
        if not ip_address:
            return {'target': target_url, 'status': 'Failed', 'reason': 'Hostname resolution failed'}
        
        print(f"\n{Fore.YELLOW}[SCANNING]{Style.RESET_ALL} {hostname} ({ip_address})")
        command_args = f"-sV -Pn --script-args http.useragent='WebVulnScanner/1.0',http.hostheader='{hostname}' -p 80,443,8080,8443 --open -T4"
        if nse_args:
            command_args += f" --script {nse_args}"

        try:
            self.nm.scan(ip_address, arguments=command_args)
            host_info = self.nm.all_hosts()[0] if self.nm.all_hosts() else None
            if not host_info:
                return {'target': target_url, 'ip': ip_address, 'status': 'Failed', 'reason': 'Nmap found no live host.'}

            results = {'target': target_url, 'ip': host_info, 'status': 'Success', 'open_ports': []}
            for proto in self.nm[host_info].all_protocols():
                for port in self.nm[host_info][proto]:
                    port_info = self.nm[host_info][proto][port]
                    service_data = {
                        'port': port,
                        'protocol': proto,
                        'service': port_info.get('name', 'unknown'),
                        'version': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    }
                    script_output = port_info.get('script', {})
                    vulns = [f"[{script_name}]: {output}" for script_name, output in script_output.items() if 'vuln' in script_name or 'malware' in script_name or 'exploit' in script_name]
                    if vulns:
                        service_data['vulnerabilities'] = vulns
                    results['open_ports'].append(service_data)
            return results
        except nmap.PortScannerError as e:
            return {'target': target_url, 'ip': ip_address, 'status': 'Failed', 'reason': f'Nmap error: {e}'}
        except Exception as e:
            return {'target': target_url, 'ip': ip_address, 'status': 'Failed', 'reason': f'Unexpected error: {e}'}

# --- Part 3: Main Execution Logic (Updated) ---
def main():
    # NEW: Start the timer to measure scan duration
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description="An advanced web vulnerability scanner with comprehensive reporting.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-i', '--input', default='url_list_1.txt', help="Input text file with raw URLs.")
    parser.add_argument('-f', '--file', default='targets.csv', help="Input CSV file with a 'url' column.")
    parser.add_argument('-w', '--workers', type=int, default=5, help="Number of parallel workers. Defaults to 5.")
    parser.add_argument('-t', '--timeout', type=int, default=300, help="Timeout for the entire scanning process in seconds. Defaults to 300.")
    parser.add_argument('-p', '--profile', default='full', choices=['full', 'fast', 'discovery'], help="Scan profile to use. Defaults to 'full'.")
    parser.add_argument('-o', '--output', default='vulnerability_report', help="Output file base name (without extension).")
    args = parser.parse_args()

    # --- Define Scan Profiles ---
    profiles = {
        'full': {'nse': 'default,vuln,http-malware-host,http-sql-injection', 'name': 'Full Vulnerability Scan'},
        'fast': {'nse': 'http-title,http-server-header,http-methods', 'name': 'Fast Banner & Service Grab'},
        'discovery': {'nse': 'http-robots.txt,http-enum,http-vhosts', 'name': 'Content & Host Discovery'}
    }
    active_profile = profiles[args.profile]
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Using scan profile: {active_profile['name']}")

    # --- Check if targets.csv exists ---
    try:
        pd.read_csv(args.file)
    except FileNotFoundError:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} '{args.file}' not found. Creating from '{args.input}'...")
        extracted_urls = extract_urls_from_file(args.input)
        if not extracted_urls or not save_urls_to_csv(extracted_urls, args.file):
            sys.exit(1)

    # --- Load Targets ---
    try:
        df_targets = pd.read_csv(args.file)
        targets = df_targets['url'].tolist()
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Loaded {len(targets)} targets from '{args.file}'.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Could not read CSV file: {e}")
        sys.exit(1)

    # --- Perform Scans ---
    scanner = WebVulnScanner(max_workers=args.workers, timeout=args.timeout)
    all_results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_url = {executor.submit(scanner.scan_target, url, active_profile['nse']): url for url in targets}
            for future in tqdm(concurrent.futures.as_completed(future_to_url, timeout=args.timeout), total=len(targets), desc="Scanning"):
                all_results.append(future.result())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Scan cancelled by user. Saving partial results...")
        for future in future_to_url:
            if future.done():
                try:
                    all_results.append(future.result())
                except Exception:
                    pass

    # --- Process and Generate Comprehensive Report ---
    print(f"\n{Fore.CYAN}[INFO]{Style.RESET_ALL} Processing scan results and generating report...")
    report_data = []
    for res in all_results:
        if res['status'] == 'Success' and res['open_ports']:
            for port_info in res['open_ports']:
                vulns_str = "\n".join(port_info.get('vulnerabilities', ['N/A']))
                report_data.append({
                    'Target': res['target'],
                    'IP': res['ip'],
                    'Port': port_info['port'],
                    'Service': port_info['service'],
                    'Version': port_info['version'],
                    'Vulnerabilities': vulns_str
                })
        else:
            report_data.append({
                'Target': res['target'],
                'IP': res.get('ip', 'N/A'),
                'Port': 'N/A',
                'Service': 'N/A',
                'Version': 'N/A',
                'Vulnerabilities': f"Scan Failed: {res['reason']}"
            })

    # --- Prepare Data for Charts and Summary ---
    df_report = pd.DataFrame(report_data)
    successful_scans = df_report[df_report['Port'] != 'N/A']
    
    # NEW: Extract top technologies from version strings
    all_versions = successful_scans['Version'].dropna()
    tech_stack = all_versions.str.split().str[0].value_counts().nlargest(5)

    service_counts = successful_scans['Service'].value_counts().nlargest(10)
    port_counts = successful_scans['Port'].value_counts()
    vuln_hosts_df = successful_scans[successful_scans['Vulnerabilities'] != 'N/A']
    vuln_hosts_count = len(vuln_hosts_df['Target'].unique())
    high_risk_vulns_count = len(vuln_hosts_df[vuln_hosts_df['Vulnerabilities'].str.contains("vuln", case=False, na=False)])

    # --- Render HTML Report with Jinja2 ---
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('report_template.html')

    # NEW: Calculate final scan duration
    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)

    # MODIFIED: Updated template_vars with new data
    template_vars = {
        "scan_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration": f"{scan_duration} seconds",
        "scan_profile": active_profile['name'],
        "total_targets": len(targets),
        "vuln_hosts_count": vuln_hosts_count,
        "total_open_ports": len(successful_scans),
        "unique_services_count": successful_scans['Service'].nunique(),
        "high_risk_vulns_count": high_risk_vulns_count,
        "service_names": service_counts.index.tolist(),
        "service_counts": service_counts.values.tolist(),
        "port_names": port_counts.index.tolist(),
        "port_counts": port_counts.values.tolist(),
        "top_tech_names": tech_stack.index.tolist(),
        "top_tech_counts": tech_stack.values.tolist(),
        "report_data": report_data
    }

    html_output = template.render(template_vars)
    html_filename = f"{args.output}.html"
    with open(html_filename, 'w') as f:
        f.write(html_output)
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Comprehensive HTML report saved to '{html_filename}'")

    # --- Save CSV and JSON for data portability ---
    csv_filename = f"{args.output}.csv"
    df_report.to_csv(csv_filename, index=False)
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} CSV report saved to '{csv_filename}'")

    json_filename = f"{args.output}.json"
    df_report.to_json(json_filename, orient='records', indent=4)
    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} JSON report saved to '{json_filename}'")


# Make sure line 244 ends cleanly, without any hidden characters.
# For example, if line 244 was the main() call, it should look like this:

if __name__ == "__main__":
    main()

# And the next line (245) should either be the end of the file or another
# function/class definition with no indentation.
