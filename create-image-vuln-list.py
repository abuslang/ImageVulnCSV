#!/usr/bin/env python3
import http.client
import json
import csv
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlencode
import config  # Imports variables from your config.py file

# --- CONFIGURATION ---
JSON_IMAGES_FILE = 'image_scan_reports.json'
JSON_CONTAINERS_FILE = 'container_scan_reports.json'
CSV_FILENAME = 'image_vulnerabilities.csv'
API_VERSION = "v34.03" 

# --- API HELPERS ---

def clean_url(url):
    """Strips protocol and trailing slashes for http.client"""
    return url.replace('https://', '').replace('http://', '').rstrip('/')

def get_proxy_settings():
    """Manual proxy parsing from environment variables"""
    https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    if https_proxy:
        https_proxy = https_proxy.replace('https://', '').replace('http://', '')
        if ':' in https_proxy:
            proxy_host, proxy_port = https_proxy.split(':')
            return proxy_host, int(proxy_port)
        else:
            print(f"[!] Warning: Proxy found ({https_proxy}) but no port specified.")
    return None, None

def create_connection(base_url, timeout=30):
    """Creates an HTTPS connection, tunneling through proxy if detected"""
    proxy_host, proxy_port = get_proxy_settings()
    
    # Standard Secure SSL Context
    import ssl
    context = ssl.create_default_context()
    
    # Optional: Ignore SSL errors if configured (not recommended but supported)
    if hasattr(config, 'verify_ssl') and not config.verify_ssl:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if proxy_host and proxy_port:
        print(f"[DEBUG] Connecting via Proxy: {proxy_host}:{proxy_port} -> {base_url}")
        conn = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=context)
        conn.set_tunnel(base_url)
    else:
        conn = http.client.HTTPSConnection(base_url, timeout=timeout, context=context)
    
    return conn

def make_request(host, method, endpoint, headers, body=None):
    """Wrapper to handle the http.client request lifecycle"""
    try:
        conn = create_connection(host)
        
        if body and not isinstance(body, str):
            body = json.dumps(body)
            
        conn.request(method, endpoint, body, headers)
        res = conn.getresponse()
        
        response_data = res.read()
        conn.close()
        
        if res.status == 429:
            print("[-] Rate Limit Hit (429). Waiting 30s...")
            time.sleep(30)
            return 429
            
        if res.status != 200:
            print(f"[-] HTTP Error {res.status} on {endpoint}")
            try: print(f"[-] Response: {response_data.decode('utf-8')[:200]}")
            except: pass
            return None
            
        return json.loads(response_data.decode('utf-8'))
        
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        sys.exit(1)

# ==========================================
# PART 1: AUTHENTICATION
# ==========================================

def login_to_prisma():
    print(f"\n[DEBUG] Authenticating via CSPM at: {config.url}")
    auth_host = clean_url(config.url)
    
    payload = {
        "username": config.api_key,
        "password": config.api_secret
    }
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    }

    data = make_request(auth_host, "POST", "/login", headers, payload)
    
    if data and 'token' in data:
        return data['token']
    else:
        print("[-] Authentication failed. No token received.")
        sys.exit(1)

# ==========================================
# PART 2: DATA FETCHING
# ==========================================

def fetch_paginated_data(token, endpoint_base, description, is_image_endpoint=False):
    raw_url = clean_url(config.compute_url)
    
    # Handle tenant path (e.g., us-east1/us-2-12345)
    if "/" in raw_url:
        compute_host, tenant_path = raw_url.split("/", 1)
        tenant_path = "/" + tenant_path 
    else:
        compute_host = raw_url
        tenant_path = ""
        
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'x-redlock-auth': token,
        'x-prisma-cloud-target-env': json.dumps({"permission":"monitorImages"})
    }

    all_items = []
    offset = 0
    limit = 50
    more_data = True

    print(f"\n[DEBUG] Connecting to Host: {compute_host}")

    while more_data:
        params = {'limit': limit, 'offset': offset}
        if is_image_endpoint:
            params['compact'] = 'false'
            
        query_string = urlencode(params)
        full_path = f"{tenant_path}/api/{API_VERSION}{endpoint_base}?{query_string}"

        data = make_request(compute_host, "GET", full_path, headers)

        if data == 429:
            continue 
            
        if data is None:
            print(f"[-] Failed to fetch batch at offset {offset}")
            break

        if isinstance(data, list):
            count = len(data)
            all_items.extend(data)
            print(f"[+] Retrieved {count} items (Offset: {offset})")
            
            offset += count
            if count < limit:
                more_data = False
            time.sleep(1.1)
        else:
            more_data = False

    return all_items

# ==========================================
# PART 3: HELPERS & CSV LOGIC
# ==========================================

def convert_unix_time(ts):
    if not ts or ts == 0: return ""
    try: return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except: return str(ts)

def clean_iso_date(date_str):
    if not date_str or date_str.startswith("0001-01"): return ""
    return date_str.replace("T", " ").replace("Z", "")

def format_cvss(score):
    """Formats CVSS score to 2 decimal places (e.g. 7.50, 0.00)."""
    if score is None or score == "":
        return ""
    try:
        val = float(score)
        return "{:.2f}".format(val)
    except (ValueError, TypeError):
        return score

def parse_risk_factors(risk_factors):
    if not risk_factors: return ""
    if isinstance(risk_factors, dict): return ", ".join(risk_factors.keys())
    return str(risk_factors)

def build_package_map(image_obj):
    pkg_map = {}
    raw_packages_list = image_obj.get('packages') or []
    for entry in raw_packages_list:
        pkgs = entry.get('pkgs') or []
        for p in pkgs:
            if p.get('name') and p.get('version'):
                pkg_map[(p['name'], p['version'])] = {
                    'license': p.get('license', ''),
                    'purl': p.get('purl', '')
                }
    return pkg_map

def get_simple_list(obj_list, key_name='name'):
    if not obj_list: return ""
    return ", ".join([item.get(key_name, '') for item in obj_list if item.get(key_name)])

def build_namespace_map(containers_data):
    print("[*] Building Namespace Map from Containers data...")
    ns_map = {}
    for container in containers_data:
        info = container.get('info') or {}
        image_id = info.get('imageID') or container.get('imageID')
        namespace = info.get('namespace')

        if image_id and namespace:
            if image_id not in ns_map: ns_map[image_id] = set()
            ns_map[image_id].add(namespace)
    print(f"[*] Mapped namespaces for {len(ns_map)} unique images.")
    return ns_map

def generate_csv(images_data, containers_data):
    print(f"\n[*] Starting CSV Generation...")
    
    namespace_map = build_namespace_map(containers_data)
    
    CSV_HEADERS = [
        "Registry", "Repository", "Tag", "Id", "Distro", "Hosts", "Layer", "CVE ID", 
        "Compliance ID", "Result", "Type", "Severity", "Packages", "Source Package", 
        "Package Version", "Package License", "CVSS", "Fix Status", "Fix Date", 
        "Grace Days", "Risk Factors", "Vulnerability Tags", "Description", "Cause", 
        "Containers", "Custom Labels", "Published", "Discovered", "Binaries", 
        "Clusters", "Namespaces", "Collections", "Digest", "Vulnerability Link", 
        "Apps", "Package Path", "Start Time", "Defender Hosts", "Agentless Hosts", 
        "PURL", "Cloud Security Agent Hosts"
    ]

    successful_maps = 0
    mapped_namespaces = set()

    with open(CSV_FILENAME, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        rows_written = 0

        for img in images_data:
            repo_tag = img.get('repoTag') or {}
            registry = repo_tag.get('registry', '')
            repository = repo_tag.get('repo', '')
            tag = repo_tag.get('tag', '')
            image_id = img.get('id', '') or img.get('sha256', '')

            # --- NAMESPACE MERGE ---
            namespaces_list = img.get('namespaces') or []
            if image_id in namespace_map:
                found_namespaces = namespace_map[image_id]
                successful_maps += 1
                mapped_namespaces.update(found_namespaces)
                merged_ns = set(namespaces_list)
                merged_ns.update(found_namespaces)
                namespaces_list = list(merged_ns)
            namespaces_str = ", ".join(namespaces_list)

            os_distro = img.get('osDistro', '')
            os_release = img.get('osDistroRelease', '')
            distro = f"{os_distro}-{os_release}" if (os_distro and os_release) else img.get('distro', '')

            hosts_obj = img.get('hosts') or {}
            host_names = list(hosts_obj.keys()) if isinstance(hosts_obj, dict) else hosts_obj
            hosts_str = ", ".join(host_names) if host_names else ""
            hosts_count = len(host_names) if host_names else 0

            is_agentless = img.get('agentless', False)
            defender_hosts = hosts_count if not is_agentless else 0
            agentless_hosts = hosts_count if is_agentless else 0
            is_csa = img.get('csa', False) or img.get('csaWindows', False)
            csa_hosts = hosts_count if is_csa else 0

            clusters = ", ".join(img.get('clusters') or [])
            collections = ", ".join(img.get('collections') or [])
            digest = (img.get('repoDigests') or [""])[0]
            apps_str = get_simple_list(img.get('applications') or [])
            binaries_str = get_simple_list(img.get('binaries') or [])
            containers_count = len(img.get('instances') or [])
            pkg_lookup = build_package_map(img)

            vulnerabilities = img.get('vulnerabilities') or []
            for vuln in vulnerabilities:
                p_name = vuln.get('packageName', '')
                p_ver = vuln.get('packageVersion', '')
                extras = pkg_lookup.get((p_name, p_ver), {})
                
                row = {
                    "Registry": registry, "Repository": repository, "Tag": tag, "Id": image_id,
                    "Distro": distro, "Hosts": hosts_str, "Layer": "",
                    "CVE ID": vuln.get('cve', ''), "Compliance ID": vuln.get('id', ''),
                    "Result": "fail", "Type": "OS", "Severity": vuln.get('severity', ''),
                    "Packages": p_name, "Source Package": vuln.get('sourcePackage', ''),
                    "Package Version": p_ver, "Package License": extras.get('license', ''),
                    "CVSS": format_cvss(vuln.get('cvss', '')),  # <--- UPDATED to 0.00
                    "Fix Status": vuln.get('status', ''),
                    "Fix Date": convert_unix_time(vuln.get('fixDate')),
                    "Grace Days": vuln.get('gracePeriodDays', ''),
                    "Risk Factors": parse_risk_factors(vuln.get('riskFactors') or {}),
                    "Vulnerability Tags": ", ".join(vuln.get('tags') or []),
                    "Description": vuln.get('description', ''), "Cause": vuln.get('cause', ''),
                    "Containers": containers_count, "Custom Labels": "",
                    "Published": convert_unix_time(vuln.get('published')),
                    "Discovered": clean_iso_date(vuln.get('discovered', '')),
                    "Binaries": binaries_str, "Clusters": clusters,
                    "Namespaces": namespaces_str,
                    "Collections": collections, "Digest": digest,
                    "Vulnerability Link": vuln.get('link', ''), "Apps": apps_str,
                    "Package Path": vuln.get('packagePath', ''),
                    "Start Time": clean_iso_date(vuln.get('discovered', '')),
                    "Defender Hosts": defender_hosts, "Agentless Hosts": agentless_hosts,
                    "PURL": extras.get('purl', ''), "Cloud Security Agent Hosts": csa_hosts
                }
                writer.writerow(row)
                rows_written += 1

            compliance_issues = img.get('complianceIssues') or []
            for comp in compliance_issues:
                row = {
                    "Registry": registry, "Repository": repository, "Tag": tag, "Id": image_id,
                    "Distro": distro, "Hosts": hosts_str, "Layer": "",
                    "CVE ID": "", "Compliance ID": comp.get('id', ''),
                    "Result": "fail", "Type": "Compliance", "Severity": comp.get('severity', ''),
                    "Packages": "", "Source Package": "", "Package Version": "",
                    "Package License": "", "CVSS": "", "Fix Status": "", "Fix Date": "",
                    "Grace Days": "", "Risk Factors": "", "Vulnerability Tags": "",
                    "Description": comp.get('description', ''), "Cause": comp.get('cause', ''),
                    "Containers": containers_count, "Custom Labels": "", "Published": "",
                    "Discovered": "", "Binaries": binaries_str, "Clusters": clusters,
                    "Namespaces": namespaces_str,
                    "Collections": collections, "Digest": digest,
                    "Vulnerability Link": "", "Apps": apps_str, "Package Path": "",
                    "Start Time": clean_iso_date(comp.get('discovered', '')),
                    "Defender Hosts": defender_hosts, "Agentless Hosts": agentless_hosts,
                    "PURL": "", "Cloud Security Agent Hosts": csa_hosts
                }
                writer.writerow(row)
                rows_written += 1

    print(f"[*] Done. Wrote {rows_written} rows to {CSV_FILENAME}")
    print("\n--- Namespace Merge Verification ---")
    print(f"Total Unique Images: {len(images_data)}")
    print(f"Enriched with Namespace data: {successful_maps}")
    if mapped_namespaces:
        print("\nFound Namespaces:")
        for ns in sorted(mapped_namespaces):
            print(f" - {ns}")
    else:
        print("\n[-] No namespaces found (are these images running as containers?)")

# ==========================================
# MAIN EXECUTION
# ==========================================

def main():
    print("--- Prisma Cloud Image Report Generator (Zero Dependency) ---")
    choice = input("[?] Do you want to fetch NEW data from the API? (y/n): ").strip().lower()

    images_data = []
    containers_data = []

    if choice == 'y':
        token = login_to_prisma()
        
        # 1. Fetch Images
        images_data = fetch_paginated_data(token, "/images", "Images", is_image_endpoint=True)
        with open(JSON_IMAGES_FILE, 'w') as f: json.dump(images_data, f, indent=4)
        
        # 2. Fetch Containers
        containers_data = fetch_paginated_data(token, "/containers", "Containers")
        with open(JSON_CONTAINERS_FILE, 'w') as f: json.dump(containers_data, f, indent=4)
    else:
        if os.path.exists(JSON_IMAGES_FILE):
            print(f"[*] Loading Images from {JSON_IMAGES_FILE}...")
            with open(JSON_IMAGES_FILE, 'r', encoding='utf-8') as f: images_data = json.load(f)
        else:
            print(f"[-] Error: {JSON_IMAGES_FILE} missing."); sys.exit(1)

        if os.path.exists(JSON_CONTAINERS_FILE):
            print(f"[*] Loading Containers from {JSON_CONTAINERS_FILE}...")
            with open(JSON_CONTAINERS_FILE, 'r', encoding='utf-8') as f: containers_data = json.load(f)
        else:
            print(f"[-] Warning: {JSON_CONTAINERS_FILE} missing."); containers_data = []

    if images_data:
        generate_csv(images_data, containers_data)
    else:
        print("[-] No image data found to process.")

if __name__ == "__main__":
    main()
