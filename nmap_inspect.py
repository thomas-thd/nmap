#!/usr/bin/env python3
# nmap_inspect.py
# Parse Nmap XML (-oX) files in scans/ and print a human-readable summary per host.
# Options:
#   --csv        : export CSV report (nmap_inspect_report.csv)
#   --per-host   : create one text report file per host under reports/
#
# Usage:
#   python nmap_inspect.py --per-host --csv

import os
import glob
import csv
import argparse
from lxml import etree
from collections import Counter

SCANS_DIR = "scans"
CSV_OUT = "nmap_inspect_report.csv"
REPORTS_DIR = "reports"

# --- Parsing Nmap XML ---
def parse_nmap_xml(path):
    hosts = {}
    tree = etree.parse(path)
    root = tree.getroot()
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        # Hostname
        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None and hn.get("name"):
                hostname = hn.get("name")
        # Ports
        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                st = p.find("state")
                if st is None or st.get("state") != "open":
                    continue
                portnum = p.get("portid")
                proto = p.get("protocol")
                svc = p.find("service")
                svc_name = svc.get("name") if svc is not None and svc.get("name") else ""
                svc_product = svc.get("product") if svc is not None and svc.get("product") else ""
                svc_version = svc.get("version") if svc is not None and svc.get("version") else ""
                ports.append({
                    "port": int(portnum),
                    "proto": proto,
                    "service": svc_name.lower(),
                    "product": svc_product,
                    "version": svc_version
                })
        # OS
        os_list = []
        os_el = host.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                name = m.get("name")
                accuracy = m.get("accuracy")
                if name:
                    os_list.append((name, int(accuracy) if accuracy and accuracy.isdigit() else None))
        hosts[ip] = {"hostname": hostname, "ports": sorted(ports, key=lambda x: x["port"]), "os": os_list}
    return hosts

# --- Merge multiple scans ---
def gather_all_hosts(scans_dir):
    all_hosts = {}
    for path in glob.glob(os.path.join(scans_dir, "*.xml")):
        parsed = parse_nmap_xml(path)
        for ip, info in parsed.items():
            if ip not in all_hosts:
                all_hosts[ip] = info
            else:
                existing_ports = {(p['port'], p['proto']) for p in all_hosts[ip]['ports']}
                for p in info['ports']:
                    key = (p['port'], p['proto'])
                    if key not in existing_ports:
                        all_hosts[ip]['ports'].append(p)
                existing_os = {o[0] for o in all_hosts[ip]['os']}
                for o in info['os']:
                    if o[0] not in existing_os:
                        all_hosts[ip]['os'].append(o)
                if not all_hosts[ip]['hostname'] and info.get('hostname'):
                    all_hosts[ip]['hostname'] = info.get('hostname')
    for ip in all_hosts:
        all_hosts[ip]['ports'] = sorted(all_hosts[ip]['ports'], key=lambda x: x['port'])
    return all_hosts

# --- Filtrer les hôtes actifs uniquement ---
def filter_active_hosts(all_hosts):
    return {ip: info for ip, info in all_hosts.items() if info['ports'] or info['os']}

# --- Heuristique type équipement ---
def guess_device_type(info):
    ports = {p['port'] for p in info['ports']}
    services = {p['service'] for p in info['ports'] if p['service']}
    os_text = " ".join([o[0].lower() for o in info['os']])
    if 161 in ports or "snmp" in services or "cisco" in os_text or "router" in os_text:
        return "Équipement réseau (switch/router)"
    if 445 in ports or 139 in ports or "microsoft" in os_text or "windows" in os_text or 3389 in ports:
        return "Hôte Windows (PC/Serveur)"
    if 3306 in ports or 5432 in ports or 1433 in ports:
        return "Base de données / Serveur applicatif"
    web_ports = {80, 443, 8080, 8000, 8443}
    if 22 in ports and len(ports & web_ports) >= 1:
        return "Serveur (SSH + services web)"
    if len(ports & web_ports) >= 1 and len(ports) <= 3:
        return "Device Web simple (possible IoT)"
    if len(ports) >= 10:
        return "Serveur (beaucoup de ports ouverts)"
    if len(ports) == 0:
        return "Hôte (aucun port ouvert détecté)"
    return "Inconnu / Poste utilisateur possible"

# --- Résumé hôte ---
def summarize_host(ip, info):
    lines = []
    hn = info.get("hostname") or "-"
    lines.append(f"IP: {ip}    Hostname: {hn}")
    # OS
    if info['os']:
        os_lines = [f"{o[0]} (accuracy={o[1]}%)" if o[1] is not None else o[0] for o in info['os']]
        lines.append("OS détectés: " + " ; ".join(os_lines))
    else:
        lines.append("OS détectés: -")
    # Ports
    if info['ports']:
        lines.append(f"Ports ouverts ({len(info['ports'])}):")
        for p in info['ports']:
            svc = p['service'] or "-"
            prod = (p['product'] + " " + p['version']).strip()
            prod = prod if prod else "-"
            lines.append(f"  - {p['port']}/{p['proto']}: {svc}  | {prod}")
    else:
        lines.append("Ports ouverts: aucun")
    # Services fréquents
    services = [p['service'] for p in info['ports'] if p['service']]
    serv_counts = Counter(services)
    if serv_counts:
        top = serv_counts.most_common(5)
        lines.append("Services fréquents: " + ", ".join(f"{s}({c})" for s,c in top))
    # Device guess
    lines.append("Estimation type d'équipement: " + guess_device_type(info))
    return "\n".join(lines)

# --- Export CSV ---
def export_csv(all_hosts, csv_path):
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip","hostname","os_detected","num_ports","top_services","device_guess","ports_list"])
        for ip, info in sorted(all_hosts.items(), key=lambda x: tuple(int(part) for part in x[0].split("."))):
            osd = ";".join([o[0] for o in info['os']]) if info['os'] else ""
            num_ports = len(info['ports'])
            services = ";".join(sorted({p['service'] for p in info['ports'] if p['service']}))
            guess = guess_device_type(info)
            ports_list = ";".join([f"{p['port']}/{p['proto']}:{p['service']}" for p in info['ports']])
            w.writerow([ip, info.get('hostname') or "", osd, num_ports, services, guess, ports_list])
    print(f"CSV exporté: {csv_path}")

# --- Export texte par hôte ---
def sanitize_filename(s):
    return "".join(c for c in s if c.isalnum() or c in "._-").rstrip()

def export_per_host(all_hosts, reports_dir):
    os.makedirs(reports_dir, exist_ok=True)
    for idx, (ip, info) in enumerate(sorted(all_hosts.items(), key=lambda x: tuple(int(p) for p in x[0].split("."))), start=1):
        hn = info.get('hostname') or "-"
        safe_name = sanitize_filename(f"{idx:03d}_{ip}_{hn}.txt")
        path = os.path.join(reports_dir, safe_name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"--- Host report #{idx} ---\n")
            f.write(summarize_host(ip, info))
            f.write("\n")
        print(f"[file] {path}")

# --- Main ---
def main(csv_export=False, per_host=False):
    if not os.path.isdir(SCANS_DIR):
        print(f"Le dossier {SCANS_DIR} n'existe pas. Place tes fichiers nmap -oX dedans.")
        return

    all_hosts = gather_all_hosts(SCANS_DIR)
    active_hosts = filter_active_hosts(all_hosts)

    if not active_hosts:
        print("Aucun host actif détecté dans", SCANS_DIR)
        return

    sorted_hosts = sorted(active_hosts.items(), key=lambda x: tuple(int(p) for p in x[0].split(".")))

    print(f"{len(sorted_hosts)} hosts actifs trouvés. Détail par appareil :\n")
    for idx, (ip, info) in enumerate(sorted_hosts, start=1):
        header = f"=== Host #{idx} — {ip} ==="
        print(header)
        print(summarize_host(ip, info))
        print("=" * max(len(header), 40))
        print()

    if per_host:
        print(f"Création des fichiers par hôte dans '{REPORTS_DIR}/' ...")
        export_per_host(active_hosts, REPORTS_DIR)

    if csv_export:
        export_csv(active_hosts, CSV_OUT)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inspect Nmap XML and summarize hosts (OS, services, guess device).")
    parser.add_argument("--csv", action="store_true", help="Export report as CSV")
    parser.add_argument("--per-host", action="store_true", help="Create one text report file per host in 'reports/'")
    args = parser.parse_args()
    main(csv_export=args.csv, per_host=args.per_host)
