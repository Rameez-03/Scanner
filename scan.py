#!/usr/bin/env python3
"""
scan_patched.py - Threaded port scanner with banner grabbing and live CVE lookup (NVD v2 + CIRCL fallback).
Includes improved banner -> product/version extraction for better CVE matching.
Safe test mode: uses only HTTP GETs / simple TCP reads and public CVE APIs.
Author: (you)
"""

import socket
import threading
from queue import Queue, Empty
import requests
import os
import time
from urllib.parse import quote_plus
import re

# Config
TIMEOUT = 5.0
THREADS = 100
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_URL = "https://vulnerability.circl.lu/api/search/"
q = Queue()
results_lock = threading.Lock()
print_lock = threading.Lock()

# ------------------ Banner extraction helper ------------------ #
def extract_keywords_from_banner(banner):
    """
    Return an ordered list of keyword candidates for CVE lookup derived from the banner.
    Prioritises product+version pairs like "OpenSSL 1.0.1" and "OpenSSL/1.0.1".
    """
    if not banner:
        return []

    banner = banner.strip()
    candidates = []
    seen = set()

    # 1) find common product/version patterns NAME/1.2.3 or NAME 1.2.3 (with optional v)
    matches = re.findall(r'([A-Za-z0-9\-\._]+)[/ ]v?(\d+\.\d+(?:\.\d+)?)', banner)
    for name, ver in matches:
        cand1 = f"{name} {ver}"
        cand2 = f"{name}/{ver}"
        for c in (cand1, cand2):
            if c not in seen:
                candidates.append(c)
                seen.add(c)

    # 2) look for well-known product names and attempt to extract versions near them
    common = ['openssl','nginx','apache','httpd','python','php','mysql','postgres','tomcat','jetty','node','werkzeug']
    low = banner.lower()
    for p in common:
        if p in low:
            m = re.search(rf'({p})[/ ]v?(\d+\.\d+(?:\.\d+)?)', low)
            if m:
                cand = f"{m.group(1)} {m.group(2)}"
                cand = cand.split()
                cand = f"{cand[0].capitalize()} {cand[1]}"
                if cand not in seen:
                    candidates.append(cand)
                    seen.add(cand)
            cap = p.capitalize()
            if cap not in seen:
                candidates.append(cap)
                seen.add(cap)

    # 3) add the whole banner with some normalization variants (slash->space, lower)
    whole = banner
    if whole not in seen:
        candidates.append(whole); seen.add(whole)
    sspace = banner.replace("/", " ")
    if sspace not in seen:
        candidates.append(sspace); seen.add(sspace)
    lowwhole = banner.lower()
    if lowwhole not in seen:
        candidates.append(lowwhole); seen.add(lowwhole)

    # 4) tokenise and add first token
    tokens = re.split(r'[\s,]+', banner)
    if tokens:
        first = tokens[0].strip()
        if first and first not in seen:
            candidates.append(first); seen.add(first)

    return candidates

# ------------------ Banner grabbing ------------------ #
def grab_banner(ip, port, timeout=TIMEOUT):
    """
    Prefer HTTP GET (reads Server header). If not HTTP or GET fails, do a generic TCP recv.
    Returns banner string or None.
    """
    http_ports = {80, 8080, 8000, 8008}
    # Try HTTP GET first for common HTTP ports
    if port in http_ports:
        try:
            url = f"http://{ip}:{port}/"
            r = requests.get(url, timeout=timeout, headers={"User-Agent": "BannerProbe/1.0"})
            # DEBUG: print response headers
            with print_lock:
                print(f"[DBG] HTTP GET {url} -> status={r.status_code} headers={dict(r.headers)}")
            server_hdr = r.headers.get("Server")
            if server_hdr:
                return server_hdr.strip()
            if r.text:
                for line in r.text.splitlines():
                    s = line.strip()
                    if s:
                        return s
        except Exception as e:
            with print_lock:
                print(f"[DBG] HTTP GET failed for {ip}:{port} -> {e}")

    # Generic TCP banner grab fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b"\r\n")
        except Exception:
            pass
        try:
            data = s.recv(4096)
            if data:
                dec = data.decode(errors="ignore").strip()
                with print_lock:
                    print(f"[DBG] TCP recv {ip}:{port} -> {dec!r}")
                return dec
        except Exception as e:
            with print_lock:
                print(f"[DBG] TCP recv failed for {ip}:{port} -> {e}")
        finally:
            s.close()
    except Exception as e:
        with print_lock:
            print(f"[DBG] TCP connect failed for {ip}:{port} -> {e}")
    return None

# ------------------ /vulncheck probe (safe) ------------------ #
def probe_vuln_endpoint(ip, port, timeout=2):
    try:
        url = f"http://{ip}:{port}/vulncheck"
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "VulnProbe/1.0"})
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            try:
                data = r.json()
                if isinstance(data, dict) and data.get("test_cve"):
                    return data
            except Exception:
                return None
    except Exception:
        pass
    return None

# ------------------ CVE API helpers ------------------ #
def query_nvd(keyword, max_results=5, api_key=None):
    if not keyword:
        return []
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    headers = {"apiKey": api_key} if api_key else {}
    try:
        with print_lock:
            print(f"[DEBUG] NVD query -> url={NVD_URL} params={params} api_key_present={bool(api_key)}")
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=15)
        with print_lock:
            print(f"[DEBUG] NVD response -> status={r.status_code} url={r.url}")
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities") or []
            out = []
            for v in vulns[:max_results]:
                cve = v.get("cve", {}) or {}
                cve_id = cve.get("id") or cve.get("CVE_data_meta", {}).get("ID")
                desc = ""
                descs = cve.get("descriptions") or []
                if isinstance(descs, list) and descs:
                    for d in descs:
                        val = d.get("value") or ""
                        if val:
                            desc = val
                            break
                if cve_id:
                    out.append({"id": cve_id, "description": desc})
            return out
    except Exception as e:
        with print_lock:
            print(f"[DEBUG] NVD query error: {e}")
    return []


def query_circl(keyword, max_results=5):
    if not keyword:
        return []
    try:
        url = CIRCL_URL + quote_plus(keyword)
        with print_lock:
            print(f"[DEBUG] CIRCL query -> url={url}")
        r = requests.get(url, timeout=10)
        with print_lock:
            print(f"[DEBUG] CIRCL response -> status={r.status_code} url={r.url}")
        if r.status_code == 200:
            data = r.json() or []
            with print_lock:
                print(f"[DEBUG] CIRCL returned {len(data)} results (preview).")
            out = []
            for it in data[:max_results]:
                out.append({"id": it.get("id"), "description": it.get("summary") or ""})
            return out
    except Exception as e:
        with print_lock:
            print(f"[DEBUG] CIRCL query error: {e}")
    return []


def find_cves(keyword, max_results=5, debug=False):
    if debug:
        with print_lock:
            print(f"DEBUG: Searching CVE APIs for keyword: '{keyword}'")
    api_key = os.getenv("NVD_API_KEY")
    results = []
    if api_key:
        results = query_nvd(keyword, max_results=max_results, api_key=api_key)
        if results:
            return results
        time.sleep(1.0)
    results = query_nvd(keyword, max_results=max_results, api_key=None)
    if results:
        return results
    return query_circl(keyword, max_results=max_results)

# ------------------ Scanner worker ------------------ #
def scan_port(ip, port, open_ports, lock, debug=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        rc = sock.connect_ex((ip, port))
        if rc == 0:
            banner = grab_banner(ip, port)
            with lock:
                open_ports.append((port, banner))
            with print_lock:
                if banner:
                    print(f"[+] Port {port} OPEN — {banner}")
                else:
                    print(f"[+] Port {port} OPEN — No banner")
        sock.close()
    except Exception:
        pass


def worker(ip, q, open_ports, lock, debug=False):
    while True:
        try:
            port = q.get_nowait()
        except Empty:
            break
        try:
            scan_port(ip, port, open_ports, lock, debug=debug)
        finally:
            q.task_done()


def threaded_scan(ip, start, end, threads=THREADS, debug=False):
    q = Queue()
    open_ports = []
    lock = threading.Lock()
    for p in range(start, end + 1):
        q.put(p)
    thread_list = []
    count = min(threads, (end - start + 1))
    for _ in range(count):
        t = threading.Thread(target=worker, args=(ip, q, open_ports, lock, debug))
        t.daemon = True
        t.start()
        thread_list.append(t)
    q.join()
    return sorted(open_ports, key=lambda x: x[0])

# ------------------ Main ------------------ #
def main():
    print("Simple vuln-aware scanner (NVD + CIRCL).")
    target = input("Enter IP to scan (or hostname): ").strip()
    start = int(input("Start port (default 1): ").strip() or 1)
    end = int(input("End port (default 1024): ").strip() or 1024)
    debug_mode = input("Enable debug API query prints? (y/N): ").strip().lower() == "y"

    print(f"\n[*] Scanning {target}:{start}-{end} ...\n")
    found = threaded_scan(target, start, end, threads=THREADS, debug=debug_mode)

    print("\nScan complete. Inspecting services and querying CVE databases...\n")

    for port, banner in found:
        if banner:
            # try vulncheck endpoint first (if HTTP)
            probe = probe_vuln_endpoint(target, port)
            if probe and probe.get("test_cve"):
                print(f"[!] {target}:{port} reports test CVE: {probe.get('test_cve')} - {probe.get('description')}")
                continue

            # use extractor to create better keyword variants
            variants_clean = extract_keywords_from_banner(banner)
            if debug_mode:
                print(f"[DBG] Extracted keyword candidates: {variants_clean}")

            found_any = False
            for kw in variants_clean:
                cves = find_cves(kw, debug=debug_mode)
                if cves:
                    found_any = True
                    print(f"[*] CVEs for '{kw}' on {target}:{port}:")
                    for c in cves:
                        print(f"    - {c.get('id')}: {c.get('description')[:300]}")
                    break
                time.sleep(0.6)
            if not found_any:
                print(f"[*] No CVEs found for {target}:{port} (tried {len(variants_clean)} variants).")
        else:
            print(f"[*] {target}:{port} had no banner; skipping CVE lookup.")

    print("\nDone.")

if __name__ == "__main__":
    main()
