#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  PHANTOM SCAN v5.0 — Advanced Network Security Suite                        ║
║  Port Scanner + Vulnerability Assessment + SYN Stealth + Brute Force +      ║
║  Topology Map + Scheduler + NVD CVE Auto-Update + Shodan API + PDF Export   ║
║  Python 3.8+  |  Core: Zero pip dependencies  |  Optional: reportlab,       ║
║               |  paramiko  (install only for PDF/SSH brute-force)            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import socket, threading, queue, time, json, csv, ipaddress
import subprocess, platform, re, struct, ftplib, urllib.request
import urllib.parse, urllib.error, math, os, sys, random, hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl

# ── Optional: PDF (pip install reportlab) ──────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle,
        Paragraph, Spacer, HRFlowable)
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# ── Optional: SSH Brute-Force (pip install paramiko) ───────────────────────
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ─── Color Palette ─────────────────────────────────────────────────────────
BG_DARK     = "#0a0e14"
BG_PANEL    = "#0d1117"
BG_CARD     = "#161b22"
BG_HOVER    = "#1c2333"
ACCENT_CYAN = "#00d4ff"
ACCENT_GRN  = "#39ff14"
ACCENT_RED  = "#ff3860"
ACCENT_YLW  = "#ffd700"
ACCENT_PRP  = "#b388ff"
ACCENT_ORG  = "#ff8c42"
TEXT_PRI    = "#e6edf3"
TEXT_SEC    = "#8b949e"
TEXT_DIM    = "#484f58"
BORDER      = "#21262d"

# ─── Service Dictionary ─────────────────────────────────────────────────────
COMMON_SERVICES = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",80:"HTTP",110:"POP3",111:"RPC",135:"MSRPC",
    139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",
    995:"POP3S",1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",
    1521:"Oracle",1723:"PPTP",2049:"NFS",2082:"cPanel",
    2083:"cPanel-SSL",2086:"WHM",2087:"WHM-SSL",2181:"Zookeeper",
    2375:"Docker",2376:"Docker-TLS",3000:"Dev-Server",
    3306:"MySQL",3389:"RDP",3690:"SVN",4444:"Metasploit",
    4848:"GlassFish",5000:"Flask/UPnP",5432:"PostgreSQL",
    5900:"VNC",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",
    6379:"Redis",6667:"IRC",7001:"WebLogic",7547:"TR-069",
    8000:"HTTP-Alt",8008:"HTTP-Alt",8080:"HTTP-Proxy",
    8443:"HTTPS-Alt",8888:"Jupyter",9000:"SonarQube",
    9090:"Prometheus",9200:"Elasticsearch",9300:"Elasticsearch",
    11211:"Memcached",27017:"MongoDB",50000:"SAP",50070:"Hadoop"
}

# ─── Vulnerability Database ─────────────────────────────────────────────────
VULN_DB = {
    "ftp":{
        "vsftpd 2.3.4":{"cve":"CVE-2011-2523","cvss":10.0,"severity":"CRITICAL",
            "description":"Backdoor command execution - allows remote root access",
            "exploit_available":True,"remediation":"Upgrade to vsftpd 2.3.5+ immediately"},
        "vsftpd 2.0.5":{"cve":"CVE-2007-5962","cvss":5.8,"severity":"MEDIUM",
            "description":"Denial of service vulnerability","exploit_available":False,
            "remediation":"Upgrade to latest version"},
        "proftpd 1.3.5":{"cve":"CVE-2015-3306","cvss":7.5,"severity":"HIGH",
            "description":"Mod_copy arbitrary file copy leading to RCE","exploit_available":True,
            "remediation":"Upgrade to ProFTPD 1.3.6+"},
        "pure-ftpd":{"cve":"CVE-2020-9365","cvss":6.1,"severity":"MEDIUM",
            "description":"Directory traversal vulnerability","exploit_available":False,
            "remediation":"Upgrade to Pure-FTPd 1.0.49+"}
    },
    "ssh":{
        "openssh 7.2p2":{"cve":"CVE-2016-6210","cvss":7.8,"severity":"HIGH",
            "description":"User enumeration allows attackers to find valid users",
            "exploit_available":True,"remediation":"Upgrade to OpenSSH 7.3+"},
        "openssh 4.3p2":{"cve":"CVE-2006-5051","cvss":9.8,"severity":"CRITICAL",
            "description":"Signal handler race condition leading to RCE","exploit_available":True,
            "remediation":"Upgrade to OpenSSH 4.4+"},
        "openssh 5.9":{"cve":"CVE-2012-0814","cvss":5.0,"severity":"MEDIUM",
            "description":"SSH protocol weakness","exploit_available":False,
            "remediation":"Upgrade to OpenSSH 6.0+"}
    },
    "http":{
        "apache 2.4.49":{"cve":"CVE-2021-41773","cvss":9.8,"severity":"CRITICAL",
            "description":"Path traversal and RCE in Apache HTTP Server","exploit_available":True,
            "remediation":"Upgrade to Apache 2.4.50+"},
        "apache 2.4.50":{"cve":"CVE-2021-42013","cvss":9.8,"severity":"CRITICAL",
            "description":"Improved path traversal allowing RCE","exploit_available":True,
            "remediation":"Upgrade to Apache 2.4.51+"},
        "nginx 1.14.0":{"cve":"CVE-2019-20372","cvss":5.3,"severity":"MEDIUM",
            "description":"HTTP request smuggling vulnerability","exploit_available":False,
            "remediation":"Upgrade to nginx 1.16.0+"},
        "nginx 1.17.5":{"cve":"CVE-2019-20372","cvss":5.3,"severity":"MEDIUM",
            "description":"HTTP request smuggling vulnerability","exploit_available":False,
            "remediation":"Upgrade to nginx 1.18.0+"}
    },
    "smb":{
        "samba 3.0.0":{"cve":"CVE-2017-7494","cvss":9.8,"severity":"CRITICAL",
            "description":"SambaCry - remote code execution vulnerability","exploit_available":True,
            "remediation":"Upgrade to Samba 4.6.4+"},
        "microsoft-ds":{"cve":"CVE-2017-0144","cvss":8.8,"severity":"HIGH",
            "description":"EternalBlue - SMBv1 remote code execution","exploit_available":True,
            "remediation":"Disable SMBv1 and apply MS17-010 patch"}
    },
    "mysql":{"mysql 5.7.20":{"cve":"CVE-2017-15365","cvss":7.5,"severity":"HIGH",
            "description":"Denial of service vulnerability","exploit_available":False,
            "remediation":"Upgrade to MySQL 5.7.21+"}},
    "rdp":{"microsoft rdp":{"cve":"CVE-2019-0708","cvss":9.8,"severity":"CRITICAL",
            "description":"BlueKeep - RCE without authentication","exploit_available":True,
            "remediation":"Apply security patch and enable NLA"}}
}

SERVICE_TO_DB_KEY = {
    21:"ftp",22:"ssh",23:"telnet",80:"http",443:"http",
    8080:"http",8443:"http",445:"smb",139:"smb",
    3306:"mysql",5432:"postgresql",1433:"mssql",
    3389:"rdp",5900:"vnc",6379:"redis"
}

# ══════════════════════════════════════════════════════════════════════════════
#  ①  SYN STEALTH SCAN  (Linux + root only)
# ══════════════════════════════════════════════════════════════════════════════
def _tcp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF

def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build a raw IP+TCP SYN packet."""
    # ── IP Header ──────────────────────────────────────────────────────────
    ip_ver_ihl = (4 << 4) | 5
    ip_tos     = 0
    ip_tot_len = 0               # Kernel fills
    ip_id      = random.randint(1000, 65535)
    ip_frag    = 0
    ip_ttl     = 64
    ip_proto   = socket.IPPROTO_TCP
    ip_check   = 0               # Kernel fills
    ip_src     = socket.inet_aton(src_ip)
    ip_dst     = socket.inet_aton(dst_ip)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_tot_len, ip_id, ip_frag,
        ip_ttl, ip_proto, ip_check, ip_src, ip_dst)
    # ── TCP Header ─────────────────────────────────────────────────────────
    seq      = random.randint(0, 2**32 - 1)
    tcp_hdr  = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), 0x02,          # data-offset=5, SYN flag
        socket.htons(5840), 0, 0)
    # ── Pseudo header for TCP checksum ─────────────────────────────────────
    pseudo   = struct.pack("!4s4sBBH", ip_src, ip_dst, 0,
        socket.IPPROTO_TCP, len(tcp_hdr))
    tcp_cksum = _tcp_checksum(pseudo + tcp_hdr)
    tcp_hdr  = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, 0,
        (5 << 4), 0x02, socket.htons(5840), tcp_cksum, 0)
    return ip_hdr + tcp_hdr

def syn_scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    SYN stealth scan: sends SYN, checks SYN-ACK/RST without completing handshake.
    Requires root on Linux.  Returns same dict shape as scan_port().
    """
    base = {"port":port,"service":COMMON_SERVICES.get(port,""),"banner":"","latency":"","vulnerabilities":[]}
    if platform.system() != "Linux":
        return {**base, "state":"SKIP", "banner":"SYN scan: Linux only"}
    try:
        ip = socket.gethostbyname(host)
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.connect((ip, 80)); src_ip = tmp.getsockname()[0]; tmp.close()
        src_port = random.randint(49152, 65535)
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.settimeout(timeout)
        pkt = _build_syn_packet(src_ip, ip, src_port, port)
        t0  = time.time()
        raw.sendto(pkt, (ip, 0))
        deadline = t0 + timeout
        while time.time() < deadline:
            try:
                resp = raw.recv(1024)
                lat  = round((time.time() - t0) * 1000, 2)
                if len(resp) < 40: continue
                tcp  = struct.unpack("!HHLLBBHHH", resp[20:40])
                r_sp, r_dp, _, _, _, flags = tcp[0], tcp[1], tcp[2], tcp[3], tcp[4], tcp[5]
                if r_sp == port and r_dp == src_port:
                    raw.close()
                    if flags & 0x12:   # SYN-ACK
                        return {**base,"state":"OPEN","latency":lat,"banner":"SYN-ACK (stealth)"}
                    elif flags & 0x04: # RST
                        return {**base,"state":"CLOSED","latency":lat}
            except socket.timeout:
                break
        raw.close()
        return {**base,"state":"FILTERED","banner":"No response"}
    except PermissionError:
        return {**base,"state":"ERROR","banner":"Requires root: sudo python3 phantom_scan.py"}
    except Exception as exc:
        return {**base,"state":"ERROR","banner":str(exc)[:60]}

# ══════════════════════════════════════════════════════════════════════════════
#  ②  NVD CVE AUTO-UPDATE
# ══════════════════════════════════════════════════════════════════════════════
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_cves(keyword: str, api_key: str = "", max_results: int = 20) -> list:
    """
    Query NVD CVE API v2.0 for a keyword.
    Returns list of dicts with cve, cvss, description, etc.
    No API key needed; key only increases rate limit.
    """
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    url    = NVD_API_BASE + "?" + urllib.parse.urlencode(params)
    headers = {"apiKey": api_key} if api_key else {}
    try:
        req  = urllib.request.Request(url, headers={**headers, "User-Agent":"PhantomScan/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        results = []
        for item in data.get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id  = cve_obj.get("id", "")
            descs   = cve_obj.get("descriptions", [])
            desc    = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve_obj.get("metrics", {})
            cvss    = 0.0; severity = "UNKNOWN"
            for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    cvss     = m.get("baseScore", 0.0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break
            results.append({"cve":cve_id,"cvss":cvss,"severity":severity,
                             "description":desc[:200],"exploit_available":False,
                             "remediation":"Check NVD for patch details"})
        return results
    except Exception as exc:
        return [{"error": str(exc)}]

def update_vuln_db_from_nvd(keywords: list, api_key: str, callback) -> None:
    """
    Background thread: fetch CVEs for each keyword, merge into VULN_DB.
    callback(msg, level) is called for progress updates.
    """
    for kw in keywords:
        callback(f"NVD: Fetching CVEs for '{kw}'...", "info")
        results = fetch_nvd_cves(kw, api_key, max_results=10)
        if results and "error" in results[0]:
            callback(f"NVD Error: {results[0]['error']}", "error")
            continue
        db_key = kw.lower().replace(" ", "_")
        if db_key not in VULN_DB:
            VULN_DB[db_key] = {}
        added = 0
        for r in results:
            cve = r.get("cve","")
            if cve and cve not in str(VULN_DB[db_key]):
                VULN_DB[db_key][cve] = r
                added += 1
        callback(f"NVD: Added {added} new CVEs for '{kw}'", "ok")
        time.sleep(6)   # NVD free tier: max 5 req/30 s

# ══════════════════════════════════════════════════════════════════════════════
#  ③  SHODAN API INTEGRATION
# ══════════════════════════════════════════════════════════════════════════════
SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}?key={key}"
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search?key={key}&query={q}"

def shodan_host_lookup(ip: str, api_key: str) -> dict:
    """
    Look up an IP address on Shodan.
    Returns parsed host info dict or {'error': msg}.
    Requires free Shodan account API key from shodan.io
    """
    if not api_key.strip():
        return {"error": "No Shodan API key configured. Get a free key at https://shodan.io"}
    url = SHODAN_HOST_URL.format(ip=ip, key=api_key.strip())
    try:
        req  = urllib.request.Request(url, headers={"User-Agent":"PhantomScan/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        return {"error": f"HTTP {e.code}: {body[:100]}"}
    except Exception as exc:
        return {"error": str(exc)}

# ══════════════════════════════════════════════════════════════════════════════
#  ④  SERVICE BRUTE-FORCE MODULE  (For authorised pentesting only)
# ══════════════════════════════════════════════════════════════════════════════
BRUTE_DISCLAIMER = (
    "⚠️  AUTHORISED TESTING ONLY\n\n"
    "This module is for authorised penetration testing on systems you own "
    "or have explicit written permission to test. Unauthorised use is illegal."
)

DEFAULT_USERNAMES = ["admin","root","administrator","user","test","guest","ftp","anonymous"]
DEFAULT_PASSWORDS = ["","password","123456","admin","root","test","guest","12345",
                     "password123","admin123","letmein","welcome","changeme","default"]

def brute_ftp(host: str, port: int, username: str, password: str,
              timeout: float = 3.0) -> dict:
    """Test a single FTP credential using stdlib ftplib."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return {"success": True, "username": username, "password": password}
    except ftplib.error_perm:
        return {"success": False}
    except Exception as exc:
        return {"success": False, "error": str(exc)[:40]}

def brute_ssh(host: str, port: int, username: str, password: str,
              timeout: float = 3.0) -> dict:
    """Test a single SSH credential using paramiko (if available)."""
    if not PARAMIKO_AVAILABLE:
        return {"success": False, "error": "paramiko not installed (pip install paramiko)"}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, allow_agent=False, look_for_keys=False)
        client.close()
        return {"success": True, "username": username, "password": password}
    except paramiko.AuthenticationException:
        return {"success": False}
    except Exception as exc:
        return {"success": False, "error": str(exc)[:40]}

def brute_http_basic(host: str, port: int, username: str, password: str,
                     path: str = "/", timeout: float = 3.0) -> dict:
    """Test HTTP Basic Auth credentials using stdlib urllib."""
    try:
        import base64
        scheme = "https" if port in (443, 8443) else "http"
        url    = f"{scheme}://{host}:{port}{path}"
        creds  = base64.b64encode(f"{username}:{password}".encode()).decode()
        req    = urllib.request.Request(url, headers={
            "Authorization": f"Basic {creds}",
            "User-Agent": "PhantomScan/5.0"})
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            if resp.status in (200, 301, 302):
                return {"success": True, "username": username, "password": password}
    except urllib.error.HTTPError as e:
        if e.code != 401:
            return {"success": True, "username": username, "password": password}
    except Exception:
        pass
    return {"success": False}

# ══════════════════════════════════════════════════════════════════════════════
#  EXISTING CORE FUNCTIONS  (preserved from v4)
# ══════════════════════════════════════════════════════════════════════════════
def grab_banner(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout); s.connect((host, port))
        probes = {
            21: b"USER anonymous\r\nSYST\r\nQUIT\r\n",
            22: b"SSH-2.0-PhantomScanner\r\n",
            25: b"EHLO phantom.scanner\r\nQUIT\r\n",
            80: f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: PhantomScanner\r\n\r\n".encode(),
            110: b"USER test\r\nQUIT\r\n",
            143: b"A001 CAPABILITY\r\n",
            6379: b"INFO\r\n",
        }
        if port in probes: s.send(probes[port]); time.sleep(0.2)
        banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
        s.close()
        banner = banner.replace('\n','\\n').replace('\r','').replace('\x00','')
        for svc, pat in [("SSH",r"SSH-([0-9.]+)"),("APACHE",r"Apache/([0-9.]+)"),
                         ("NGINX",r"nginx/([0-9.]+)"),("VSFTPD",r"vsFTPd ([0-9.]+)"),
                         ("PROFTPD",r"ProFTPD ([0-9.]+)"),("OPENSSH",r"OpenSSH[_]([0-9.]+)")]:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                banner = f"{svc} {m.group(1)} | {banner[:80]}"; break
        return banner[:150]
    except:
        return ""

def grab_https_banner(host, port, timeout=2):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s  = socket.create_connection((host, port), timeout=timeout)
        ss = ctx.wrap_socket(s, server_hostname=host)
        cert = ss.getpeercert()
        cn = ""
        if cert:
            subj = dict(x[0] for x in cert.get("subject",[]))
            cn = subj.get("commonName","")
        ss.close()
        return f"SSL/TLS | CN={cn}" if cn else "SSL/TLS"
    except:
        return ""

def detect_vulnerabilities(port, service_name, banner):
    db_key = SERVICE_TO_DB_KEY.get(port)
    if not db_key or db_key not in VULN_DB:
        return []
    vulns = []
    bl, sl = banner.lower(), service_name.lower()
    for ver, data in VULN_DB[db_key].items():
        if ver.lower() in bl or ver.lower() in sl or sl in ver.lower():
            vulns.append({"version":ver,"cve":data["cve"],"cvss":data["cvss"],
                "severity":data["severity"],"description":data["description"],
                "exploit_available":data["exploit_available"],"remediation":data["remediation"]})
    return list({v["cve"]:v for v in vulns}.values())

def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        try: hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = host
        return ip, hostname
    except:
        return None, None

def parse_target(target):
    target = target.strip()
    if '/' in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()][:100]
        except: pass
    return [target]

def detect_os_hint(ip):
    try:
        cmd = (["ping","-c","1","-W","1",ip] if platform.system()!="Windows"
               else ["ping","-n","1","-w","1000",ip])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        m = re.search(r'ttl[=\s](\d+)', r.stdout.lower())
        if m:
            ttl = int(m.group(1))
            if ttl<=64:  return "Linux / Unix / macOS"
            if ttl<=128: return "Windows"
            return "Network Device / Cisco"
        return "Unknown"
    except:
        return "Unknown"

def scan_port(host, port, timeout=1.0, grab=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        rc = s.connect_ex((host, port))
        lat = round((time.time()-t0)*1000, 2)
        s.close()
        if rc == 0:
            svc   = COMMON_SERVICES.get(port,"Unknown")
            bnr   = ""
            vulns = []
            if grab:
                bnr   = grab_https_banner(host,port) if port==443 else grab_banner(host,port)
                if bnr: vulns = detect_vulnerabilities(port, svc, bnr)
            return {"port":port,"state":"OPEN","service":svc,"banner":bnr,"latency":lat,"vulnerabilities":vulns}
    except: pass
    return {"port":port,"state":"CLOSED","service":"","banner":"","latency":"","vulnerabilities":[]}

def scan_udp_port(host, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        t0 = time.time()
        s.sendto(b'\x00', (host, port))
        try:
            data, _ = s.recvfrom(1024)
            lat = round((time.time()-t0)*1000,2); s.close()
            return {"port":port,"state":"OPEN","service":COMMON_SERVICES.get(port,""),"banner":f"UDP ({len(data)}B)","latency":lat,"vulnerabilities":[]}
        except socket.timeout:
            s.close()
            return {"port":port,"state":"OPEN|FILTERED","service":COMMON_SERVICES.get(port,""),"banner":"UDP (no resp)","latency":"","vulnerabilities":[]}
    except:
        return {"port":port,"state":"CLOSED","service":"","banner":"","latency":"","vulnerabilities":[]}


# ══════════════════════════════════════════════════════════════════════════════
#  ⑤  NETWORK TOPOLOGY MAP  (tkinter Canvas — no external deps)
# ══════════════════════════════════════════════════════════════════════════════
class TopologyMap:
    """Draws a radial network topology on a tkinter Canvas."""
    NODE_R   = 28
    CENTER_R = 40
    RING1_R  = 160
    RING2_R  = 280

    SEV_COLORS = {
        "CRITICAL": ACCENT_RED,
        "HIGH":     ACCENT_ORG,
        "MEDIUM":   ACCENT_YLW,
        "OPEN":     ACCENT_GRN,
        "FILTERED": ACCENT_PRP,
        "UDP":      "#00bfff",
        "DEFAULT":  TEXT_SEC,
    }

    def __init__(self, parent):
        self.parent    = parent
        self.canvas    = tk.Canvas(parent, bg=BG_DARK, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self._nodes    = {}   # port -> (x,y,oval_id,text_id)
        self._tip_win  = None
        self._cx = 400; self._cy = 300
        # Zoom / pan
        self.canvas.bind("<MouseWheel>",       self._on_zoom)
        self.canvas.bind("<Button-4>",         self._on_zoom)
        self.canvas.bind("<Button-5>",         self._on_zoom)
        self.canvas.bind("<ButtonPress-2>",    self._pan_start)
        self.canvas.bind("<B2-Motion>",        self._pan_move)
        self.canvas.bind("<ButtonPress-3>",    self._pan_start)
        self.canvas.bind("<B3-Motion>",        self._pan_move)
        self._scale    = 1.0
        self._ox = 0; self._oy = 0
        self._drag_x = 0; self._drag_y = 0
        # Legend
        self._draw_legend()

    def _draw_legend(self):
        lg = [("CRITICAL/HIGH",ACCENT_RED),("MEDIUM",ACCENT_YLW),
              ("OPEN",ACCENT_GRN),("FILTERED",ACCENT_PRP),("UDP","#00bfff")]
        x, y = 12, 12
        for label, col in lg:
            self.canvas.create_oval(x,y,x+10,y+10, fill=col, outline=col)
            self.canvas.create_text(x+16,y+5, text=label, anchor="w",
                fill=TEXT_SEC, font=("Courier New",8))
            x += 100

    def clear(self):
        self.canvas.delete("node","edge","label","center")
        self._nodes = {}

    def draw(self, results: list, target_ip: str):
        self.clear()
        self.canvas.update()
        W = self.canvas.winfo_width()  or 800
        H = self.canvas.winfo_height() or 600
        cx, cy = W // 2, H // 2
        self._cx, self._cy = cx, cy

        # ── Center node (target host) ──────────────────────────────────────
        r = self.CENTER_R
        self.canvas.create_oval(cx-r, cy-r, cx+r, cy+r,
            fill=ACCENT_CYAN, outline="#ffffff", width=2, tags="center")
        self.canvas.create_text(cx, cy, text=target_ip or "TARGET",
            fill=BG_DARK, font=("Courier New",9,"bold"), tags="center")

        open_ports = [res for res in results if res.get("state") in ("OPEN","OPEN|FILTERED")]
        if not open_ports:
            self.canvas.create_text(cx, cy+r+20, text="No open ports found",
                fill=TEXT_SEC, font=("Courier New",10), tags="label")
            return

        # ── Arrange ports in rings ─────────────────────────────────────────
        n    = len(open_ports)
        ring1 = open_ports[:min(n, 12)]
        ring2 = open_ports[12:min(n, 32)]

        def place_ring(ports, radius):
            step = 2 * math.pi / max(len(ports), 1)
            for i, res in enumerate(ports):
                angle = i * step - math.pi / 2
                nx = cx + int(radius * math.cos(angle))
                ny = cy + int(radius * math.sin(angle))
                self._draw_node(res, nx, ny, cx, cy)

        place_ring(ring1, self.RING1_R)
        if ring2:
            place_ring(ring2, self.RING2_R)
        if n > 32:
            self.canvas.create_text(cx, cy+self.RING2_R+20,
                text=f"+{n-32} more ports (zoom out or filter)",
                fill=TEXT_DIM, font=("Courier New",9), tags="label")

    def _node_color(self, res):
        vulns = res.get("vulnerabilities",[])
        if vulns:
            sevs = [v.get("severity","") for v in vulns]
            if "CRITICAL" in sevs: return self.SEV_COLORS["CRITICAL"]
            if "HIGH"     in sevs: return self.SEV_COLORS["HIGH"]
            return self.SEV_COLORS["MEDIUM"]
        st = res.get("state","")
        if "FILTERED" in st: return self.SEV_COLORS["FILTERED"]
        if "UDP" in str(res.get("banner","")): return self.SEV_COLORS["UDP"]
        return self.SEV_COLORS["OPEN"]

    def _draw_node(self, res, nx, ny, cx, cy):
        port  = res.get("port","")
        svc   = res.get("service","")[:8]
        color = self._node_color(res)
        r     = self.NODE_R
        # Edge
        eid = self.canvas.create_line(cx, cy, nx, ny,
            fill=color, width=1, tags="edge", dash=(4,4))
        # Circle
        oid = self.canvas.create_oval(nx-r, ny-r, nx+r, ny+r,
            fill=BG_CARD, outline=color, width=2, tags="node")
        # Port text
        tid = self.canvas.create_text(nx, ny-6, text=str(port),
            fill=color, font=("Courier New",9,"bold"), tags="label")
        self.canvas.create_text(nx, ny+8, text=svc,
            fill=TEXT_DIM, font=("Courier New",7), tags="label")
        # Hover / click
        for iid in (oid, tid):
            self.canvas.tag_bind(iid, "<Enter>",
                lambda e, r=res: self._tooltip_show(e, r))
            self.canvas.tag_bind(iid, "<Leave>",  self._tooltip_hide)
            self.canvas.tag_bind(iid, "<Button-1>",
                lambda e, r=res: self._node_click(r))
        self._nodes[port] = (nx, ny, oid, tid)

    def _tooltip_show(self, event, res):
        self._tooltip_hide(None)
        port  = res.get("port",""); svc = res.get("service","")
        bnr   = res.get("banner","")[:50]
        vulns = res.get("vulnerabilities",[])
        lines = [f"Port {port} / {svc}", f"Banner: {bnr}" if bnr else ""]
        for v in vulns[:2]:
            lines.append(f"⚠ {v['cve']} ({v['severity']})")
        tip = tk.Toplevel(self.canvas)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{event.x_root+12}+{event.y_root+12}")
        tk.Label(tip, text="\n".join(l for l in lines if l),
            bg="#1c2333", fg=ACCENT_CYAN, font=("Courier New",9),
            justify="left", padx=8, pady=4).pack()
        self._tip_win = tip

    def _tooltip_hide(self, event):
        if self._tip_win:
            try: self._tip_win.destroy()
            except: pass
            self._tip_win = None

    def _node_click(self, res):
        port  = res.get("port",""); svc = res.get("service","")
        vulns = res.get("vulnerabilities",[])
        if vulns:
            msg = f"Port {port} — {svc}\n" + "─"*40 + "\n"
            for v in vulns:
                msg += (f"\nCVE: {v['cve']}  CVSS: {v['cvss']}  [{v['severity']}]\n"
                        f"  {v['description']}\n"
                        f"  Exploit: {'YES' if v['exploit_available'] else 'NO'}\n"
                        f"  Fix: {v['remediation']}\n")
            messagebox.showwarning(f"Vulnerability — Port {port}", msg)
        else:
            messagebox.showinfo(f"Port {port}", f"Service: {svc}\nState: {res.get('state','')}\n"
                f"Banner: {res.get('banner','N/A')}\nLatency: {res.get('latency','')} ms")

    def _on_zoom(self, event):
        delta = getattr(event, "delta", 0)
        if event.num == 4 or delta > 0: factor = 1.1
        else: factor = 0.9
        self.canvas.scale("all", self._cx, self._cy, factor, factor)
        self._scale *= factor

    def _pan_start(self, event):
        self._drag_x = event.x; self._drag_y = event.y

    def _pan_move(self, event):
        dx = event.x - self._drag_x; dy = event.y - self._drag_y
        self.canvas.move("all", dx, dy)
        self._drag_x = event.x; self._drag_y = event.y

# ══════════════════════════════════════════════════════════════════════════════
#  ⑥  SCHEDULER
# ══════════════════════════════════════════════════════════════════════════════
class SchedulerManager:
    """Manages recurring scan schedules using threading.Timer."""
    def __init__(self, scan_callback):
        self.scan_callback = scan_callback
        self.schedules     = []   # list of dicts
        self._timers       = {}   # id -> Timer
        self._lock         = threading.Lock()
        self._id_counter   = 0

    def add(self, name, target, port_from, port_to, interval_hours, enabled=True):
        with self._lock:
            self._id_counter += 1
            entry = {
                "id":           self._id_counter,
                "name":         name,
                "target":       target,
                "port_from":    port_from,
                "port_to":      port_to,
                "interval_hrs": interval_hours,
                "enabled":      enabled,
                "last_run":     None,
                "next_run":     datetime.now() + timedelta(hours=interval_hours),
                "run_count":    0,
            }
            self.schedules.append(entry)
            if enabled:
                self._arm(entry)
            return entry

    def remove(self, sid):
        with self._lock:
            self._cancel(sid)
            self.schedules = [s for s in self.schedules if s["id"] != sid]

    def toggle(self, sid):
        with self._lock:
            for s in self.schedules:
                if s["id"] == sid:
                    s["enabled"] = not s["enabled"]
                    if s["enabled"]: self._arm(s)
                    else:            self._cancel(sid)
                    return s["enabled"]
        return False

    def _arm(self, entry):
        delay = max(0.0, (entry["next_run"] - datetime.now()).total_seconds())
        t = threading.Timer(delay, self._fire, args=(entry["id"],))
        t.daemon = True
        t.start()
        self._timers[entry["id"]] = t

    def _cancel(self, sid):
        if sid in self._timers:
            self._timers[sid].cancel()
            del self._timers[sid]

    def _fire(self, sid):
        with self._lock:
            entry = next((s for s in self.schedules if s["id"]==sid), None)
            if entry is None or not entry["enabled"]: return
            entry["last_run"]  = datetime.now()
            entry["run_count"] += 1
            entry["next_run"]  = datetime.now() + timedelta(hours=entry["interval_hrs"])
        self.scan_callback(entry)
        with self._lock:
            if entry["enabled"]: self._arm(entry)

    def stop_all(self):
        with self._lock:
            for t in self._timers.values():
                t.cancel()
            self._timers.clear()

# ══════════════════════════════════════════════════════════════════════════════
#  ③  PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
def generate_pdf_report(results: list, target: str, filepath: str) -> tuple:
    """
    Generate a professional PDF report using reportlab.
    Falls back to HTML if reportlab is not installed.
    Returns (True, filepath) or (False, error_message).
    """
    if not PDF_AVAILABLE:
        # HTML fallback
        html_path = filepath.replace(".pdf", ".html")
        try:
            _generate_html_report(results, target, html_path)
            return True, html_path + " (HTML fallback — install reportlab for PDF)"
        except Exception as exc:
            return False, str(exc)

    try:
        doc = SimpleDocTemplate(filepath, pagesize=A4,
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle("PhTitle", parent=styles["Heading1"],
            textColor=rl_colors.HexColor("#00d4ff"), fontSize=18,
            spaceAfter=6, fontName="Courier-Bold")
        h2_style = ParagraphStyle("PhH2", parent=styles["Heading2"],
            textColor=rl_colors.HexColor("#e6edf3"), fontSize=12,
            spaceAfter=4, fontName="Courier-Bold")
        body_style = ParagraphStyle("PhBody", parent=styles["Normal"],
            textColor=rl_colors.HexColor("#8b949e"), fontSize=9,
            fontName="Courier")
        crit_style = ParagraphStyle("PhCrit", parent=styles["Normal"],
            textColor=rl_colors.HexColor("#ff3860"), fontSize=9,
            fontName="Courier-Bold")
        ok_style = ParagraphStyle("PhOk", parent=styles["Normal"],
            textColor=rl_colors.HexColor("#39ff14"), fontSize=9,
            fontName="Courier")

        story = []
        # Title block
        story.append(Paragraph("◈ PHANTOM SCAN", title_style))
        story.append(Paragraph("Vulnerability Assessment Report", h2_style))
        meta = [["Target", target],
                ["Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ["Open Ports", str(len([r for r in results if r.get("state")=="OPEN"]))],
                ["Vulnerable Services", str(len([r for r in results if r.get("vulnerabilities")]))]]
        mt = Table(meta, colWidths=[4*cm, 12*cm])
        mt.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),rl_colors.HexColor("#0d1117")),
            ("TEXTCOLOR",  (0,0),(0,-1),rl_colors.HexColor("#00d4ff")),
            ("TEXTCOLOR",  (1,0),(1,-1),rl_colors.HexColor("#e6edf3")),
            ("FONTNAME",   (0,0),(-1,-1),"Courier"),
            ("FONTSIZE",   (0,0),(-1,-1),9),
            ("GRID",       (0,0),(-1,-1),0.5,rl_colors.HexColor("#21262d")),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),
             [rl_colors.HexColor("#0d1117"),rl_colors.HexColor("#161b22")]),
        ]))
        story.append(mt); story.append(Spacer(1,12))

        # Vulnerable services
        vulnerable = [r for r in results if r.get("vulnerabilities")]
        if vulnerable:
            story.append(Paragraph("⚠ VULNERABLE SERVICES", h2_style))
            for res in vulnerable:
                story.append(Paragraph(
                    f"Port {res['port']} — {res.get('service','')}  |  {res.get('banner','')[:60]}",
                    crit_style))
                for v in res["vulnerabilities"]:
                    vdata = [
                        [v["cve"], f"CVSS {v['cvss']}", v["severity"],
                         "EXPLOIT ✓" if v["exploit_available"] else "No exploit"],
                        [v["description"][:80], "", "", ""],
                        [f"Fix: {v['remediation'][:80]}", "", "", ""],
                    ]
                    vt = Table(vdata, colWidths=[5*cm, 2.5*cm, 2.5*cm, 3*cm])
                    vt.setStyle(TableStyle([
                        ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#1c2333")),
                        ("BACKGROUND",(0,1),(-1,-1),rl_colors.HexColor("#161b22")),
                        ("TEXTCOLOR", (0,0),(-1,-1),rl_colors.HexColor("#e6edf3")),
                        ("FONTNAME",  (0,0),(-1,-1),"Courier"),
                        ("FONTSIZE",  (0,0),(-1,-1),8),
                        ("SPAN",      (0,1),(3,1)),("SPAN",(0,2),(3,2)),
                        ("GRID",      (0,0),(-1,-1),0.3,rl_colors.HexColor("#21262d")),
                    ]))
                    story.append(vt); story.append(Spacer(1,4))
            story.append(Spacer(1,8))

        # All open ports table
        story.append(Paragraph("ALL OPEN PORTS", h2_style))
        open_ports = [r for r in results if r.get("state") in ("OPEN","OPEN|FILTERED")]
        if open_ports:
            rows = [["PORT","STATE","SERVICE","BANNER","RTT(ms)"]]
            for r in open_ports:
                rows.append([str(r["port"]), r["state"], r.get("service",""),
                              r.get("banner","")[:55], str(r.get("latency",""))])
            t = Table(rows, colWidths=[1.5*cm, 2.5*cm, 3*cm, 8*cm, 2*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#00d4ff")),
                ("TEXTCOLOR", (0,0),(-1,0),rl_colors.HexColor("#0a0e14")),
                ("FONTNAME",  (0,0),(-1,0),"Courier-Bold"),
                ("FONTNAME",  (0,1),(-1,-1),"Courier"),
                ("FONTSIZE",  (0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),
                 [rl_colors.HexColor("#0d1117"),rl_colors.HexColor("#161b22")]),
                ("TEXTCOLOR", (0,1),(-1,-1),rl_colors.HexColor("#e6edf3")),
                ("GRID",      (0,0),(-1,-1),0.3,rl_colors.HexColor("#21262d")),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No open ports found.", body_style))

        doc.build(story)
        return True, filepath
    except Exception as exc:
        return False, str(exc)

def _generate_html_report(results, target, filepath):
    """Fallback HTML report."""
    open_ports = [r for r in results if r.get("state") in ("OPEN","OPEN|FILTERED")]
    vulnerable = [r for r in results if r.get("vulnerabilities")]
    rows = ""
    for r in open_ports:
        vulns = r.get("vulnerabilities",[])
        bg = "#ff386022" if vulns else ""
        v_col = "🔴 " + ",".join(v["cve"] for v in vulns) if vulns else "✓"
        rows += (f"<tr style='background:{bg}'><td>{r['port']}</td><td>{r['state']}</td>"
                 f"<td>{r.get('service','')}</td><td>{r.get('banner','')[:60]}</td>"
                 f"<td>{v_col}</td><td>{r.get('latency','')}</td></tr>\n")
    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Phantom Scan Report — {target}</title>
<style>body{{background:#0a0e14;color:#e6edf3;font-family:Courier New;margin:32px}}
h1{{color:#00d4ff}}h2{{color:#8b949e;font-size:14px}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}
th{{background:#00d4ff;color:#0a0e14;padding:8px;text-align:left}}
td{{border:1px solid #21262d;padding:6px;font-size:12px}}
tr:nth-child(even){{background:#0d1117}}</style></head><body>
<h1>◈ PHANTOM SCAN — Vulnerability Assessment Report</h1>
<h2>Target: {target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
Open: {len(open_ports)} | Vulnerable: {len(vulnerable)}</h2>
<table><tr><th>PORT</th><th>STATE</th><th>SERVICE</th><th>BANNER</th><th>CVEs</th><th>RTT</th></tr>
{rows}</table></body></html>"""
    with open(filepath,"w") as f: f.write(html)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN GUI APPLICATION  v5.0
# ══════════════════════════════════════════════════════════════════════════════
def resource_path(rel):
    try:    return os.path.join(sys._MEIPASS, rel)
    except: return os.path.join(os.path.abspath("."), rel)

class PhantomScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PHANTOM SCAN v5.0  ◈  Network Security Suite")
        self.root.geometry("1340x860")
        self.root.minsize(1100, 720)
        self.root.configure(bg=BG_DARK)

        self.result_queue  = queue.Queue()
        self.is_scanning   = False
        self.scan_thread   = None
        self.results       = []
        self.total_ports   = 0
        self.scanned_ports = 0
        self.current_ip    = ""
        # Brute force state
        self.is_bruteforcing = False
        self.brute_thread    = None
        self.brute_queue     = queue.Queue()
        # API keys (persisted in phantom_config.json)
        self.shodan_key_var = tk.StringVar()
        self.nvd_key_var    = tk.StringVar()
        self._load_config()
        # Scheduler
        self.scheduler = SchedulerManager(self._scheduler_scan_trigger)

        self._setup_fonts()
        self._setup_styles()
        self._build_ui()
        self._start_pollers()
        self._bind_shortcuts()

    # ── Config persistence ─────────────────────────────────────────────────
    def _load_config(self):
        try:
            with open("phantom_config.json") as f:
                cfg = json.load(f)
            self.shodan_key_var.set(cfg.get("shodan_key",""))
            self.nvd_key_var.set(cfg.get("nvd_key",""))
        except: pass

    def _save_config(self):
        cfg = {"shodan_key": self.shodan_key_var.get(),
               "nvd_key":    self.nvd_key_var.get()}
        try:
            with open("phantom_config.json","w") as f: json.dump(cfg, f, indent=2)
        except: pass

    # ── Fonts / Styles ─────────────────────────────────────────────────────
    def _setup_fonts(self):
        self.font_title   = ("Courier New", 20, "bold")
        self.font_mono    = ("Courier New", 10)
        self.font_mono_sm = ("Courier New", 9)
        self.font_label   = ("Courier New", 10, "bold")
        self.font_btn     = ("Courier New", 11, "bold")
        self.font_big     = ("Courier New", 24, "bold")

    def _setup_styles(self):
        s = ttk.Style(); s.theme_use("clam")
        s.configure("Dark.TFrame",  background=BG_DARK)
        s.configure("Card.TFrame",  background=BG_CARD)
        s.configure("Panel.TFrame", background=BG_PANEL)
        s.configure("Treeview", background=BG_CARD, foreground=TEXT_PRI,
            fieldbackground=BG_CARD, borderwidth=0, rowheight=26,
            font=("Courier New",10))
        s.configure("Treeview.Heading", background=BG_PANEL,
            foreground=ACCENT_CYAN, borderwidth=0,
            font=("Courier New",10,"bold"), relief="flat")
        s.map("Treeview", background=[("selected","#1c3a5a")],
            foreground=[("selected",ACCENT_CYAN)])
        s.configure("TProgressbar", troughcolor=BG_CARD,
            background=ACCENT_CYAN, thickness=6)
        s.configure("TScrollbar", background=BG_PANEL, troughcolor=BG_DARK,
            arrowcolor=TEXT_SEC, relief="flat")
        s.configure("TCombobox", background=BG_CARD, foreground=TEXT_PRI,
            fieldbackground=BG_CARD, arrowcolor=ACCENT_CYAN)
        s.map("TCombobox", fieldbackground=[("readonly",BG_CARD)],
            background=[("readonly",BG_CARD)])
        # Notebook tabs
        s.configure("TNotebook", background=BG_DARK, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG_PANEL, foreground=TEXT_SEC,
            font=("Courier New",9,"bold"), padding=[10,5],
            borderwidth=0)
        s.map("TNotebook.Tab",
            background=[("selected",BG_CARD)],
            foreground=[("selected",ACCENT_CYAN)])

    def _bind_shortcuts(self):
        self.root.bind("<Control-s>", lambda e: self._start_scan())
        self.root.bind("<Control-x>", lambda e: self._stop_scan())
        self.root.bind("<Control-c>", lambda e: self._clear_log())
        self.root.bind("<F1>",        lambda e: self._show_help())
        self.root.bind("<Control-q>", lambda e: self.root.quit())

    # ── Build Full UI ──────────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        main = tk.Frame(self.root, bg=BG_DARK)
        main.pack(fill="both", expand=True)
        left = tk.Frame(main, bg=BG_PANEL, width=330)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Frame(main, bg=BORDER, width=1).pack(side="left", fill="y")
        right = tk.Frame(main, bg=BG_DARK)
        right.pack(side="left", fill="both", expand=True)
        self._build_controls(left)
        self._build_right_notebook(right)
        self._build_statusbar()

    # ── Header ─────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG_PANEL, height=60)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Frame(hdr, bg=ACCENT_CYAN, width=4).pack(side="left", fill="y")
        tk.Label(hdr, text="◈ PHANTOM SCAN  v5.0",
            font=self.font_title, bg=BG_PANEL, fg=ACCENT_CYAN
        ).pack(side="left", padx=14, pady=10)
        tk.Label(hdr, text="Network Security Suite | Port Scan + Vuln + BruteForce + Topology + Scheduler + Shodan",
            font=("Courier New",9), bg=BG_PANEL, fg=TEXT_SEC
        ).pack(side="left", padx=4)
        self.time_var = tk.StringVar()
        tk.Label(hdr, textvariable=self.time_var,
            font=self.font_mono_sm, bg=BG_PANEL, fg=TEXT_SEC
        ).pack(side="right", padx=14)
        self._update_clock()
        tk.Frame(self.root, bg=ACCENT_CYAN, height=1).pack(fill="x")

    def _update_clock(self):
        self.time_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._update_clock)

    # ── Controls Panel ─────────────────────────────────────────────────────
    def _build_controls(self, parent):
        cv = tk.Canvas(parent, bg=BG_PANEL, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=cv.yview)
        fr = tk.Frame(cv, bg=BG_PANEL)
        cv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        cv.configure(yscrollcommand=sb.set)
        wid = cv.create_window((0,0), window=fr, anchor="nw")
        fr.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(wid, width=e.width))

        p = 14
        def sec(title):
            f = tk.Frame(fr, bg=BG_CARD, padx=p, pady=8)
            f.pack(fill="x", padx=p, pady=(p,4))
            row = tk.Frame(f, bg=BG_CARD); row.pack(fill="x", pady=(0,6))
            tk.Label(row, text="▸", font=("Courier New",11), bg=BG_CARD, fg=ACCENT_CYAN).pack(side="left")
            tk.Label(row, text=title, font=self.font_label, bg=BG_CARD, fg=TEXT_PRI).pack(side="left", padx=(3,0))
            return f

        def erow(par, lbl, var, ph=""):
            tk.Label(par, text=lbl, font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            e = tk.Entry(par, textvariable=var, bg=BG_DARK, fg=TEXT_PRI,
                insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
                highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER)
            e.pack(fill="x", pady=(2,6), ipady=5)
            if ph and not var.get(): var.set(ph)
            return e

        # ── TARGET ───────────────────────────────────────────────────────
        s1 = sec("TARGET")
        self.target_var = tk.StringVar(value="scanme.nmap.org")
        erow(s1, "Host / IP / CIDR:", self.target_var)
        qf = tk.Frame(s1, bg=BG_CARD); qf.pack(fill="x")
        for nm, tg in [("Localhost","127.0.0.1"),("Nmap Test","scanme.nmap.org")]:
            tk.Button(qf, text=nm, bg=BG_PANEL, fg=ACCENT_CYAN,
                font=self.font_mono_sm, relief="flat", cursor="hand2",
                command=lambda t=tg: self.target_var.set(t)
            ).pack(side="left", padx=(0,4))

        # ── PORT CONFIG ───────────────────────────────────────────────────
        s2 = sec("PORT CONFIGURATION")
        self.port_preset_var = tk.StringVar(value="Common (Top 100)")
        tk.Label(s2, text="Preset:", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        pc = ttk.Combobox(s2, textvariable=self.port_preset_var, state="readonly",
            values=["Common (Top 100)","Top 1000","Well-Known (1-1023)","Full (1-65535)","Custom Range"],
            font=self.font_mono_sm)
        pc.pack(fill="x", pady=(2,6))
        pc.bind("<<ComboboxSelected>>", self._on_preset_change)
        pf = tk.Frame(s2, bg=BG_CARD); pf.pack(fill="x")
        self.port_from_var = tk.StringVar(value="1")
        self.port_to_var   = tk.StringVar(value="1024")
        for lbl, var, side in [("From:", self.port_from_var,"left"),("To:", self.port_to_var,"left")]:
            sub = tk.Frame(pf, bg=BG_CARD); sub.pack(side=side, fill="x", expand=True, padx=(0,4))
            tk.Label(sub, text=lbl, font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            ent = tk.Entry(sub, textvariable=var, bg=BG_DARK, fg=TEXT_PRI,
                insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
                highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER)
            ent.pack(fill="x", ipady=4)
            if "From" in lbl: self.port_from_entry = ent
            else:             self.port_to_entry   = ent

        # ── SCAN OPTIONS ──────────────────────────────────────────────────
        s3 = sec("SCAN OPTIONS")
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        tk.Label(s3, text="Protocol:", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        ttk.Combobox(s3, textvariable=self.scan_type_var, state="readonly",
            values=["TCP Connect","UDP","Both TCP+UDP","SYN Stealth (Linux+root)"],
            font=self.font_mono_sm).pack(fill="x", pady=(2,6))

        self.threads_var = tk.IntVar(value=200)
        tk.Label(s3, text="Threads:", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        tk.Scale(s3, from_=10, to=500, orient="horizontal", variable=self.threads_var,
            bg=BG_CARD, fg=TEXT_PRI, troughcolor=BG_DARK, highlightthickness=0,
            activebackground=ACCENT_CYAN, font=self.font_mono_sm, sliderrelief="flat", bd=0
        ).pack(fill="x", pady=(2,2))

        self.timeout_var = tk.DoubleVar(value=1.0)
        tk.Label(s3, text="Timeout (sec):", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        tk.Scale(s3, from_=0.1, to=5.0, resolution=0.1, orient="horizontal",
            variable=self.timeout_var, bg=BG_CARD, fg=TEXT_PRI,
            troughcolor=BG_DARK, highlightthickness=0, activebackground=ACCENT_CYAN,
            font=self.font_mono_sm, sliderrelief="flat", bd=0
        ).pack(fill="x", pady=(2,4))

        self.grab_banner_var = tk.BooleanVar(value=True)
        self.os_detect_var   = tk.BooleanVar(value=True)
        self.resolve_dns_var = tk.BooleanVar(value=True)
        for txt, var in [("Banner Grabbing + Vuln",self.grab_banner_var),
                         ("OS Detection (TTL)",    self.os_detect_var),
                         ("DNS Resolution",        self.resolve_dns_var)]:
            tk.Checkbutton(s3, text=f"  {txt}", variable=var,
                bg=BG_CARD, fg=TEXT_PRI, selectcolor=BG_DARK,
                activebackground=BG_CARD, activeforeground=ACCENT_CYAN,
                font=self.font_mono_sm, cursor="hand2").pack(anchor="w", pady=1)

        # ── API SETTINGS ──────────────────────────────────────────────────
        s4 = sec("API SETTINGS")
        erow(s4, "Shodan API Key (shodan.io):", self.shodan_key_var)
        erow(s4, "NVD API Key (optional):",     self.nvd_key_var)
        tk.Button(s4, text="💾 Save Keys", command=self._save_config,
            bg=BG_PANEL, fg=ACCENT_YLW, font=self.font_mono_sm,
            relief="flat", cursor="hand2", pady=3
        ).pack(fill="x", pady=(0,4))

        # NVD update
        tk.Button(s4, text="🔄 Update CVE DB from NVD",
            command=self._nvd_update_dialog,
            bg=BG_PANEL, fg=ACCENT_CYAN, font=self.font_mono_sm,
            relief="flat", cursor="hand2", pady=4
        ).pack(fill="x", pady=(0,4))

        tk.Button(s4, text="🔍 Shodan Lookup (Last Target)",
            command=self._shodan_lookup,
            bg=BG_PANEL, fg=ACCENT_PRP, font=self.font_mono_sm,
            relief="flat", cursor="hand2", pady=4
        ).pack(fill="x")

        # ── ACTIONS ───────────────────────────────────────────────────────
        sa = tk.Frame(fr, bg=BG_PANEL)
        sa.pack(fill="x", padx=p, pady=(p,4))

        self.scan_btn = tk.Button(sa, text="◈  START SCAN", command=self._start_scan,
            bg=ACCENT_CYAN, fg=BG_DARK, font=self.font_btn,
            relief="flat", cursor="hand2", pady=11,
            activebackground="#00aacc", activeforeground=BG_DARK)
        self.scan_btn.pack(fill="x", pady=(0,6))

        self.stop_btn = tk.Button(sa, text="■  STOP", command=self._stop_scan,
            bg=ACCENT_RED, fg="white", font=self.font_btn,
            relief="flat", cursor="hand2", pady=9, state="disabled",
            activebackground="#cc2244", activeforeground="white")
        self.stop_btn.pack(fill="x", pady=(0,6))

        # Export row
        ef = tk.Frame(sa, bg=BG_PANEL); ef.pack(fill="x")
        exports = [("JSON",self._export_json,ACCENT_PRP),
                   ("CSV", self._export_csv, ACCENT_GRN),
                   ("TXT", self._export_txt, ACCENT_YLW),
                   ("PDF", self._export_pdf, ACCENT_RED)]
        for txt, cmd, col in exports:
            tk.Button(ef, text=f"↓{txt}", command=cmd,
                bg=BG_CARD, fg=col, font=self.font_mono_sm,
                relief="flat", cursor="hand2", pady=5,
                highlightthickness=1, highlightbackground=col,
                activebackground=BG_HOVER, activeforeground=col
            ).pack(side="left", expand=True, fill="x", padx=1)

    # ── Right Notebook (4 Tabs) ────────────────────────────────────────────
    def _build_right_notebook(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True, padx=6, pady=6)

        # Tab 1: Scan Results
        tab1 = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(tab1, text="◈ SCAN RESULTS")
        self._build_results_tab(tab1)

        # Tab 2: Topology Map
        tab2 = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(tab2, text="◈ TOPOLOGY MAP")
        self._build_topology_tab(tab2)

        # Tab 3: Brute Force
        tab3 = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(tab3, text="◈ BRUTE FORCE")
        self._build_brute_tab(tab3)

        # Tab 4: Scheduler
        tab4 = tk.Frame(self.nb, bg=BG_DARK)
        self.nb.add(tab4, text="◈ SCHEDULER")
        self._build_scheduler_tab(tab4)

    # ── Tab 1: Scan Results (preserved from v4) ────────────────────────────
    def _build_results_tab(self, parent):
        stats = tk.Frame(parent, bg=BG_CARD, height=66)
        stats.pack(fill="x", padx=10, pady=(10,4)); stats.pack_propagate(False)
        self.stat_open     = self._stat_lbl(stats,"0","OPEN PORTS",ACCENT_GRN)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_closed   = self._stat_lbl(stats,"0","CLOSED",TEXT_DIM)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_filtered = self._stat_lbl(stats,"0","FILTERED",ACCENT_YLW)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_total    = self._stat_lbl(stats,"0","SCANNED",TEXT_SEC)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_host     = self._stat_lbl(stats,"—","TARGET IP",ACCENT_CYAN)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_os       = self._stat_lbl(stats,"—","OS HINT",ACCENT_YLW)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_vuln     = self._stat_lbl(stats,"0","VULNERABLE",ACCENT_RED)
        tk.Frame(stats,bg=BORDER,width=1).pack(side="left",fill="y",pady=8)
        self.stat_time     = self._stat_lbl(stats,"—","SCAN TIME",ACCENT_PRP)

        pb = tk.Frame(parent, bg=BG_DARK); pb.pack(fill="x", padx=10, pady=(0,2))
        self.progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(pb, variable=self.progress_var, maximum=100,
            style="TProgressbar").pack(fill="x", ipady=1)
        self.progress_label = tk.Label(pb, text="Ready...",
            font=self.font_mono_sm, bg=BG_DARK, fg=TEXT_SEC)
        self.progress_label.pack(anchor="w")

        fb = tk.Frame(parent, bg=BG_DARK); fb.pack(fill="x", padx=10, pady=(2,2))
        tk.Label(fb, text="Filter:", font=self.font_mono_sm, bg=BG_DARK, fg=TEXT_SEC).pack(side="left", padx=(0,4))
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self._apply_filter)
        tk.Entry(fb, textvariable=self.filter_var, bg=BG_CARD, fg=TEXT_PRI,
            insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
            highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER,
            width=28).pack(side="left", ipady=3)
        self.show_open_only = tk.BooleanVar(value=False)
        self.show_vuln_only = tk.BooleanVar(value=False)
        for txt, var, col in [("Open Only",self.show_open_only,ACCENT_GRN),
                               ("Vuln Only",self.show_vuln_only,ACCENT_RED)]:
            tk.Checkbutton(fb, text=f"  {txt}", variable=var, command=self._apply_filter,
                bg=BG_DARK, fg=col, selectcolor=BG_CARD,
                activebackground=BG_DARK, activeforeground=col,
                font=self.font_mono_sm, cursor="hand2").pack(side="left", padx=6)

        tf = tk.Frame(parent, bg=BG_DARK)
        tf.pack(fill="both", expand=True, padx=10, pady=(0,2))
        cols = ("port","state","service","banner","latency")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
        for col, hd, w, anc in [("port","PORT",65,"center"),("state","STATE",90,"center"),
                                  ("service","SERVICE",120,"w"),
                                  ("banner","BANNER / CVE INFO",360,"w"),("latency","RTT(ms)",75,"center")]:
            self.tree.heading(col, text=hd, anchor=anc)
            self.tree.column(col, width=w, minwidth=40, anchor=anc, stretch=(col=="banner"))
        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y"); hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)
        for tag, col, bold in [("open",ACCENT_GRN,False),("vuln_critical",ACCENT_RED,True),
                                 ("vuln_high",ACCENT_RED,False),("vuln_medium",ACCENT_YLW,False),
                                 ("udp","#00bfff",False),("filtered",ACCENT_PRP,False),("closed",TEXT_DIM,False)]:
            kw = {"foreground":col}
            if bold: kw["font"] = ("Courier New",10,"bold")
            self.tree.tag_configure(tag, **kw)
        self.tree.bind("<Double-1>", self._show_vuln_details)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=10)
        lh = tk.Frame(parent, bg=BG_PANEL); lh.pack(fill="x", padx=10, pady=(2,0))
        tk.Label(lh, text="◈ SCAN LOG", font=self.font_mono_sm, bg=BG_PANEL, fg=ACCENT_CYAN).pack(side="left")
        tk.Button(lh, text="Clear", command=self._clear_log, bg=BG_PANEL,
            fg=TEXT_SEC, relief="flat", font=self.font_mono_sm, cursor="hand2").pack(side="right")
        self.log_text = tk.Text(parent, height=6, bg=BG_PANEL, fg=TEXT_SEC,
            font=self.font_mono_sm, relief="flat", insertbackground=ACCENT_CYAN,
            state="disabled", padx=8, pady=4)
        self.log_text.pack(fill="x", padx=10, pady=(0,4))
        for tag, col in [("info",ACCENT_CYAN),("ok",ACCENT_GRN),("warn",ACCENT_YLW),
                          ("error",ACCENT_RED),("critical",ACCENT_RED)]:
            self.log_text.tag_config(tag, foreground=col)

    def _stat_lbl(self, par, val, lbl, col):
        f = tk.Frame(par, bg=BG_CARD, padx=14, pady=4)
        f.pack(side="left", fill="both", expand=True)
        v = tk.StringVar(value=val)
        tk.Label(f, textvariable=v, font=self.font_big, bg=BG_CARD, fg=col).pack()
        tk.Label(f, text=lbl, font=("Courier New",7), bg=BG_CARD, fg=TEXT_DIM).pack()
        return v

    # ── Tab 2: Topology Map ────────────────────────────────────────────────
    def _build_topology_tab(self, parent):
        bar = tk.Frame(parent, bg=BG_PANEL); bar.pack(fill="x", padx=10, pady=(8,4))
        tk.Label(bar, text="Network Topology Map  — Radial view of discovered open ports",
            font=self.font_mono_sm, bg=BG_PANEL, fg=TEXT_SEC).pack(side="left", padx=8)
        tk.Button(bar, text="🔄 Refresh Map", bg=BG_CARD, fg=ACCENT_CYAN,
            font=self.font_mono_sm, relief="flat", cursor="hand2",
            command=self._refresh_topology
        ).pack(side="right", padx=8)
        tk.Label(bar, text="Right-drag: pan  |  Scroll: zoom  |  Click node: details",
            font=("Courier New",8), bg=BG_PANEL, fg=TEXT_DIM).pack(side="right")
        self.topology = TopologyMap(parent)

    def _refresh_topology(self):
        self.topology.draw(self.results, self.current_ip)

    # ── Tab 3: Brute Force ─────────────────────────────────────────────────
    def _build_brute_tab(self, parent):
        # Disclaimer banner
        disc = tk.Frame(parent, bg="#300010", bd=0)
        disc.pack(fill="x", padx=10, pady=(8,4))
        tk.Label(disc, text=BRUTE_DISCLAIMER, font=("Courier New",8),
            bg="#300010", fg=ACCENT_YLW, justify="left", padx=10, pady=6
        ).pack(anchor="w")

        # Settings row
        cfg = tk.Frame(parent, bg=BG_DARK); cfg.pack(fill="x", padx=10, pady=4)
        # Left col
        lc = tk.Frame(cfg, bg=BG_CARD, padx=10, pady=8)
        lc.pack(side="left", fill="both", expand=True, padx=(0,4))
        tk.Label(lc, text="▸ TARGET", font=self.font_label, bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w")
        self.bf_target_var  = tk.StringVar(value="127.0.0.1")
        self.bf_port_var    = tk.StringVar(value="21")
        self.bf_service_var = tk.StringVar(value="FTP")
        self.bf_path_var    = tk.StringVar(value="/")
        for lbl, var in [("Host/IP:", self.bf_target_var),("Port:", self.bf_port_var)]:
            tk.Label(lc, text=lbl, font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            tk.Entry(lc, textvariable=var, bg=BG_DARK, fg=TEXT_PRI,
                insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
                highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER
            ).pack(fill="x", pady=(2,4), ipady=4)
        tk.Label(lc, text="Service:", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        svc_cb = ttk.Combobox(lc, textvariable=self.bf_service_var, state="readonly",
            values=["FTP","SSH","HTTP Basic Auth"], font=self.font_mono_sm)
        svc_cb.pack(fill="x", pady=(2,4))
        svc_cb.bind("<<ComboboxSelected>>", self._bf_service_changed)
        tk.Label(lc, text="HTTP Path (for Basic Auth):", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        tk.Entry(lc, textvariable=self.bf_path_var, bg=BG_DARK, fg=TEXT_PRI,
            insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
            highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER
        ).pack(fill="x", pady=(2,4), ipady=4)

        # Right col
        rc = tk.Frame(cfg, bg=BG_CARD, padx=10, pady=8)
        rc.pack(side="left", fill="both", expand=True)
        tk.Label(rc, text="▸ WORDLISTS", font=self.font_label, bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w")
        tk.Label(rc, text="Usernames (comma separated or file path):",
            font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        self.bf_users_text = tk.Text(rc, height=4, bg=BG_DARK, fg=TEXT_PRI,
            insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono_sm,
            highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER)
        self.bf_users_text.pack(fill="x", pady=(2,4))
        self.bf_users_text.insert("1.0", "\n".join(DEFAULT_USERNAMES))
        tk.Label(rc, text="Passwords (comma separated or file path):",
            font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        self.bf_pass_text = tk.Text(rc, height=4, bg=BG_DARK, fg=TEXT_PRI,
            insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono_sm,
            highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER)
        self.bf_pass_text.pack(fill="x", pady=(2,4))
        self.bf_pass_text.insert("1.0", "\n".join(DEFAULT_PASSWORDS))
        # Rate limit
        tk.Label(rc, text="Delay between attempts (sec):", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
        self.bf_delay_var = tk.DoubleVar(value=0.3)
        tk.Scale(rc, from_=0.0, to=3.0, resolution=0.1, orient="horizontal",
            variable=self.bf_delay_var, bg=BG_CARD, fg=TEXT_PRI,
            troughcolor=BG_DARK, highlightthickness=0, sliderrelief="flat", bd=0,
            activebackground=ACCENT_CYAN, font=self.font_mono_sm
        ).pack(fill="x")

        # Control buttons
        bf_btns = tk.Frame(parent, bg=BG_DARK); bf_btns.pack(fill="x", padx=10, pady=4)
        self.bf_start_btn = tk.Button(bf_btns, text="▶  START BRUTE FORCE",
            command=self._start_brute, bg=ACCENT_ORG, fg="white",
            font=self.font_btn, relief="flat", cursor="hand2", pady=8,
            activebackground="#cc6600", activeforeground="white")
        self.bf_start_btn.pack(side="left", padx=(0,8))
        self.bf_stop_btn = tk.Button(bf_btns, text="■  STOP",
            command=self._stop_brute, bg=ACCENT_RED, fg="white",
            font=self.font_btn, relief="flat", cursor="hand2", pady=8,
            state="disabled")
        self.bf_stop_btn.pack(side="left")
        tk.Button(bf_btns, text="📋 Load User File", bg=BG_CARD, fg=ACCENT_CYAN,
            font=self.font_mono_sm, relief="flat", cursor="hand2",
            command=lambda: self._load_wordlist(self.bf_users_text)
        ).pack(side="right", padx=(4,0))
        tk.Button(bf_btns, text="📋 Load Pass File", bg=BG_CARD, fg=ACCENT_CYAN,
            font=self.font_mono_sm, relief="flat", cursor="hand2",
            command=lambda: self._load_wordlist(self.bf_pass_text)
        ).pack(side="right", padx=(4,0))

        self.bf_progress_var = tk.DoubleVar(value=0)
        bf_pb_f = tk.Frame(parent, bg=BG_DARK); bf_pb_f.pack(fill="x", padx=10, pady=(0,2))
        ttk.Progressbar(bf_pb_f, variable=self.bf_progress_var, maximum=100,
            style="TProgressbar").pack(fill="x", ipady=1)
        self.bf_status_lbl = tk.Label(bf_pb_f, text="Idle", font=self.font_mono_sm,
            bg=BG_DARK, fg=TEXT_SEC); self.bf_status_lbl.pack(anchor="w")

        # Results tree
        rt = tk.Frame(parent, bg=BG_DARK); rt.pack(fill="both", expand=True, padx=10, pady=(0,6))
        self.bf_tree = ttk.Treeview(rt,
            columns=("username","password","result","detail"), show="headings")
        for col, hd, w in [("username","USERNAME",120),("password","PASSWORD",120),
                            ("result","RESULT",90),("detail","DETAIL",400)]:
            self.bf_tree.heading(col, text=hd)
            self.bf_tree.column(col, width=w, stretch=(col=="detail"))
        bvsb = ttk.Scrollbar(rt, orient="vertical", command=self.bf_tree.yview)
        self.bf_tree.configure(yscrollcommand=bvsb.set)
        bvsb.pack(side="right", fill="y"); self.bf_tree.pack(fill="both", expand=True)
        self.bf_tree.tag_configure("success", foreground=ACCENT_GRN, font=("Courier New",10,"bold"))
        self.bf_tree.tag_configure("fail",    foreground=TEXT_DIM)
        self.bf_tree.tag_configure("error",   foreground=ACCENT_YLW)

    # ── Tab 4: Scheduler ───────────────────────────────────────────────────
    def _build_scheduler_tab(self, parent):
        tk.Label(parent, text="◈ SCHEDULED SCANS — Auto-run scans at configurable intervals",
            font=self.font_mono_sm, bg=BG_DARK, fg=TEXT_SEC
        ).pack(anchor="w", padx=12, pady=(10,4))

        # Add form
        af = tk.Frame(parent, bg=BG_CARD, padx=12, pady=10)
        af.pack(fill="x", padx=12, pady=(0,6))
        tk.Label(af, text="▸ ADD NEW SCHEDULE", font=self.font_label, bg=BG_CARD, fg=ACCENT_CYAN).pack(anchor="w", pady=(0,6))
        row1 = tk.Frame(af, bg=BG_CARD); row1.pack(fill="x")
        self.sch_name_var     = tk.StringVar(value="Daily Scan")
        self.sch_target_var   = tk.StringVar(value="192.168.1.1")
        self.sch_pfrom_var    = tk.StringVar(value="1")
        self.sch_pto_var      = tk.StringVar(value="1024")
        self.sch_interval_var = tk.DoubleVar(value=24.0)
        labels = ["Name:", "Target:", "Port From:", "Port To:"]
        vars_  = [self.sch_name_var, self.sch_target_var, self.sch_pfrom_var, self.sch_pto_var]
        for i, (lbl, var) in enumerate(zip(labels, vars_)):
            col_f = tk.Frame(row1, bg=BG_CARD); col_f.pack(side="left", expand=True, fill="x", padx=(0,6))
            tk.Label(col_f, text=lbl, font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(anchor="w")
            tk.Entry(col_f, textvariable=var, bg=BG_DARK, fg=TEXT_PRI,
                insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono,
                highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER
            ).pack(fill="x", ipady=4)
        row2 = tk.Frame(af, bg=BG_CARD); row2.pack(fill="x", pady=(6,0))
        tk.Label(row2, text="Interval (hours):", font=self.font_mono_sm, bg=BG_CARD, fg=TEXT_SEC).pack(side="left")
        tk.Scale(row2, from_=0.1, to=168, resolution=0.5, orient="horizontal",
            variable=self.sch_interval_var, bg=BG_CARD, fg=TEXT_PRI,
            troughcolor=BG_DARK, highlightthickness=0, sliderrelief="flat", bd=0,
            activebackground=ACCENT_CYAN, font=self.font_mono_sm, length=200
        ).pack(side="left", padx=8)
        tk.Label(row2, textvariable=self.sch_interval_var, font=self.font_mono_sm,
            bg=BG_CARD, fg=ACCENT_CYAN).pack(side="left")
        tk.Button(row2, text="➕ Add Schedule", command=self._add_schedule,
            bg=ACCENT_CYAN, fg=BG_DARK, font=self.font_mono_sm,
            relief="flat", cursor="hand2", padx=10, pady=4
        ).pack(side="right")

        # Schedule list
        sf = tk.Frame(parent, bg=BG_DARK); sf.pack(fill="both", expand=True, padx=12, pady=(0,6))
        self.sch_tree = ttk.Treeview(sf,
            columns=("name","target","ports","interval","next_run","last_run","runs","status"),
            show="headings")
        for col, hd, w in [("name","NAME",120),("target","TARGET",120),("ports","PORTS",90),
                            ("interval","INTERVAL",80),("next_run","NEXT RUN",150),
                            ("last_run","LAST RUN",150),("runs","RUNS",50),("status","STATUS",70)]:
            self.sch_tree.heading(col, text=hd)
            self.sch_tree.column(col, width=w, stretch=(col=="target"))
        svsb = ttk.Scrollbar(sf, orient="vertical", command=self.sch_tree.yview)
        self.sch_tree.configure(yscrollcommand=svsb.set)
        svsb.pack(side="right", fill="y"); self.sch_tree.pack(fill="both", expand=True)
        self.sch_tree.tag_configure("enabled",  foreground=ACCENT_GRN)
        self.sch_tree.tag_configure("disabled", foreground=TEXT_DIM)

        ctl = tk.Frame(parent, bg=BG_DARK); ctl.pack(fill="x", padx=12, pady=(0,8))
        for txt, cmd, col in [("Toggle Enable/Disable",self._toggle_schedule,ACCENT_YLW),
                               ("Remove Selected",self._remove_schedule,ACCENT_RED),
                               ("Refresh List",self._refresh_schedule_list,ACCENT_CYAN)]:
            tk.Button(ctl, text=txt, command=cmd, bg=BG_CARD, fg=col,
                font=self.font_mono_sm, relief="flat", cursor="hand2", padx=8, pady=4
            ).pack(side="left", padx=(0,6))
        self.sch_log = tk.Text(parent, height=4, bg=BG_PANEL, fg=TEXT_SEC,
            font=self.font_mono_sm, relief="flat", state="disabled", padx=8, pady=4)
        self.sch_log.pack(fill="x", padx=12, pady=(0,6))
        self.sch_log.tag_config("ok", foreground=ACCENT_GRN)
        self.sch_log.tag_config("info", foreground=ACCENT_CYAN)

    # ── Status Bar ─────────────────────────────────────────────────────────
    def _build_statusbar(self):
        sb = tk.Frame(self.root, bg=BG_PANEL, height=26)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready  |  v5.0  |  Ctrl+S=Scan | F1=Help")
        tk.Label(sb, textvariable=self.status_var,
            font=self.font_mono_sm, bg=BG_PANEL, fg=TEXT_SEC).pack(side="left", padx=12)
        avail = []
        if PDF_AVAILABLE:      avail.append("PDF✓")
        if PARAMIKO_AVAILABLE: avail.append("SSH✓")
        caps = " | ".join(avail) if avail else "Install reportlab+paramiko for full features"
        tk.Label(sb, text=f"PHANTOM SCAN v5.0  |  {caps}",
            font=self.font_mono_sm, bg=BG_PANEL, fg=TEXT_DIM).pack(side="right", padx=12)


    # ══════════════════════════════════════════════════════════════════════════
    #  EVENT HANDLERS & HELPERS
    # ══════════════════════════════════════════════════════════════════════════
    def _on_preset_change(self, event=None):
        p = self.port_preset_var.get()
        if   p == "Common (Top 100)":    self.port_from_var.set("1");  self.port_to_var.set("1024")
        elif p == "Top 1000":            self.port_from_var.set("1");  self.port_to_var.set("1000")
        elif p == "Well-Known (1-1023)": self.port_from_var.set("1");  self.port_to_var.set("1023")
        elif p == "Full (1-65535)":      self.port_from_var.set("1");  self.port_to_var.set("65535")
        st = "normal" if p == "Custom Range" else "readonly"
        try:
            self.port_from_entry.config(state=st)
            self.port_to_entry.config(state=st)
        except: pass

    def _apply_filter(self, *args):
        qry      = self.filter_var.get().lower()
        openonly = self.show_open_only.get()
        vulnonly = self.show_vuln_only.get()
        for item in self.tree.get_children(): self.tree.delete(item)
        for r in self.results:
            if openonly and r.get("state","") not in ("OPEN","OPEN|FILTERED"): continue
            if vulnonly and not r.get("vulnerabilities",[]): continue
            combo = f"{r.get('port','')} {r.get('state','')} {r.get('service','')} {r.get('banner','')}".lower()
            if qry and qry not in combo: continue
            self._insert_result(r)

    def _insert_result(self, r):
        port  = r.get("port","");  state = r.get("state","CLOSED")
        svc   = r.get("service","");  bnr = r.get("banner","")[:80]
        lat   = r.get("latency",""); vulns = r.get("vulnerabilities",[])
        if vulns:
            sevs = [v.get("severity","") for v in vulns]
            bnr  = f"{'⚠⚠ CRITICAL! ' if 'CRITICAL' in sevs else '⚠ HIGH! ' if 'HIGH' in sevs else '⚠ MEDIUM '}{bnr}"
        if state == "OPEN":
            if vulns:
                sevs = [v.get("severity","") for v in vulns]
                tag  = "vuln_critical" if "CRITICAL" in sevs else "vuln_high" if "HIGH" in sevs else "vuln_medium"
            else:
                tag = "open"
        elif "FILTERED" in state: tag = "filtered"
        elif "UDP" in str(bnr):   tag = "udp"
        else:                     tag = "closed"
        self.tree.insert("","end", values=(port,state,svc,bnr,lat), tags=(tag,))

    def _show_vuln_details(self, event):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0],"values")
        if not vals: return
        port = vals[0]
        for res in self.results:
            if str(res.get("port","")) == str(port):
                vulns = res.get("vulnerabilities",[])
                if vulns:
                    msg = f"VULNERABILITY REPORT — Port {port}\n{'═'*50}\n\n"
                    for i,v in enumerate(vulns,1):
                        msg += (f"[{i}] CVE: {v['cve']}\n"
                                f"    Severity : {v['severity']} (CVSS {v['cvss']})\n"
                                f"    Desc     : {v['description']}\n"
                                f"    Exploit  : {'✅ YES' if v['exploit_available'] else '❌ NO'}\n"
                                f"    Fix      : {v['remediation']}\n\n{'─'*40}\n\n")
                    messagebox.showwarning(f"⚠ CVE Details — Port {port}", msg)
                else:
                    messagebox.showinfo(f"Port {port}",
                        f"Service : {res.get('service','')}\n"
                        f"State   : {res.get('state','')}\n"
                        f"Banner  : {res.get('banner','N/A')}\n"
                        f"Latency : {res.get('latency','')} ms\n\n"
                        f"No known vulnerabilities detected.")
                return

    # ══════════════════════════════════════════════════════════════════════════
    #  SCAN ENGINE
    # ══════════════════════════════════════════════════════════════════════════
    def _start_scan(self):
        if self.is_scanning: return
        self.results = []
        for item in self.tree.get_children(): self.tree.delete(item)
        for sv in [self.stat_open,self.stat_closed,self.stat_filtered,
                   self.stat_total,self.stat_vuln]:
            sv.set("0")
        self.stat_host.set("—"); self.stat_os.set("—"); self.stat_time.set("—")
        self.progress_var.set(0)
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Input", "Enter a target host or IP."); return
        try:
            pf,pt = int(self.port_from_var.get()), int(self.port_to_var.get())
            if not (1<=pf<=65535 and 1<=pt<=65535 and pf<=pt): raise ValueError
        except ValueError:
            messagebox.showwarning("Input","Invalid port range."); return
        targets = parse_target(target)
        if not targets:
            messagebox.showwarning("Error",f"Could not resolve: {target}"); return
        self.is_scanning = True
        self.scan_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        self.status_var.set(f"Scanning {target} ...")
        self.scan_thread = threading.Thread(target=self._scan_worker,
            args=(targets,pf,pt), daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.is_scanning = False
        self._log("Scan stopped by user.","warn")
        self.status_var.set("Stopped.")
        self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")

    def _scan_worker(self, targets, p_from, p_to):
        t_start = time.time()
        scan_type= self.scan_type_var.get()
        threads  = self.threads_var.get()
        timeout  = self.timeout_var.get()
        grab     = self.grab_banner_var.get()
        open_c=closed_c=filt_c=vuln_c=0
        self.scanned_ports=0; self.total_ports=0

        for host in targets:
            if not self.is_scanning: break
            self.result_queue.put(("log",f"Resolving {host}...","info"))
            ip, hostname = resolve_host(host)
            if not ip:
                self.result_queue.put(("log",f"Could not resolve: {host}","error")); continue
            self.current_ip = ip
            self.result_queue.put(("log",f"Resolved: {host} → {ip} ({hostname})","ok"))
            self.result_queue.put(("stat_host", ip))

            if self.os_detect_var.get():
                self.result_queue.put(("log","Detecting OS via TTL...","info"))
                os_hint = detect_os_hint(ip)
                self.result_queue.put(("stat_os", os_hint[:20]))
                self.result_queue.put(("log",f"OS Hint: {os_hint}","ok"))

            ports = list(range(p_from, p_to+1))
            syn_mode = "SYN" in scan_type
            mults = 1
            if scan_type == "Both TCP+UDP": mults = 2
            self.total_ports += len(ports)*mults
            self.result_queue.put(("log",
                f"Scanning {len(ports)} ports on {ip} [{scan_type}] — {threads} threads","info"))
            self.result_queue.put(("progress",0))

            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {}
                for port in ports:
                    if not self.is_scanning: break
                    if syn_mode:
                        futures[ex.submit(syn_scan_port, ip, port, timeout)] = ("syn",port)
                    else:
                        if scan_type in ("TCP Connect","Both TCP+UDP"):
                            futures[ex.submit(scan_port, ip, port, timeout, grab)] = ("tcp",port)
                        if scan_type in ("UDP","Both TCP+UDP"):
                            futures[ex.submit(scan_udp_port, ip, port, timeout)] = ("udp",port)

                for future in as_completed(futures):
                    if not self.is_scanning: break
                    try: result = future.result()
                    except Exception:
                        self.scanned_ports += 1; continue
                    self.scanned_ports += 1
                    pct = (self.scanned_ports/max(self.total_ports,1))*100
                    self.result_queue.put(("progress",pct))

                    st = result.get("state","CLOSED")
                    if st == "OPEN":
                        open_c += 1
                        self.results.append(result)
                        self.result_queue.put(("result",result))
                        vulns = result.get("vulnerabilities",[])
                        if vulns:
                            vuln_c += 1
                            self.result_queue.put(("stat_vuln",str(vuln_c)))
                            summ = ", ".join(f"{v['cve']} ({v['severity']})" for v in vulns)
                            self.result_queue.put(("log",
                                f"[VULNERABLE] Port {result['port']} {result.get('service','')} — {summ}","critical"))
                        else:
                            self.result_queue.put(("log",
                                f"[OPEN] Port {result['port']} {result.get('service','')} {result.get('banner','')[:40]}","ok"))
                        self.result_queue.put(("stat_open",str(open_c)))
                    elif st == "OPEN|FILTERED":
                        filt_c += 1
                        self.results.append(result)
                        self.result_queue.put(("result",result))
                        self.result_queue.put(("log",f"[FILTERED] Port {result['port']}","warn"))
                        self.result_queue.put(("stat_filtered",str(filt_c)))
                    else:
                        closed_c += 1
                        self.result_queue.put(("stat_closed",str(closed_c)))
                    self.result_queue.put(("stat_total",str(self.scanned_ports)))

        elapsed = round(time.time()-t_start,2)
        self.result_queue.put(("stat_time",f"{elapsed}s"))
        self.result_queue.put(("log",
            f"Scan done in {elapsed}s | {open_c} open | {filt_c} filtered | {vuln_c} vulnerable","info"))
        self.result_queue.put(("progress",100))
        self.result_queue.put(("done",None))

    # ══════════════════════════════════════════════════════════════════════════
    #  QUEUE POLLERS
    # ══════════════════════════════════════════════════════════════════════════
    def _start_pollers(self):
        self._poll_results()
        self._poll_brute_results()

    def _poll_results(self):
        try:
            while True:
                msg = self.result_queue.get_nowait(); kind = msg[0]
                if   kind=="result":       self._insert_result(msg[1])
                elif kind=="log":          self._log(msg[1],msg[2])
                elif kind=="stat_host":   self.stat_host.set(msg[1])
                elif kind=="stat_os":     self.stat_os.set(msg[1])
                elif kind=="stat_open":   self.stat_open.set(msg[1])
                elif kind=="stat_closed": self.stat_closed.set(msg[1])
                elif kind=="stat_filtered":self.stat_filtered.set(msg[1])
                elif kind=="stat_total":  self.stat_total.set(msg[1])
                elif kind=="stat_vuln":   self.stat_vuln.set(msg[1])
                elif kind=="stat_time":   self.stat_time.set(msg[1])
                elif kind=="progress":
                    self.progress_var.set(msg[1])
                    self.progress_label.config(
                        text=f"Progress: {msg[1]:.1f}%  ({self.scanned_ports}/{self.total_ports} ports)")
                elif kind=="done":
                    self.is_scanning = False
                    self.scan_btn.config(state="normal"); self.stop_btn.config(state="disabled")
                    self.status_var.set("Scan finished.")
                    self.progress_label.config(text="Scan complete.")
                    # Auto-refresh topology
                    self.topology.draw(self.results, self.current_ip)
        except queue.Empty: pass
        self.root.after(50, self._poll_results)

    def _poll_brute_results(self):
        try:
            while True:
                msg = self.brute_queue.get_nowait(); kind = msg[0]
                if kind=="bf_row":
                    u,pw,res_d = msg[1],msg[2],msg[3]
                    ok  = res_d.get("success",False)
                    det = f"✅ CREDENTIALS FOUND!" if ok else res_d.get("error","Invalid")
                    tag = "success" if ok else ("error" if "error" in res_d else "fail")
                    self.bf_tree.insert("","end",values=(u,pw,"SUCCESS" if ok else "FAIL",det),tags=(tag,))
                    if ok: self.bf_tree.see(self.bf_tree.get_children()[-1])
                elif kind=="bf_progress":
                    self.bf_progress_var.set(msg[1])
                    self.bf_status_lbl.config(text=msg[2])
                elif kind=="bf_done":
                    self.is_bruteforcing = False
                    self.bf_start_btn.config(state="normal"); self.bf_stop_btn.config(state="disabled")
                    self.bf_status_lbl.config(text=msg[1])
        except queue.Empty: pass
        self.root.after(100, self._poll_brute_results)

    # ══════════════════════════════════════════════════════════════════════════
    #  LOG
    # ══════════════════════════════════════════════════════════════════════════
    def _log(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{ts}] ","info")
        self.log_text.insert("end", msg+"\n", level)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0","end")
        self.log_text.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    #  EXPORTS
    # ══════════════════════════════════════════════════════════════════════════
    def _export_json(self):
        if not self.results: messagebox.showinfo("Export","No results."); return
        path = filedialog.asksaveasfilename(defaultextension=".json",
            filetypes=[("JSON","*.json")], initialfile="phantom_report.json")
        if not path: return
        data = {"target":self.target_var.get(),"scan_time":datetime.now().isoformat(),
                "open_ports":[r for r in self.results if r.get("state")=="OPEN"],
                "vulnerable_ports":[r for r in self.results if r.get("vulnerabilities")],
                "summary":{"total_open":len([r for r in self.results if r.get("state")=="OPEN"]),
                            "total_vulnerable":len([r for r in self.results if r.get("vulnerabilities")])}}
        with open(path,"w") as f: json.dump(data,f,indent=2)
        self._log(f"Exported JSON → {path}","ok")

    def _export_csv(self):
        if not self.results: messagebox.showinfo("Export","No results."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV","*.csv")], initialfile="phantom_report.csv")
        if not path: return
        with open(path,"w",newline="") as f:
            w = csv.DictWriter(f,fieldnames=["port","state","service","banner","latency","vulnerabilities"])
            w.writeheader()
            for r in self.results:
                row = {k:r.get(k,"") for k in ["port","state","service","banner","latency"]}
                row["vulnerabilities"] = ", ".join(v["cve"] for v in r.get("vulnerabilities",[]))
                w.writerow(row)
        self._log(f"Exported CSV → {path}","ok")

    def _export_txt(self):
        if not self.results: messagebox.showinfo("Export","No results."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text","*.txt")], initialfile="phantom_report.txt")
        if not path: return
        with open(path,"w") as f:
            f.write("PHANTOM SCAN v5.0 — Vulnerability Assessment Report\n")
            f.write("═"*70+"\n")
            f.write(f"Target : {self.target_var.get()}\n")
            f.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("═"*70+"\n\n")
            vulnerable = [r for r in self.results if r.get("vulnerabilities")]
            if vulnerable:
                f.write("VULNERABLE SERVICES:\n"+"─"*70+"\n")
                for r in vulnerable:
                    f.write(f"\nPort {r['port']} — {r.get('service','')}\n")
                    for v in r.get("vulnerabilities",[]):
                        f.write(f"  ├─ CVE         : {v['cve']}\n")
                        f.write(f"  ├─ CVSS        : {v['cvss']} [{v['severity']}]\n")
                        f.write(f"  ├─ Description : {v['description']}\n")
                        f.write(f"  ├─ Exploit     : {'YES' if v['exploit_available'] else 'NO'}\n")
                        f.write(f"  └─ Fix         : {v['remediation']}\n")
            else:
                f.write("No vulnerable services detected.\n")
            f.write("\n"+"═"*70+"\nALL OPEN PORTS:\n"+"─"*70+"\n")
            for r in self.results:
                if r.get("state") in ("OPEN","OPEN|FILTERED"):
                    f.write(f"Port {r['port']:5d}  {r['state']:15s}  {r.get('service',''):20s}  {r.get('banner','')[:60]}\n")
        self._log(f"Exported TXT → {path}","ok")

    def _export_pdf(self):
        if not self.results: messagebox.showinfo("Export","No results."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf" if PDF_AVAILABLE else ".html",
            filetypes=[("PDF","*.pdf"),("HTML","*.html")],
            initialfile="phantom_report.pdf" if PDF_AVAILABLE else "phantom_report.html")
        if not path: return
        ok, result = generate_pdf_report(self.results, self.target_var.get(), path)
        if ok:
            self._log(f"PDF/HTML report → {result}","ok")
            messagebox.showinfo("Export Complete",f"Report saved:\n{result}")
        else:
            self._log(f"PDF export error: {result}","error")
            messagebox.showerror("Export Error", result)

    # ══════════════════════════════════════════════════════════════════════════
    #  SHODAN LOOKUP
    # ══════════════════════════════════════════════════════════════════════════
    def _shodan_lookup(self):
        if not self.current_ip:
            messagebox.showinfo("Shodan","Run a scan first to set the target IP."); return
        key = self.shodan_key_var.get().strip()
        if not key:
            messagebox.showwarning("Shodan","No API key set.\nGet a free key at https://shodan.io and enter it in API Settings.")
            return
        self._log(f"Shodan: Looking up {self.current_ip}...","info")
        def _run():
            data = shodan_host_lookup(self.current_ip, key)
            self.result_queue.put(("log","─"*50,"info"))
            if "error" in data:
                self.result_queue.put(("log",f"Shodan Error: {data['error']}","error")); return
            org   = data.get("org","Unknown")
            isp   = data.get("isp","Unknown")
            city  = data.get("city",""); country = data.get("country_name","")
            ports = data.get("ports",[])
            vulns = data.get("vulns",{})
            tags  = data.get("tags",[])
            self.result_queue.put(("log",f"[SHODAN] {self.current_ip}","ok"))
            self.result_queue.put(("log",f"  Org     : {org}","info"))
            self.result_queue.put(("log",f"  ISP     : {isp}","info"))
            self.result_queue.put(("log",f"  Location: {city}, {country}","info"))
            self.result_queue.put(("log",f"  Ports   : {ports}","info"))
            self.result_queue.put(("log",f"  Tags    : {tags}","info"))
            if vulns:
                self.result_queue.put(("log",f"  Shodan CVEs ({len(vulns)}):","warn"))
                for cve_id in list(vulns.keys())[:10]:
                    self.result_queue.put(("log",f"    • {cve_id}","warn"))
            self.result_queue.put(("log","─"*50,"info"))
            # Pop-up summary
            msg = (f"SHODAN — {self.current_ip}\n{'═'*40}\n"
                   f"Org      : {org}\nISP      : {isp}\n"
                   f"Location : {city}, {country}\n"
                   f"Open Ports: {ports}\nTags     : {tags}\n"
                   f"CVEs found: {len(vulns)}\n")
            if vulns:
                msg += "\nCVEs:\n" + "\n".join(f"  {k}" for k in list(vulns.keys())[:15])
            self.root.after(0, lambda: messagebox.showinfo("Shodan Results", msg))
        threading.Thread(target=_run, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    #  NVD CVE AUTO-UPDATE
    # ══════════════════════════════════════════════════════════════════════════
    def _nvd_update_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Update CVE Database from NVD")
        dlg.geometry("480x360"); dlg.configure(bg=BG_DARK)
        dlg.resizable(False,False)
        tk.Label(dlg, text="◈ NVD CVE AUTO-UPDATE", font=self.font_label,
            bg=BG_DARK, fg=ACCENT_CYAN).pack(pady=(14,4), padx=20, anchor="w")
        tk.Label(dlg,
            text=("Fetches latest CVEs from NVD (nvd.nist.gov) and merges them\n"
                  "into the live vulnerability database. Free — no key required.\n"
                  "NVD free rate: 5 requests / 30 seconds (auto-throttled)."),
            font=self.font_mono_sm, bg=BG_DARK, fg=TEXT_SEC, justify="left"
        ).pack(padx=20, anchor="w")
        tk.Label(dlg, text="Keywords to search (one per line):",
            font=self.font_mono_sm, bg=BG_DARK, fg=TEXT_SEC).pack(padx=20, pady=(10,2), anchor="w")
        kw_text = tk.Text(dlg, height=5, bg=BG_CARD, fg=TEXT_PRI,
            insertbackground=ACCENT_CYAN, relief="flat", font=self.font_mono_sm,
            highlightthickness=1, highlightcolor=ACCENT_CYAN, highlightbackground=BORDER)
        kw_text.pack(padx=20, fill="x")
        kw_text.insert("1.0","vsftpd\nOpenSSH\nApache httpd\nnginx\nSamba")
        log_box = tk.Text(dlg, height=5, bg=BG_PANEL, fg=TEXT_SEC,
            font=self.font_mono_sm, relief="flat", state="disabled", padx=6, pady=4)
        log_box.pack(padx=20, pady=(8,0), fill="x")
        log_box.tag_config("ok",    foreground=ACCENT_GRN)
        log_box.tag_config("info",  foreground=ACCENT_CYAN)
        log_box.tag_config("error", foreground=ACCENT_RED)

        def _log_dlg(msg, lvl="info"):
            log_box.config(state="normal")
            log_box.insert("end", msg+"\n", lvl)
            log_box.see("end"); log_box.config(state="disabled")
            self._log(msg, lvl)

        def _run():
            kws = [k.strip() for k in kw_text.get("1.0","end").splitlines() if k.strip()]
            if not kws: return
            btn.config(state="disabled", text="Updating...")
            update_vuln_db_from_nvd(kws, self.nvd_key_var.get(), _log_dlg)
            btn.config(state="normal", text="▶ Fetch & Update")

        btn = tk.Button(dlg, text="▶ Fetch & Update",
            command=lambda: threading.Thread(target=_run,daemon=True).start(),
            bg=ACCENT_CYAN, fg=BG_DARK, font=self.font_btn,
            relief="flat", cursor="hand2", pady=6)
        btn.pack(padx=20, pady=10, fill="x")

    # ══════════════════════════════════════════════════════════════════════════
    #  BRUTE FORCE ENGINE
    # ══════════════════════════════════════════════════════════════════════════
    def _bf_service_changed(self, event=None):
        svc = self.bf_service_var.get()
        if svc == "FTP":             self.bf_port_var.set("21")
        elif svc == "SSH":           self.bf_port_var.set("22")
        elif svc == "HTTP Basic Auth": self.bf_port_var.set("80")

    def _load_wordlist(self, text_widget):
        path = filedialog.askopenfilename(
            filetypes=[("Text files","*.txt"),("All files","*.*")])
        if path:
            try:
                with open(path) as f: words = f.read().strip()
                text_widget.delete("1.0","end")
                text_widget.insert("1.0", words)
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def _start_brute(self):
        if self.is_bruteforcing: return
        if not messagebox.askokcancel("Authorised Use Confirmation",
            "⚠ CONFIRM: You have explicit written permission to test\n"
            "the target system. Unauthorised brute-forcing is illegal.\n\n"
            "Proceed only on systems you own or are authorised to test."
        ): return
        for item in self.bf_tree.get_children(): self.bf_tree.delete(item)
        host  = self.bf_target_var.get().strip()
        svc   = self.bf_service_var.get()
        path  = self.bf_path_var.get().strip() or "/"
        delay = self.bf_delay_var.get()
        try: port = int(self.bf_port_var.get())
        except ValueError: messagebox.showwarning("Input","Invalid port."); return
        users = [u.strip() for u in self.bf_users_text.get("1.0","end").splitlines() if u.strip()]
        pwds  = [p.strip() for p in self.bf_pass_text.get("1.0","end").splitlines() if p.strip()]
        if not users or not pwds:
            messagebox.showwarning("Input","Fill in usernames and passwords."); return
        self.is_bruteforcing = True
        self.bf_start_btn.config(state="disabled"); self.bf_stop_btn.config(state="normal")
        self.bf_progress_var.set(0)
        self.brute_thread = threading.Thread(
            target=self._brute_worker, args=(host,port,svc,users,pwds,delay,path), daemon=True)
        self.brute_thread.start()

    def _stop_brute(self):
        self.is_bruteforcing = False
        self.bf_start_btn.config(state="normal"); self.bf_stop_btn.config(state="disabled")
        self.bf_status_lbl.config(text="Stopped by user.")

    def _brute_worker(self, host, port, svc, users, pwds, delay, http_path):
        total  = len(users)*len(pwds); done = 0; found = 0
        self.brute_queue.put(("bf_progress",0,
            f"Testing {total} combinations on {host}:{port} [{svc}]"))
        for u in users:
            if not self.is_bruteforcing: break
            for pw in pwds:
                if not self.is_bruteforcing: break
                if   svc == "FTP":            res = brute_ftp(host, port, u, pw)
                elif svc == "SSH":            res = brute_ssh(host, port, u, pw)
                elif svc == "HTTP Basic Auth":res = brute_http_basic(host, port, u, pw, http_path)
                else:                         res = {"success":False}
                done += 1
                pct = (done/total)*100
                if res.get("success"): found += 1
                self.brute_queue.put(("bf_row", u, pw, res))
                self.brute_queue.put(("bf_progress", pct,
                    f"Tested {done}/{total} | Found: {found} | {u}:{pw}"))
                if delay > 0: time.sleep(delay)
        self.brute_queue.put(("bf_done",
            f"Complete: {done} attempts | {found} credential(s) found."))

    # ══════════════════════════════════════════════════════════════════════════
    #  SCHEDULER
    # ══════════════════════════════════════════════════════════════════════════
    def _add_schedule(self):
        name   = self.sch_name_var.get().strip()
        target = self.sch_target_var.get().strip()
        if not name or not target:
            messagebox.showwarning("Input","Enter name and target."); return
        try:
            pf = int(self.sch_pfrom_var.get()); pt = int(self.sch_pto_var.get())
            if not (1<=pf<=65535 and 1<=pt<=65535 and pf<=pt): raise ValueError
        except ValueError:
            messagebox.showwarning("Input","Invalid port range."); return
        hrs = self.sch_interval_var.get()
        entry = self.scheduler.add(name, target, pf, pt, hrs)
        self._refresh_schedule_list()
        self._sch_log(f"Scheduled '{name}' → {target} ports {pf}-{pt} every {hrs}h","ok")

    def _scheduler_scan_trigger(self, entry):
        """Called by scheduler timer — run a silent scan."""
        self._sch_log(f"[AUTO] Running '{entry['name']}' on {entry['target']}","info")
        def _run():
            targets = parse_target(entry["target"])
            for host in targets:
                ip, _ = resolve_host(host)
                if not ip: continue
                ports = list(range(entry["port_from"], entry["port_to"]+1))
                found = []
                with ThreadPoolExecutor(max_workers=100) as ex:
                    futs = {ex.submit(scan_port, ip, p, 1.0, True):p for p in ports}
                    for f in as_completed(futs):
                        try:
                            r = f.result()
                            if r.get("state")=="OPEN": found.append(r)
                        except: pass
                self.results.extend(found)
                vuln_c = sum(1 for r in found if r.get("vulnerabilities"))
                self._sch_log(
                    f"[AUTO] '{entry['name']}': {len(found)} open, {vuln_c} vulnerable","ok")
        threading.Thread(target=_run, daemon=True).start()
        self._refresh_schedule_list()

    def _toggle_schedule(self):
        sel = self.sch_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a schedule first."); return
        # Match by name (stored in col 0)
        name = self.sch_tree.item(sel[0],"values")[0]
        for s in self.scheduler.schedules:
            if s["name"] == name:
                new_state = self.scheduler.toggle(s["id"])
                self._sch_log(f"'{name}' {'enabled' if new_state else 'disabled'}","ok")
                self._refresh_schedule_list(); return

    def _remove_schedule(self):
        sel = self.sch_tree.selection()
        if not sel: messagebox.showinfo("Select","Select a schedule first."); return
        name = self.sch_tree.item(sel[0],"values")[0]
        for s in self.scheduler.schedules:
            if s["name"] == name:
                if messagebox.askyesno("Confirm",f"Remove schedule '{name}'?"):
                    self.scheduler.remove(s["id"])
                    self._refresh_schedule_list()
                    self._sch_log(f"Removed '{name}'","warn")
                return

    def _refresh_schedule_list(self):
        for item in self.sch_tree.get_children(): self.sch_tree.delete(item)
        for s in self.scheduler.schedules:
            nr = s["next_run"].strftime("%Y-%m-%d %H:%M") if s["next_run"] else "—"
            lr = s["last_run"].strftime("%Y-%m-%d %H:%M") if s["last_run"] else "Never"
            tag = "enabled" if s["enabled"] else "disabled"
            self.sch_tree.insert("","end", tags=(tag,), values=(
                s["name"], s["target"],
                f"{s['port_from']}-{s['port_to']}",
                f"{s['interval_hrs']}h", nr, lr,
                s["run_count"],
                "ON" if s["enabled"] else "OFF"))

    def _sch_log(self, msg, lvl="info"):
        self.sch_log.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.sch_log.insert("end",f"[{ts}] {msg}\n",lvl)
        self.sch_log.see("end"); self.sch_log.config(state="disabled")

    # ══════════════════════════════════════════════════════════════════════════
    #  HELP
    # ══════════════════════════════════════════════════════════════════════════
    def _show_help(self):
        messagebox.showinfo("Help — PHANTOM SCAN v5.0",
"""PHANTOM SCAN v5.0 — Feature Guide

KEYBOARD SHORTCUTS
  Ctrl+S   Start Scan
  Ctrl+X   Stop Scan
  Ctrl+C   Clear Log
  Ctrl+Q   Quit
  F1       This help

TABS
  Scan Results  — Live port/vuln table; double-click for CVE details
  Topology Map  — Radial node map; click node = details; scroll=zoom
  Brute Force   — Credential tester (authorised testing only)
  Scheduler     — Auto-recurring scans

SCAN TYPES
  TCP Connect   — Standard; no root required; all platforms
  UDP           — Detects UDP services; may have false positives
  Both TCP+UDP  — Comprehensive; slower
  SYN Stealth   — Raw socket; Linux + root only; no handshake

API FEATURES
  Shodan Lookup — IP intelligence from shodan.io (free API key)
  NVD Update    — Fetch latest CVEs from nvd.nist.gov

EXPORT
  JSON  — Machine-readable full report
  CSV   — Spreadsheet-compatible
  TXT   — Client-ready assessment report
  PDF   — Professional PDF (needs: pip install reportlab)

REQUIREMENTS
  Core        — Python 3.8+, stdlib only
  PDF export  — pip install reportlab
  SSH brute   — pip install paramiko

LEGAL NOTICE
  Use only on systems you own or have explicit written permission to test.""")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Windows DPI awareness
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass

    root = tk.Tk()
    app  = PhantomScanApp(root)

    # Centre window
    root.update_idletasks()
    W,H = root.winfo_width(), root.winfo_height()
    x = (root.winfo_screenwidth()  // 2) - (W // 2)
    y = (root.winfo_screenheight() // 2) - (H // 2)
    root.geometry(f"{W}x{H}+{x}+{y}")

    def on_close():
        app.scheduler.stop_all()
        if app.is_scanning:
            if messagebox.askokcancel("Quit","Scan in progress. Quit anyway?"):
                app.is_scanning = False
                root.after(400, root.destroy)
        else:
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
