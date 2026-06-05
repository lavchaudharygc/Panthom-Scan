#!/usr/bin/env python3
"""
PHANTOM SCAN v5.0 — Headless CLI Mode
Use this inside Docker containers or when no display is available.
Usage: python3 phantom_cli.py --target 192.168.1.1 --ports 1-1024
"""
import argparse, json, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from phantom_scan import (scan_port, scan_udp_port, syn_scan_port,
    resolve_host, detect_os_hint, parse_target, detect_vulnerabilities,
    COMMON_SERVICES, generate_pdf_report)
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.text    import Text
    console = Console()
    RICH = True
except ImportError:
    RICH = False
    class _C:
        def print(self, *a, **kw): print(*a)
        def rule(self, *a, **kw): print("─"*60)
    console = _C()

def banner():
    console.print("[bold cyan]◈ PHANTOM SCAN v5.0[/bold cyan] — Headless CLI Mode", style="bold")
    console.print("[dim]Advanced Port Scanner + Vulnerability Assessment[/dim]")
    console.rule()

def run_scan(args):
    if not RICH:
        print("\n[PHANTOM SCAN v5.0 CLI]\n" + "─"*50)

    targets = parse_target(args.target)
    p_from, p_to = map(int, args.ports.split("-"))
    results = []; vuln_count = 0; t0 = time.time()

    for host in targets[:5]:   # CLI: limit to 5 hosts for safety
        ip, hostname = resolve_host(host)
        if not ip:
            console.print(f"[red]Cannot resolve: {host}[/red]"); continue
        console.print(f"\n[cyan]Target:[/cyan] {host} → {ip} ({hostname})")
        if not args.no_os:
            os_h = detect_os_hint(ip)
            console.print(f"[yellow]OS Hint:[/yellow] {os_h}")

        ports = list(range(p_from, p_to+1))
        console.print(f"[dim]Scanning {len(ports)} ports with {args.threads} threads...[/dim]")

        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            futs = {ex.submit(scan_port, ip, p, args.timeout, not args.no_banner):p
                    for p in ports}
            done = 0
            for f in as_completed(futs):
                done += 1
                if done % 200 == 0:
                    pct = done/len(ports)*100
                    console.print(f"[dim]  Progress: {pct:.0f}% ({done}/{len(ports)})[/dim]")
                try:
                    r = f.result()
                    if r.get("state") == "OPEN":
                        results.append(r)
                        vulns = r.get("vulnerabilities",[])
                        if vulns:
                            vuln_count += 1
                            for v in vulns:
                                console.print(f"  [bold red][VULN][/bold red] Port {r['port']} "
                                    f"{r.get('service','')} — {v['cve']} [{v['severity']}]")
                        else:
                            console.print(f"  [green][OPEN][/green] Port {r['port']} "
                                f"{r.get('service','')} {r.get('banner','')[:50]}")
                except: pass

    elapsed = round(time.time()-t0, 2)
    console.rule()
    console.print(f"[bold]Scan complete:[/bold] {elapsed}s | "
        f"[green]{len(results)} open[/green] | [red]{vuln_count} vulnerable[/red]")

    # Save report
    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            data = {"target":args.target,"scan_time":datetime.now().isoformat(),
                    "results":results}
            with open(args.output,"w") as f: json.dump(data,f,indent=2)
        elif ext == ".pdf":
            ok, msg = generate_pdf_report(results, args.target, args.output)
            if not ok: console.print(f"[red]PDF error: {msg}[/red]")
        else:
            with open(args.output,"w") as f:
                f.write(f"PHANTOM SCAN CLI Report\nTarget: {args.target}\n"
                    f"Date: {datetime.now().isoformat()}\n{'─'*50}\n")
                for r in results:
                    f.write(f"Port {r['port']:5d} {r['state']:15s} {r.get('service',''):20s} "
                        f"{r.get('banner','')[:60]}\n")
        console.print(f"[green]Report saved: {args.output}[/green]")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Phantom Scan v5.0 CLI")
    ap.add_argument("--target",   required=True,  help="Host/IP/CIDR to scan")
    ap.add_argument("--ports",    default="1-1024",help="Port range e.g. 1-65535")
    ap.add_argument("--threads",  type=int, default=200, help="Concurrent threads")
    ap.add_argument("--timeout",  type=float, default=1.0, help="Per-port timeout sec")
    ap.add_argument("--output",   default="", help="Save report (.json/.txt/.pdf)")
    ap.add_argument("--no-banner",action="store_true", help="Skip banner grabbing")
    ap.add_argument("--no-os",    action="store_true", help="Skip OS detection")
    args = ap.parse_args()
    banner(); run_scan(args)
