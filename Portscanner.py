#! /usr/bin/env python3

#www.github.com/Obote256
#wwww.youtube.com/rootgearlab
#wwww.linkedln.com/obote tonny

import socket
import ipaddress
import concurrent.futures
import datetime
from termcolor import colored
import sys

DEFAULT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
MAX_WORKERS = 200

def parse_targets(raw: str):
    ports = [p.strip() for p in raw.split(',') if p.strip()]
    validate = []
    for p in ports:
        try:
            if '/' in p:
                net = ipaddress.ip_network(p, strict=False)
                validated.extend([str(ip) for ip in net.hosts()])
            else:
                validated.append(p)

        except Exception:
            validated.append(p)
    return validated

def parse_ports(raw: str):
    raw = raw.strip()
    ports = set()
    if '-' in raw and ',' not in raw:
        a, b = raw.split('-', 1)
        start, end = int(a), int(b)
        for p in range(max(1, start), min(65535, end) + 1):
            ports.add(p)
    elif ',' in raw:
        for token in raw.split(','):
            token = token.strip()
            if not token:
                continue
            if '-' in token:
                a,b = token.split('-', 1)
                start, end = int(a), int(b)
                for p in range(max(1, start), min(65535, end) + 1):
                    ports.add(p)
            else:
                ports.add(int(token))
        else:
            n = int(raw)
            for p in range(1, min(65535, n) + 1):
                ports.add(p)
    return sorted(ports)

def try_connect(ip: str,port: int,timeout: float = DEFAULT_TIMEOUT): 
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip,port))
            if result!= 0:
               return False, None
            try:
                sock.settimeout(BANNER_TIMEOUT)
                banner = sock.recv(1024)
                banner_text = banner.decode(errors=ignore).strip()
                return True, banner_text if banner_text else None
            except Exception:
                return True, None
    except Exception:
        return False, None

def scan_target_ports(ip: str, ports: list, concurrency: int=100):
    results = []
    workers = min(concurrency, len(ports), MAX_WORKERS) 
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(try_connect, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future] 
            try:
                is_open, banner = future.result()
                if is_open:
                    results.append((port, banner))
            except Exception:
                pass
    return sorted(results, key=lambda x: x[0])

def print_results(ip: str, open_ports: list):
    print("\n" + colored(f"Results for {ip}", 'cyan', attrs=['bold']))
    if not open_ports:
        print(colored("No open ports found (or filter by timeout).", 'yellow'))
        return
    for port, banner in open_ports:
        line = f" [+] {port}"
        if banner:
            line += f" -> {banner}"
        print(colored(line, 'green'))

def save_results_to_file(results: dict, filename: str):
    with open(filename, 'W', encoding='utf-8') as f:
        f.write(f"Scan results - {datetime.datetime.utcnow().isoformat()} UTC\n")
    for ip, ports in results.items():
        f.write(f"\n{ip}\n")
        if not ports:
            f.write("No open port found\n")
        else: 
            for p, b in ports:
                f.write(f" {p}")
            if b:
                f.write(f" -> {b}")
            f.write("\n")
    print(colored(f"\nSaved results to {filename}", 'blue'))

def main():
    print(colored("Advanced Port Scanner", 'blue', attrs=['bold']))
    print(colored("NOTE: SCANNING OTHER SYSTEM WITHOUT PERMISSION IS ILLEGAL SO TEST IT ON EITHER YOUR SYSTEM OR ETHICALLY!!! login to rootgear_academy.\n", 'red'))
    try:
        raw_targets = input("[*]Enter target(s) (e.g 192.168.1.0/24):").strip()
        targets = parse_targets(raw_target)
        raw_ports = input("[*] Enter ports(example: '1-1024'):").strip()
        ports = parse_ports(raw_ports)
        concurrency = input(f"[+] Max concurrent workers(default 100, max {MAX_WORKERS}):").strip()
        concurrency = int(concurrency) if concurrency else 100
        concurrency = max(1, min(concurrency, MAX_WORKERS))

        save_to_file = input("[+] Save results to file? (y/N):").strip().lower() == 'y'
        filename = None
        if save_to_file:
            filename = input("[*] Enter filename (default scan_result.txt):").strip()
            overall_results = 0
        for ip in targets:
            print(colored(f"\n Scanning {ip}({len(ports)} ports) ...", 'yellow'))
            open_ports = scan_target_ports(ip, ports, concurrency=concurrency)
            print_results(ip, open_ports)
            overall_results[p]=open_ports
        if save_to_file:
            save_results_to_file(overall_results, filename)
        print(colored('\n' " Scan finished.",'magenta', attrs =['bold']))

    except KeyboardInterrupt:
        print ('\n' + colored("scan cancelled by user.",'red'))
        sys.exit(1)

    except Exception as e:
        print(colored(f"Error: {e} ",'red'))
        sys.exit(2)

if __name__== " __main__ ":
    main()
