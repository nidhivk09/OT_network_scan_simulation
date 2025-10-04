#!/usr/bin/env python3
import socket
import time
import random
import os
import argparse
from concurrent.futures import ThreadPoolExecutor
from scapy.all import conf, sr1, ARP
from getmac import get_mac_address
from netaddr import IPNetwork
from mac_vendor_lookup import MacLookup
from rich.console import Console
from rich.table import Table
from rich.progress import Progress


from pymodbus.client.sync import ModbusTcpClient  
import paho.mqtt.client as mqtt_client
import requests


# ===========================
# Advanced IT/OT Scanner
# ===========================
class AdvancedITOTScanner:
    def __init__(self):
        self.console = Console()
        conf.verb = 0
        conf.checkIPaddr = False
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("pymodbus").setLevel(logging.WARNING)
        # --- Shared state for MQTT callback ---
        self.mqtt_connection_result = {"status": None}
        try:
            MacLookup().update_vendors()
        except Exception:
            pass


    def _on_connect_v2(self, client, userdata, flags, reason_code, properties):
        self.mqtt_connection_result["status"] = True

    def _verify_modbus(self, host: str, port: int) -> bool:
        client = ModbusTcpClient(host, port, timeout=2)
        try:
            if not client.connect(): return False
            client.read_holding_registers(address=0, count=1, unit=1)
            return True
        except Exception:
            return False
        finally:
            if client.is_socket_open(): client.close()

    def _verify_mqtt(self, host: str, port: int) -> bool:
        self.mqtt_connection_result["status"] = None
        client_id = f'verifier-{random.randint(0, 1000)}'
        client = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2, client_id=client_id)
        client.on_connect = self._on_connect_v2
        try:
            client.connect(host, port, 60)
            client.loop_start()
            time.sleep(1)
            client.loop_stop()
            client.disconnect()
            return self.mqtt_connection_result["status"] or False
        except Exception:
            return False

    def _verify_http(self, host: str, port: int) -> bool:
        url = f"http://{host}:{port}"
        try:
            response = requests.get(url, timeout=2)
            return response.ok
        except requests.exceptions.RequestException:
            return False

    
    def lookup_vendor(self, mac):
        try:
            return MacLookup().lookup(mac)
        except Exception:
            return "Unknown"

    def advanced_arp_scan(self, subnet):
        # (This is your original ARP scan method, unchanged)
        hosts = []
        try:
            ans, unans = sr1(ARP(pdst=subnet), timeout=5, verbose=0, multi=True)
            for s, r in ans:
                mac = r.sprintf(r"%ARP.hwsrc%")
                ip = r.sprintf(r"%ARP.psrc%")
                vendor = self.lookup_vendor(mac)
                hosts.append({'ip': ip, 'mac': mac, 'vendor': vendor})
        except Exception as e:
            self.console.print(f"[red]ARP Scan failed: {e}. Ensure you run with sudo/root privileges.[/red]")
        return hosts

    def advanced_port_scan(self, ip, ports, timeout=2):
        # (This is your original port scan method, unchanged)
        open_ports = []

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, ports)
        return sorted(open_ports)

    
    def run_comprehensive_scan(self, subnet, timeout=2):
        results = []
        self.console.print(f"[bold blue]Starting comprehensive IT/OT scan for {subnet}[/bold blue]")
        hosts = self.advanced_arp_scan(subnet)
        if not hosts:
            self.console.print(
                "[red]No hosts discovered via ARP. Ensure you are on the correct network and running with sudo.[/red]")
            return []

        self.console.print(f"[green]Discovered {len(hosts)} hosts via ARP. Now scanning ports...[/green]")
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning hosts...", total=len(hosts))
            for host in hosts:
                ip = host['ip']
                progress.update(task, description=f"Scanning {ip}")
                all_ports_to_scan = list(range(1, 1025)) + [1883, 8085]
                open_ports = self.advanced_port_scan(ip, sorted(list(set(all_ports_to_scan))), timeout=timeout)
                verified_protocols = {}
                if 502 in open_ports and self._verify_modbus(ip, 502):
                    verified_protocols[502] = 'MODBUS'
                if 1883 in open_ports and self._verify_mqtt(ip, 1883):
                    verified_protocols[1883] = 'MQTT'
                if 8085 in open_ports and self._verify_http(ip, 8085):
                    verified_protocols[8085] = 'HMI (HTTP)'

                results.append({'ip': ip, 'mac': host.get('mac'), 'vendor': host.get('vendor'),
                                'verified_protocols': verified_protocols})
                progress.advance(task)
        return results

    
    def run_local_lab_scan(self):
        results = []
        self.console.print("[bold blue]Starting targeted scan on localhost for Docker lab[/bold blue]")
        targets = {
            'Modbus PLC': {'port': 502, 'verifier': self._verify_modbus},
            'MQTT Broker': {'port': 1883, 'verifier': self._verify_mqtt},
            'HMI Panel': {'port': 8085, 'verifier': self._verify_http},
        }
        with Progress() as progress:
            task = progress.add_task("[cyan]Verifying services...", total=len(targets))
            for name, config in targets.items():
                host = 'localhost'
                port = config['port']
                progress.update(task, description=f"Verifying {name}...")
                is_detected = config['verifier'](host, port)
                results.append({'service': name, 'target': f"{host}:{port}", 'detected': is_detected})
                progress.advance(task)
        return results

   
    def display_comprehensive_results(self, results):
        table = Table(title="Comprehensive Subnet Scan Results")
        table.add_column("IP", style="cyan")
        table.add_column("MAC / Vendor", style="blue")
        table.add_column("Verified OT/ICS Protocols", style="bold red")
        for r in results:
            if not r['verified_protocols']: continue
            vendor = self.lookup_vendor(r['mac']) if r['mac'] else 'N/A'
            mac_vendor_str = f"{r['mac']}\n[green]{vendor}[/green]"
            verified_str = "\n".join([f"{p}: {proto}" for p, proto in r['verified_protocols'].items()])
            table.add_row(r['ip'], mac_vendor_str, verified_str)
        self.console.print(table)

   
    def display_local_lab_results(self, results):
        table = Table(title="Local Lab Discovery Summary")
        table.add_column("Service", style="cyan", justify="right")
        table.add_column("Target", style="blue")
        table.add_column("Status", style="bold")
        for r in results:
            status = "✅ Detected" if r['detected'] else "❌ Not Found"
            table.add_row(r['service'], r['target'], status)
        self.console.print(table)


# --------------------------
# CLI / Runner
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="Advanced IT/OT Scanner")
    parser.add_argument("--subnet", "-s", type=str, default="172.20.0.0/24", help="Subnet to scan")
    parser.add_argument("--timeout", "-t", type=int, default=1, help="Port scan timeout (seconds)")
    parser.add_argument("--local-lab", action="store_true",
                        help="Run a quick, targeted scan on localhost for the Docker lab")
    args = parser.parse_args()

    scanner = AdvancedITOTScanner()

    
    if args.local_lab:
        
        results = scanner.run_local_lab_scan()
        scanner.display_local_lab_results(results)
    else:
       
        if os.geteuid() != 0 and platform.system() != "Windows":
            print("Subnet scan uses raw sockets and requires root privileges.")
            print("Please run with 'sudo' or use the '--local-lab' flag for a targeted scan.")
            return
        results = scanner.run_comprehensive_scan(args.subnet, timeout=args.timeout)
        if results:
            scanner.display_comprehensive_results(results)


if __name__ == "__main__":
    main()
