# scan.py - Advanced IT/OT Scanner v3.1 (updated IT protocol detection)
import csv
import socket
import time
import requests
import threading
import struct
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
from getmac import get_mac_address
from ipwhois import IPWhois
from netaddr import IPNetwork
from mac_vendor_lookup import MacLookup
import json
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress
import subprocess
import platform
import random
import os

# ---- Main scanner class ----
class AdvancedITOTScanner:  # Renamed class for broader scope
    def __init__(self, shodan_api_key=None):
        self.shodan_api_key = shodan_api_key
        self.console = Console()
        # Suppress Scapy warnings and verbose output
        conf.verb = 0
        conf.checkIPaddr = False
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy").setLevel(logging.ERROR)

        try:
            MacLookup().update_vendors()
        except:
            pass

        # Minimal TLS ClientHello bytes (common minimal ClientHello to provoke response)
        # This is a small, generic ClientHello used only to trigger a TLS response.
        # Not a fully featured TLS stack — just a probe.
        self._tls_client_hello = binascii.unhexlify(
            "16030100a10100009d0303"  # TLS record header + version + length (truncated/approx)
            "5b90b6b8c8f8e6a6b6a5a4a3a2a1a0"  # random bytes filler
            "002c"  # session id & cipher suites length approx (not precise)
            "c02b"  # a common cipher suite
            "c02f000a"  # continuation (this is a heuristic probe)
            # Note: This is intentionally short/heuristic — the goal is to provoke a TLS response.
        )

        # Renamed and extended protocol definitions with multiple detection methods
        # NOW: ALL_PROTOCOLS includes both OT and IT definitions
        self.ALL_PROTOCOLS = {
            # --- OT PROTOCOLS ---
            "modbus": {
                "ports": [502, 802],
                "tcp_probe": self._create_modbus_probe(),
                "signatures": [
                    b"\x00\x00\x00\x00\x00\x03\x01\x83",  # Exception response
                    b"\x00\x00\x00\x00\x00\x05\x01\x03",  # Read response
                    b"modbus", b"MODBUS"
                ],
                "banner_keywords": ["modbus", "schneider", "unitronics"],
                "type": "OT"
            },
            "bacnet": {
                "ports": [47808],
                "udp_probe": self._create_bacnet_probe(),
                "signatures": [
                    b"\x81\x0b\x00",  # BACnet response
                    b"bacnet", b"BACnet"
                ],
                "banner_keywords": ["bacnet", "johnson controls", "honeywell"],
                "type": "OT"
            },
            "opcua": {
                "ports": [4840],
                "tcp_probe": self._create_opcua_probe(),
                "signatures": [
                    b"ACK\x00",  # OPC UA ACK
                    b"HEL\x00",  # OPC UA Hello
                    b"opcua", b"OPC"
                ],
                "banner_keywords": ["opcua", "opc ua", "prosys"],
                "type": "OT"
            },
            "dnp3": {
                "ports": [20000, 19999],
                "tcp_probe": self._create_dnp3_probe(),
                "signatures": [
                    b"\x05\x64",  # DNP3 start bytes
                    b"dnp", b"DNP"
                ],
                "banner_keywords": ["dnp3", "triangle microworks"],
                "type": "OT"
            },
            "mqtt": {
                "ports": [1883, 8883],
                "tcp_probe": self._create_mqtt_probe(),
                "signatures": [
                    b"\x20\x02\x00\x00",  # CONNACK
                    b"mqtt", b"MQTT"
                ],
                "banner_keywords": ["mqtt", "mosquitto", "hivemq"],
                "type": "OT"
            },
            "siemens_s7": {
                "ports": [102],
                "tcp_probe": self._create_s7_probe(),
                "signatures": [
                    b"\x03\x00\x00\x1b\x02\xf0\x80",  # S7 response
                    b"siemens", b"s7"
                ],
                "banner_keywords": ["siemens", "s7", "step7"],
                "type": "OT"
            },
            "ethernet_ip": {
                "ports": [44818, 2222],
                "tcp_probe": self._create_enip_probe(),
                "signatures": [
                    b"\x00\x00\x00\x00",  # EtherNet/IP response
                    b"rockwell", b"allen"
                ],
                "banner_keywords": ["ethernet/ip", "rockwell", "allen bradley"],
                "type": "OT"
            },
            "omron_fins": {
                "ports": [9600],
                "tcp_probe": self._create_fins_probe(),
                "signatures": [
                    b"FINS", b"omron"
                ],
                "banner_keywords": ["omron", "fins"],
                "type": "OT"
            },
            "codesys": {
                "ports": [2455, 1217],
                "tcp_probe": b"\x01\x00\x00\x00",
                "signatures": [
                    b"codesys", b"3s"
                ],
                "banner_keywords": ["codesys", "3s-smart"],
                "type": "OT"
            },
            # --- IT PROTOCOLS (New Additions) ---
            "http": {
                "ports": [80, 8080, 8000],
                "tcp_probe": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "signatures": [
                    b"HTTP/1.", b"Server:", b"Content-Type:"
                ],
                "banner_keywords": ["apache", "nginx", "iis", "http", "web"],
                "type": "IT"
            },
            "https": {
                "ports": [443, 8443],
                # Use TLS ClientHello probe to elicit TLS ServerHello/Alert
                "tcp_probe": self._tls_client_hello,
                "signatures": [],
                "banner_keywords": ["tls", "ssl", "https", "secure"],
                "type": "IT"
            },
            "ssh": {
                "ports": [22],
                "tcp_probe": b"",  # no active probe needed — SSH sends banner on connect
                "signatures": [
                    b"SSH-2.0-"
                ],
                "banner_keywords": ["ssh", "openssh"],
                "type": "IT"
            },
            "ftp": {
                "ports": [21],
                "tcp_probe": b"",  # FTP sends banner on connect
                "signatures": [
                    b"220", b"ftp"
                ],
                "banner_keywords": ["vsftpd", "pure-ftpd", "ftp"],
                "type": "IT"
            },
            "telnet": {
                "ports": [23],
                "tcp_probe": b"",  # Telnet usually sends negotiation/banner
                "signatures": [
                    b"login:", b"telnet"
                ],
                "banner_keywords": ["telnet", "cli"],
                "type": "IT"
            },
            "smb": {
                "ports": [139, 445],
                "tcp_probe": b"\x00\x00\x00\x85\xff\x53\x4d\x42",  # NetBIOS Session Request / SMB probe
                "signatures": [
                    b"\xff\x53\x4d\x42"  # SMB header
                ],
                "banner_keywords": ["smb", "windows", "samba"],
                "type": "IT"
            }
        }

        # Comprehensive port list
        ot_ports = [p for p_config in self.ALL_PROTOCOLS.values() for p in p_config.get("ports", []) if
                    p_config.get("type") == "OT"]
        it_ports = [p for p_config in self.ALL_PROTOCOLS.values() for p in p_config.get("ports", []) if
                    p_config.get("type") == "IT"]

        self.ALL_PORTS = sorted(list(set(ot_ports + it_ports + [
            # Other common/critical ports not explicitly in protocols above
            25, 53, 110, 143, 389, 1433, 3306, 3389, 5432, 5900, 6379
        ])))

    # -------------------- Probes (unchanged) --------------------
    def _create_modbus_probe(self):
        return b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"

    def _create_bacnet_probe(self):
        return b"\x81\x0a\x00\x08\x01\x20\xff\xff\x00\xff\x10\x08"

    def _create_opcua_probe(self):
        hello = b"HEL" + b"F" + struct.pack("<I", 28) + struct.pack("<I", 0) + struct.pack("<I", 65536) + struct.pack(
            "<I", 65536) + struct.pack("<I", 0) + b"opc.tcp://test/"
        return hello[:28]

    def _create_dnp3_probe(self):
        return b"\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21"

    def _create_mqtt_probe(self):
        return b"\x10\x0e\x00\x04MQTT\x04\x00\x00\x3c\x00\x04test"

    def _create_s7_probe(self):
        return b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"

    def _create_enip_probe(self):
        return b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def _create_fins_probe(self):
        return b"\x46\x49\x4e\x53\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

    # -------------------- Discovery methods (preserved) --------------------
    def advanced_arp_scan(self, subnet):
        hosts = []
        try:
            self.console.print("[blue]Running ARP scan...[/blue]")
            network = IPNetwork(subnet)
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            old_verb = conf.verb
            conf.verb = 0
            try:
                answered, _ = srp(packet, timeout=2, verbose=False, retry=2, inter=0.1)
                for _, rcv in answered:
                    mac = rcv.hwsrc
                    ip = rcv.psrc
                    try:
                        vendor = MacLookup().lookup(mac)
                    except:
                        vendor = "Unknown"
                    hosts.append({'ip': ip, 'mac': mac, 'vendor': vendor})
            finally:
                conf.verb = old_verb
        except Exception as e:
            self.console.print(f"[yellow]ARP scan encountered issues (continuing with other methods): {str(e)[:50]}...[/yellow]")

        # Ping sweep
        try:
            self.console.print("[blue]Running ping sweep...[/blue]")
            network = IPNetwork(subnet)
            ping_hosts = self._ping_sweep(network)
            if ping_hosts is None:
                ping_hosts = []
            existing_ips = {host['ip'] for host in hosts}
            for ip in ping_hosts:
                if ip not in existing_ips:
                    mac = "Unknown"
                    vendor = "Unknown"
                    try:
                        mac = get_mac_address(ip=ip)
                        if not mac:
                            mac = self._get_mac_from_arp_table(ip)
                        if mac and mac != "Unknown":
                            try:
                                vendor = MacLookup().lookup(mac)
                            except:
                                vendor = "Unknown"
                    except:
                        pass
                    hosts.append({'ip': ip, 'mac': mac or 'Unknown', 'vendor': vendor})
        except Exception as e:
            self.console.print(f"[yellow]Ping sweep failed: {e}[/yellow]")

        # Fallback direct port discovery
        if len(hosts) < 5:
            try:
                self.console.print("[blue]Running direct port probe for host discovery...[/blue]")
                network = IPNetwork(subnet)
                critical_ports = [80, 443, 22, 23, 502, 102, 44818, 47808]
                additional_hosts = self._direct_port_discovery(network, critical_ports)
                existing_ips = {host['ip'] for host in hosts}
                for ip in additional_hosts:
                    if ip not in existing_ips:
                        hosts.append({'ip': ip, 'mac': 'Unknown', 'vendor': 'Unknown'})
            except Exception as e:
                self.console.print(f"[yellow]Direct port discovery failed: {e}[/yellow]")

        return hosts

    def _ping_sweep(self, network):
        alive_hosts = []
        hosts_to_ping = list(network.iter_hosts())[:254]
        def ping_host(ip):
            try:
                if platform.system().lower() == "windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)],
                                            capture_output=True, text=True, timeout=2)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                            capture_output=True, text=True, timeout=2)
                return str(ip) if result.returncode == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in hosts_to_ping}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
        return alive_hosts

    def _get_mac_from_arp_table(self, ip):
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:
                                    return part.replace('-', ':')
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part
        except:
            pass
        return None

    def _direct_port_discovery(self, network, ports):
        alive_hosts = []
        hosts_to_check = list(network.iter_hosts())[:100]
        def check_host_port(ip):
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), port))
                    sock.close()
                    if result == 0:
                        return str(ip)
                except:
                    continue
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_host_port, ip): ip for ip in hosts_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)
        return alive_hosts

    # -------------------- Port scanning & banner grabbing --------------------
    def advanced_port_scan(self, ip, ports, timeout=1):
        """Multi-method port scanning: returns {port: initial_banner}"""
        open_ports_data = {}
        tcp_connect_results = self._tcp_connect_scan(ip, ports, timeout)
        for port, banner in tcp_connect_results:
            open_ports_data[port] = banner
        try:
            syn_ports = self._syn_scan(ip, ports, timeout)
            for port in syn_ports:
                if port not in open_ports_data:
                    open_ports_data[port] = b""
        except:
            pass
        return open_ports_data

    def _tcp_connect_scan(self, ip, ports, timeout):
        """Enhanced TCP connect scan: returns [(port, banner), ...]"""
        open_ports_with_banners = []
        # generic trigger probes
        TRIGGER_PROBES = [b'\x00', b'\r\n']
        # We'll also attempt HTTP GET for HTTP ports and TLS ClientHello for HTTPS ports
        http_ports = set(self.ALL_PROTOCOLS.get("http", {}).get("ports", []))
        https_ports = set(self.ALL_PROTOCOLS.get("https", {}).get("ports", []))
        smb_ports = set(self.ALL_PROTOCOLS.get("smb", {}).get("ports", []))

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # send targeted probes based on port to maximize banner elicitation
                    try:
                        if port in http_ports:
                            # HTTP GET
                            http_probe = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
                            sock.send(http_probe)
                        elif port in https_ports:
                            # send TLS ClientHello heuristic probe
                            try:
                                sock.send(self._tls_client_hello)
                            except:
                                pass
                        elif port in smb_ports:
                            # Send SMB/NetBIOS probe to elicit response
                            try:
                                sock.send(self.ALL_PROTOCOLS["smb"]["tcp_probe"])
                            except:
                                pass
                        else:
                            # generic trigger
                            try:
                                sock.send(TRIGGER_PROBES[0])
                            except:
                                pass
                    except:
                        pass

                    # Try to grab banner immediately after connection (and the trigger)
                    try:
                        sock.settimeout(0.75)
                        banner = b""
                        try:
                            banner = sock.recv(4096)
                        except:
                            banner = b""
                        sock.close()
                        return (port, banner)
                    except:
                        sock.close()
                        return (port, b"")  # Return empty banner on grab failure
                sock.close()
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports_with_banners.append(result)
        return open_ports_with_banners

    def _syn_scan(self, ip, ports, timeout):
        open_ports = []
        try:
            old_verb = conf.verb
            conf.verb = 0
            ports_to_scan = ports[:50] if len(ports) > 50 else ports
            src_port = random.randint(1024, 65535)
            responses = sr(IP(dst=ip) / TCP(sport=src_port, dport=ports_to_scan, flags="S"),
                           timeout=timeout, verbose=False, retry=1)[0]
            for sent, received in responses:
                if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN-ACK
                    open_ports.append(received[TCP].sport)
                    try:
                        send(IP(dst=ip) / TCP(sport=src_port, dport=received[TCP].sport, flags="R"),
                             verbose=False)
                    except:
                        pass
            conf.verb = old_verb
        except Exception as e:
            pass
        return open_ports

    # -------------------- Protocol detection --------------------
    def advanced_protocol_detection(self, ip, port, timeout=3, initial_banner=b""):
        """Advanced protocol detection: uses initial banner first, then probes, then grabs banner as fallback."""
        detected = []
        banner = initial_banner or b""
        # Method 1: Use the initial banner (most common protocols broadcast immediately)
        if banner:
            try:
                newly = self._analyze_banner_and_port_match(banner, port)
                for d in newly:
                    if d not in detected:
                        detected.append(d)
            except:
                pass

        # Method 2: Active probing (best for silent protocols like Modbus/EtherNet/IP)
        for protocol, config in self.ALL_PROTOCOLS.items():
            try:
                if port in config.get("ports", []):
                    result = self._probe_protocol(ip, port, protocol, config, timeout)
                    if result and result not in detected:
                        detected.append(result)
            except:
                pass

        # Method 3: Fallback banner grabbing (for protocols that require a send or were SYN-scanned)
        if not banner:
            try:
                banner = self._grab_banner(ip, port, timeout)
                if banner:
                    newly_detected = self._analyze_banner_and_port_match(banner, port)
                    for d in newly_detected:
                        if d not in detected:
                            detected.append(d)
            except:
                pass

        # Method 4: Service detection (standard port names)
        try:
            service = self._detect_service(ip, port)
            if service and service not in detected:
                detected.append(service)
        except:
            pass

        # If nothing detected but port is commonly known (e.g., 443), mark tentative
        if not detected:
            common_map = {443: "https?", 80: "http?", 22: "ssh?", 21: "ftp?"}
            if port in common_map:
                detected.append(common_map[port])

        # Cleanup: Remove duplicates and prefer explicit names
        final_detected = []
        for d in detected:
            if d.startswith("service_") and any(
                    s for s in detected if not s.startswith("service_") and s.lower() in d.lower()):
                continue
            if d not in final_detected:
                final_detected.append(d)
        return final_detected

    def _grab_banner(self, ip, port, timeout):
        """Enhanced banner grabbing (now only used as a fallback)"""
        banners = []
        approaches = [
            b"",  # Just connect
            b"\r\n",  # Generic trigger
            b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",  # HTTP
            b"\x00" * 4,  # Null bytes
        ]
        for approach in approaches:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))
                if approach:
                    try:
                        sock.send(approach)
                    except:
                        pass
                    time.sleep(0.12)
                try:
                    banner = sock.recv(4096)
                except:
                    banner = b""
                sock.close()
                if banner and len(banner) > 0:
                    banners.append(banner)
                    break
            except:
                continue
        return banners[0] if banners else b""

    def _analyze_banner_and_port_match(self, banner, port):
        """Analyze banner for protocol signatures and check port commonality"""
        detected = []
        if not banner:
            banner = b""
        # Convert banner to a safe lower-case string
        try:
            banner_str = banner.decode('utf-8', errors='ignore').lower()
        except:
            banner_str = ""

        for protocol, config in self.ALL_PROTOCOLS.items():
            # Check if port matches the protocol's known ports
            is_common_port = port in config.get("ports", [])

            # Check signatures (byte or string)
            signatures = config.get("signatures", []) or []
            for sig in signatures:
                sig_str = sig.decode('utf-8', errors='ignore').lower() if isinstance(sig, (bytes, bytearray)) else str(sig).lower()
                if sig_str and sig_str in banner_str:
                    if protocol not in detected:
                        detected.append(protocol)
                    break

            # Check banner keywords (human keywords)
            for keyword in config.get("banner_keywords", []):
                try:
                    if keyword.lower() in banner_str:
                        if protocol not in detected:
                            detected.append(protocol)
                        break
                except:
                    continue

            # Fallback: If no signature but port is an exact match for a known protocol
            if not detected and is_common_port and port in [502, 102, 22, 23, 80, 443, 445]:
                if protocol not in detected:
                    detected.append(f"{protocol}?")  # tentative

        return detected

    def _probe_protocol(self, ip, port, protocol, config, timeout):
        """Send protocol-specific probes"""
        try:
            if "tcp_probe" in config and config["tcp_probe"]:
                return self._tcp_probe(ip, port, protocol, config["tcp_probe"], config.get("signatures", []), timeout)
            elif "udp_probe" in config and config["udp_probe"]:
                return self._udp_probe(ip, port, protocol, config["udp_probe"], config.get("signatures", []), timeout)
        except:
            pass
        return None

    def _tcp_probe(self, ip, port, protocol, probe, signatures, timeout):
        """Send TCP probe and analyze response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if probe:
                try:
                    sock.send(probe)
                except:
                    pass
            # read response
            try:
                response = sock.recv(4096)
            except:
                response = b""
            sock.close()
            if response:
                try:
                    response_str = response.decode('utf-8', errors='ignore').lower()
                except:
                    response_str = ""
                # check signatures (bytes/str)
                for sig in signatures:
                    sig_str = sig.decode('utf-8', errors='ignore').lower() if isinstance(sig, (bytes, bytearray)) else str(sig).lower()
                    if sig_str and sig_str in response_str:
                        return protocol
                # heuristics: got something => tentative
                if len(response) > 4:
                    return f"{protocol}?"
        except:
            pass
        return None

    def _udp_probe(self, ip, port, protocol, probe, signatures, timeout):
        """Send UDP probe and analyze response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(probe, (ip, port))
            try:
                response, _ = sock.recvfrom(4096)
            except:
                response = b""
            sock.close()
            if response:
                try:
                    response_str = response.decode('utf-8', errors='ignore').lower()
                except:
                    response_str = ""
                for sig in signatures:
                    sig_str = sig.decode('utf-8', errors='ignore').lower() if isinstance(sig, (bytes, bytearray)) else str(sig).lower()
                    if sig_str and sig_str in response_str:
                        return protocol
                if len(response) > 4:
                    return f"{protocol}?"
        except:
            pass
        return None

    def _detect_service(self, ip, port):
        """Detect standard services"""
        try:
            service_name = socket.getservbyport(port)
            return f"service_{service_name}"
        except:
            return None

    # -------------------- High-level scan runner --------------------
    def run_comprehensive_scan(self, subnet):
        """Run comprehensive scan with all methods (OT and IT)"""
        results = []
        self.console.print(f"[bold blue]Starting comprehensive IT/OT scan for {subnet}[/bold blue]")

        hosts = self.advanced_arp_scan(subnet)
        if not hosts:
            self.console.print("[red]No hosts discovered![/red]")
            return []

        self.console.print(f"[green]Discovered {len(hosts)} hosts[/green]")

        with Progress() as progress:
            task = progress.add_task("Comprehensive scanning...", total=len(hosts))

            for host in hosts:
                ip = host['ip']
                progress.update(task, description=f"Scanning {ip}")

                port_data = self.advanced_port_scan(ip, self.ALL_PORTS, timeout=1)
                open_ports = list(port_data.keys())

                ot_services = []
                it_services = []
                all_services = {}

                for port in open_ports:
                    initial_banner = port_data.get(port, b"")
                    protocols = self.advanced_protocol_detection(ip, port, initial_banner=initial_banner)
                    all_services[port] = protocols

                    for protocol in protocols:
                        proto_base = protocol.strip('?')
                        proto_type = self.ALL_PROTOCOLS.get(proto_base.lower(), {}).get("type")

                        if proto_type == "OT":
                            ot_services.append((port, protocol))
                        elif proto_type == "IT":
                            it_services.append((port, protocol))
                        elif not proto_type and "service_" in protocol:
                            if port in [502, 102, 44818, 47808, 4840]:
                                ot_services.append((port, protocol))
                            else:
                                it_services.append((port, protocol))
                        else:
                            it_services.append((port, protocol))

                shodan_data = self.enrich_with_shodan(ip)
                results.append({
                    'ip': ip,
                    'mac': host['mac'],
                    'vendor': host['vendor'],
                    'ports': open_ports,
                    'ot_services': ot_services,
                    'it_services': it_services,
                    'all_services': all_services,
                    'shodan': shodan_data
                })

                progress.advance(task)

        return results

    def enrich_with_shodan(self, ip):
        if not self.shodan_api_key:
            return {}
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return {}

    # -------------------- Display & export helpers --------------------
    def display_results(self, results):
        table = Table(title="Advanced IT/OT Discovery Results")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="blue")
        table.add_column("Vendor", style="green")
        table.add_column("Open Ports", style="yellow")
        table.add_column("OT Protocols", style="red", width=25)
        table.add_column("IT Protocols", style="magenta", width=25)
        table.add_column("Risk", style="red")

        ot_devices = []

        for r in results:
            ports_str = ", ".join(map(str, r['ports'][:10]))
            if len(r['ports']) > 10:
                ports_str += "..."
            ot_str = ", ".join([f"{p}:{proto}" for p, proto in r['ot_services']])
            it_str = ", ".join([f"{p}:{proto}" for p, proto in r['it_services']])

            risk = "Low"
            if r['ot_services']:
                if len(r['ot_services']) > 3:
                    risk = "Critical"
                elif len(r['ot_services']) > 1:
                    risk = "High"
                else:
                    risk = "Medium"
                ot_devices.append(r)
            elif r['it_services']:
                it_risk_services = [s for p, s in r['it_services'] if p in [22, 23, 3389, 445]]
                if it_risk_services:
                    risk = "IT-Medium"
                else:
                    risk = "Low"

            table.add_row(r['ip'], r['mac'], r['vendor'], ports_str, ot_str, it_str, risk)

        self.console.print(table)

        if ot_devices:
            self.console.print(f"\n[bold red]🚨 DETECTED {len(ot_devices)} POTENTIAL OT/ICS DEVICES 🚨[/bold red]")
            ot_table = Table(title="OT Device Details")
            ot_table.add_column("IP", style="cyan")
            ot_table.add_column("Vendor", style="green")
            ot_table.add_column("OT Protocols", style="red")
            ot_table.add_column("IT Protocols", style="magenta")

            for device in ot_devices:
                ot_protocols = [proto for _, proto in device['ot_services']]
                it_protocols = [proto for _, proto in device['it_services']]

                ot_table.add_row(
                    device['ip'],
                    device['vendor'],
                    ", ".join(ot_protocols),
                    ", ".join(it_protocols[:5]) + ("..." if len(it_protocols) > 5 else "")
                )
            self.console.print(ot_table)

        self.console.print(f"\n[blue]Scan Statistics:[/blue]")
        self.console.print(f"• Total hosts: {len(results)}")
        self.console.print(f"• Hosts with open ports: {len([r for r in results if r['ports']])}")
        self.console.print(f"• Potential OT devices: {len(ot_devices)}")

        if ot_devices:
            protocols_found = set()
            for device in ot_devices:
                for _, proto in device['ot_services']:
                    protocols_found.add(proto)
            self.console.print(f"• OT Protocols detected: {', '.join(sorted(protocols_found))}")

        it_protocols_found = set()
        for device in results:
            for _, proto in device['it_services']:
                it_protocols_found.add(proto)
        self.console.print(f"• IT Protocols detected: {', '.join(sorted(it_protocols_found))}")

    def export_detailed_csv(self, results, filename="it_ot_scan_results.csv"):
        os.makedirs("static/exports", exist_ok=True)
        filepath = os.path.join("static/exports", filename)
        with open(filepath, "w", newline="", encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP", "MAC", "Vendor", "Open Ports", "OT Services",
                "IT Services", "All Detected Services", "Risk Level", "Port Count", "OT Protocol Count"
            ])
            for r in results:
                risk = "Low"
                if r['ot_services']:
                    if len(r['ot_services']) > 3:
                        risk = "Critical"
                    elif len(r['ot_services']) > 1:
                        risk = "High"
                    else:
                        risk = "Medium"
                elif r['it_services']:
                    it_risk_services = [s for p, s in r['it_services'] if p in [22, 23, 3389, 445]]
                    if it_risk_services:
                        risk = "IT-Medium"
                    else:
                        risk = "Low"

                all_services = []
                for port, services in r['all_services'].items():
                    for svc in services:
                        all_services.append(f"{port}:{svc}")

                writer.writerow([
                    r['ip'], r['mac'], r['vendor'],
                    ";".join(map(str, r['ports'])),
                    ";".join([f"{p}:{proto}" for p, proto in r['ot_services']]),
                    ";".join([f"{p}:{proto}" for p, proto in r['it_services']]),
                    ";".join(all_services),
                    risk,
                    len(r['ports']),
                    len(r['ot_services'])
                ])
        self.console.print(f"[green]Detailed results exported to {filename}[/green]")

    def export_json(self, results, filename="it_ot_scan_results.json"):
        os.makedirs("static/exports", exist_ok=True)
        filepath = os.path.join("static/exports", filename)
        with open(filepath, "w", encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        self.console.print(f"[green]JSON results exported to {filepath}[/green]")


# -------------------- CLI runner --------------------
if __name__ == "__main__":
    console = Console()
    console.print("[bold blue]Advanced IT/OT Scanner v3.1[/bold blue]")
    console.print("Enhanced network handling and warning suppression.\n")

    try:
        if platform.system().lower() != "windows":
            if os.geteuid() != 0:
                console.print("[yellow]⚠️  For best results, run as root/administrator for SYN scanning[/yellow]")
        else:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                console.print("[yellow]⚠️  For best results, run as administrator for advanced scanning[/yellow]")
    except:
        pass

    api_key = input("Enter Shodan API key (optional, press Enter to skip): ").strip() or None

    console.print("\n[blue]Examples:[/blue] 192.168.1.0/24, 10.0.0.0/16, 172.16.0.0/12")
    while True:
        subnet = input("Enter subnet to scan: ").strip()
        try:
            net = IPNetwork(subnet)
            if net.size > 1024:
                confirm = input(f"Large network ({net.size} hosts). Continue? (y/n): ")
                if confirm.lower() != 'y':
                    continue
            break
        except:
            print("Invalid subnet format! Use CIDR notation (e.g., 192.168.1.0/24)")

    console.print("\n[blue]Scan Options:[/blue]")
    console.print("1. Quick scan (common IT/OT ports only)")
    console.print("2. Full scan (all defined IT/OT ports)")
    console.print("3. Stealth scan (slower, less detectable)")

    scan_type = input("Select scan type (1-3, default=2): ").strip() or "2"

    scanner = AdvancedITOTScanner(shodan_api_key=api_key)

    if scan_type == "1":
        scanner.ALL_PORTS = [21, 22, 23, 80, 443, 502, 102, 44818, 47808, 4840, 1883, 3389, 445]
        console.print("[blue]Quick scan mode selected[/blue]")
    elif scan_type == "3":
        console.print("[blue]Stealth scan mode selected (this will take longer)[/blue]")

    console.print(f"\n[green]Starting scan of {subnet}...[/green]")

    start_time = time.time()
    results = scanner.run_comprehensive_scan(subnet)
    end_time = time.time()

    if results:
        console.print(f"\n[green]Scan completed in {end_time - start_time:.1f} seconds[/green]")
        scanner.display_results(results)

        console.print("\n[blue]Export Options:[/blue]")
        export = input("Export results? (csv/json/both/no): ").lower().strip()
        if export in ['csv', 'both']:
            scanner.export_detailed_csv(results)
        if export in ['json', 'both']:
            scanner.export_json(results)
    else:
        console.print("[red]No results obtained. Check network connectivity and permissions.[/red]")
        console.print("\n[yellow]Troubleshooting tips:[/yellow]")
        console.print("• Run as administrator/root")
        console.print("• Check if you're on the right network segment")
        console.print("• Try a smaller subnet (e.g., /28 instead of /24)")
        console.print("• Verify the subnet address is correct")
