"""
Packet Sniffer Engine
Handles asynchronous packet capturing using Scapy, manages background worker threads,
tracks real-time capture metrics, provides interface discovery, and includes a built-in
educational simulation mode when Npcap is not available.
"""

import random
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from scapy.all import conf, get_if_list, sniff
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    conf = None
    get_if_list = None
    sniff = None
    IP = TCP = UDP = ICMP = ARP = Ether = Raw = None

from packet_analyzer import analyze_packet, export_packets_to_csv


def is_pcap_supported() -> bool:
    """Check if Npcap/WinPcap driver is loaded and usable."""
    if not SCAPY_AVAILABLE or conf is None:
        return False
    return bool(getattr(conf, "use_pcap", False))


def generate_simulated_packet() -> Any:
    """
    Generate realistic educational synthetic packets for testing
    when Npcap is not installed on the host system.
    """
    choices = ["http", "dns", "ping", "https", "arp"]
    choice = random.choice(choices)
    local_ip = "192.168.1.105"
    gateway_ip = "192.168.1.1"

    if choice == "http":
        src_port = random.randint(49152, 65535)
        web_ip = random.choice(["93.184.216.34", "151.101.1.140", "172.217.16.206"])
        return (
            Ether(src="00:1a:2b:3c:4d:5e", dst="f0:98:38:12:34:56")
            / IP(src=local_ip, dst=web_ip, ttl=64)
            / TCP(sport=src_port, dport=80, flags="PA", seq=random.randint(1000, 90000), ack=random.randint(1000, 90000))
            / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: SnifferDemo/1.0\r\n\r\n")
        )
    elif choice == "https":
        src_port = random.randint(49152, 65535)
        web_ip = random.choice(["142.250.190.46", "104.244.42.1", "13.107.42.16"])
        flags = random.choice(["S", "SA", "A", "PA"])
        return (
            Ether(src="00:1a:2b:3c:4d:5e", dst="f0:98:38:12:34:56")
            / IP(src=local_ip, dst=web_ip, ttl=128)
            / TCP(sport=src_port, dport=443, flags=flags, seq=random.randint(1000, 90000))
            / Raw(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03TLS_CLIENT_HELLO_SIMULATED")
        )
    elif choice == "dns":
        src_port = random.randint(49152, 65535)
        domain = random.choice(["google.com", "github.com", "python.org", "wikipedia.org"])
        return (
            Ether(src="00:1a:2b:3c:4d:5e", dst="f0:98:38:12:34:56")
            / IP(src=local_ip, dst="8.8.8.8", ttl=64)
            / UDP(sport=src_port, dport=53)
            / Raw(f"\x00\x01\x01\x00Standard query A {domain}".encode())
        )
    elif choice == "ping":
        dst_ip = random.choice(["8.8.4.4", "1.1.1.1", gateway_ip])
        icmp_type = random.choice([8, 0])
        return (
            Ether(src="00:1a:2b:3c:4d:5e", dst="f0:98:38:12:34:56")
            / IP(src=local_ip, dst=dst_ip, ttl=54)
            / ICMP(type=icmp_type, code=0)
            / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
        )
    else:  # arp
        return ARP(
            op=random.choice([1, 2]),
            hwsrc="00:1a:2b:3c:4d:5e",
            psrc=local_ip,
            hwdst="00:00:00:00:00:00",
            pdst=gateway_ip,
        )


class PacketSniffer:
    """
    Thread-safe packet sniffer engine using Scapy.
    Captures packets in a background thread, updates live counters, and stores
    analyzed packet summaries in a memory-bounded buffer.
    """

    def __init__(self, max_buffer_size: int = 2500):
        self.max_buffer_size = max_buffer_size
        self._packets: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.is_running = False
        self.selected_interface: Optional[str] = None
        self.protocol_filter: Optional[str] = None  # None / 'all', 'tcp', 'udp', 'icmp'
        self.last_error: Optional[str] = None
        self.start_time: Optional[float] = None
        self.packet_counter = 0

        # Protocol statistics
        self.stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "bytes_total": 0,
        }

    @staticmethod
    def get_available_interfaces() -> List[Dict[str, Any]]:
        """
        Discover available network interfaces using Scapy configuration.
        Returns a structured list with friendly names, descriptions, and IPs.
        Includes a Simulated Traffic mode for educational testing without Npcap.
        """
        has_pcap = is_pcap_supported()
        interfaces: List[Dict[str, Any]] = []

        # Always include Simulated Traffic mode at the top for instant testing
        demo_label = "⚡ Simulated Traffic (Demo Mode)"
        if not has_pcap:
            demo_label += " [Recommended - Npcap not installed]"

        interfaces.append({
            "id": "simulated",
            "name": "Simulated Traffic (Demo Mode)",
            "description": "Built-in realistic network packet generator (No Npcap or Admin privileges required)",
            "ip": "192.168.1.105",
            "label": demo_label,
            "is_simulated": True,
        })

        if not SCAPY_AVAILABLE:
            return interfaces

        try:
            # Query Scapy's interface table
            if hasattr(conf, "ifaces") and conf.ifaces:
                for iface_key, iface_obj in conf.ifaces.items():
                    name = getattr(iface_obj, "name", str(iface_key))
                    description = getattr(iface_obj, "description", "")
                    ip = getattr(iface_obj, "ip", "") or ""

                    # Friendly display label
                    label = name
                    if ip:
                        label += f" ({ip})"
                    if description and description != name:
                        label += f" - {description}"
                    if not has_pcap:
                        label += " [Requires Npcap]"

                    interfaces.append({
                        "id": str(iface_key),
                        "name": str(name),
                        "description": str(description),
                        "ip": str(ip),
                        "label": label,
                        "is_simulated": False,
                    })

            # Fallback to get_if_list() if conf.ifaces was empty
            if len(interfaces) == 1 and get_if_list:
                for if_name in get_if_list():
                    label = str(if_name)
                    if not has_pcap:
                        label += " [Requires Npcap]"
                    interfaces.append({
                        "id": str(if_name),
                        "name": str(if_name),
                        "description": "",
                        "ip": "",
                        "label": label,
                        "is_simulated": False,
                    })
        except Exception as ex:
            interfaces.append({
                "id": "default",
                "name": f"Error scanning interfaces: {str(ex)}",
                "ip": "",
                "description": "Please ensure Npcap is installed.",
                "label": "Default Interface (Error reading adapters)",
                "is_simulated": False,
            })

        return interfaces

    def _packet_callback(self, raw_packet: Any) -> None:
        """Callback executed for each captured or generated packet."""
        with self._lock:
            self.packet_counter += 1
            current_id = self.packet_counter

        # Analyze packet structure
        parsed = analyze_packet(raw_packet, packet_id=current_id)

        # Update protocol counters
        proto = parsed.get("protocol", "").upper()
        pkt_bytes = parsed.get("length", 0)

        with self._lock:
            self.stats["total"] += 1
            self.stats["bytes_total"] += pkt_bytes

            if "TCP" in proto:
                self.stats["tcp"] += 1
            elif "UDP" in proto:
                self.stats["udp"] += 1
            elif "ICMP" in proto:
                self.stats["icmp"] += 1
            else:
                self.stats["other"] += 1

            # Filter checking for packet storage
            matches_filter = True
            if self.protocol_filter and self.protocol_filter.lower() != "all":
                target = self.protocol_filter.upper()
                if target not in proto:
                    matches_filter = False

            if matches_filter:
                self._packets.append(parsed)
                # Keep buffer capped to prevent unbounded memory growth
                if len(self._packets) > self.max_buffer_size:
                    self._packets.pop(0)

    def _simulated_sniff_worker(self) -> None:
        """Simulate realistic network traffic for testing."""
        self.last_error = None
        self.is_running = True
        self.start_time = time.time()

        try:
            while not self._stop_event.is_set():
                pkt = generate_simulated_packet()
                self._packet_callback(pkt)
                # Sleep briefly between synthetic packets (200ms - 600ms)
                sleep_sec = random.uniform(0.2, 0.6)
                if self._stop_event.wait(timeout=sleep_sec):
                    break
        except Exception as ex:
            self.last_error = f"Simulation error: {str(ex)}"
        finally:
            self.is_running = False

    def _sniff_worker(self, iface: Optional[str]) -> None:
        """Worker thread function executing live scapy sniff with fallback."""
        self.last_error = None
        self.is_running = True
        self.start_time = time.time()

        # If simulated mode was requested
        if iface == "simulated":
            self._simulated_sniff_worker()
            return

        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": self._packet_callback,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            }

            if iface and iface not in ("default", "all"):
                sniff_kwargs["iface"] = iface

            # Attempt live sniff
            try:
                sniff(**sniff_kwargs)
            except Exception as initial_err:
                # If layer 2 capture failed due to missing WinPcap/Npcap, try L3 socket fallback
                err_lower = str(initial_err).lower()
                if ("winpcap" in err_lower or "layer 2" in err_lower) and hasattr(conf, "L3socket") and conf.L3socket:
                    sniff_kwargs["L2socket"] = conf.L3socket
                    sniff(**sniff_kwargs)
                else:
                    raise initial_err

        except PermissionError:
            self.last_error = (
                "Permission denied: Packet sniffing requires Administrator privileges on Windows. "
                "Please run PowerShell or Command Prompt as Administrator, or select 'Simulated Traffic (Demo Mode)'."
            )
        except Exception as ex:
            err_msg = str(ex)
            err_lower = err_msg.lower()
            if "winpcap" in err_lower or "npcap" in err_lower or "libpcap" in err_lower or "layer 2" in err_lower or "10013" in err_lower:
                self.last_error = (
                    "Npcap driver not detected on Windows. Live adapter capture requires Npcap. "
                    "Download Npcap from https://npcap.com (check 'Install in WinPcap API-compatible Mode'), "
                    "or select 'Simulated Traffic (Demo Mode)' to test immediately without installing drivers."
                )
            else:
                self.last_error = f"Capture failed: {err_msg}"
        finally:
            self.is_running = False
            self._stop_event.set()

    def start(self, interface: Optional[str] = None, protocol_filter: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Start the packet sniffer on a background thread.
        Returns (success: bool, error_message: Optional[str]).
        """
        if not SCAPY_AVAILABLE:
            return False, "Scapy is not installed. Run: pip install scapy"

        with self._lock:
            if self.is_running:
                return False, "Capture is already running."

            self._stop_event.clear()
            self.selected_interface = interface
            self.protocol_filter = protocol_filter if protocol_filter and protocol_filter.lower() != "all" else None
            self.last_error = None

            self._thread = threading.Thread(
                target=self._sniff_worker,
                args=(interface,),
                daemon=True,
                name="PacketSnifferThread",
            )
            self._thread.start()

        # Brief wait to catch immediate startup errors (e.g. missing Npcap on real adapter)
        time.sleep(0.3)
        if self.last_error:
            return False, self.last_error

        return True, None

    def stop(self) -> Tuple[bool, Optional[str]]:
        """Stop packet capture safely."""
        with self._lock:
            if not self.is_running:
                return True, "Capture already stopped."
            self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)

        self.is_running = False
        return True, None

    def clear(self) -> None:
        """Reset captured packets and counters."""
        with self._lock:
            self._packets.clear()
            self.packet_counter = 0
            self.stats = {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "icmp": 0,
                "other": 0,
                "bytes_total": 0,
            }
            self.last_error = None

    def get_packets(
        self,
        since_id: int = 0,
        limit: int = 150,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve packets newer than since_id, with optional protocol and text search filtering.
        """
        with self._lock:
            packets = self._packets

            if since_id > 0:
                packets = [p for p in packets if p.get("id", 0) > since_id]

            if protocol and protocol.lower() != "all":
                target = protocol.upper()
                packets = [p for p in packets if target in p.get("protocol", "").upper()]

            if search:
                term = search.lower()
                packets = [
                    p for p in packets
                    if (
                        term in p.get("src_ip", "").lower()
                        or term in p.get("dst_ip", "").lower()
                        or term in str(p.get("src_port", "")).lower()
                        or term in str(p.get("dst_port", "")).lower()
                        or term in p.get("protocol", "").lower()
                        or term in p.get("info", "").lower()
                        or term in p.get("payload_preview", "").lower()
                    )
                ]

            return packets[-limit:] if limit > 0 else packets

    def get_all_packets_for_export(self) -> List[Dict[str, Any]]:
        """Return a copy of all currently buffered packets."""
        with self._lock:
            return list(self._packets)

    def get_status(self) -> Dict[str, Any]:
        """Return status snapshot including running state, stats, and active interface."""
        with self._lock:
            uptime = round(time.time() - self.start_time, 1) if (self.is_running and self.start_time) else 0
            return {
                "is_running": self.is_running,
                "interface": self.selected_interface or "Default / All",
                "protocol_filter": self.protocol_filter or "all",
                "stats": dict(self.stats),
                "buffered_packets": len(self._packets),
                "uptime_seconds": uptime,
                "last_error": self.last_error,
                "has_pcap": is_pcap_supported(),
            }


# Standalone CLI mode
def main():
    print("=" * 60)
    print("      BASIC NETWORK SNIFFER - CLI MODE")
    print("=" * 60)

    has_pcap = is_pcap_supported()
    if not has_pcap:
        print("[!] NOTICE: Npcap driver not detected on Windows.")
        print("    Live adapter capture requires Npcap (https://npcap.com).")
        print("    You can use option [0] 'Simulated Traffic (Demo Mode)' to test immediately.\n")

    sniffer = PacketSniffer()
    ifaces = sniffer.get_available_interfaces()
    print("Available Options & Interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"  [{i}] {iface['label']}")

    selected_iface = "simulated" if not has_pcap else None
    if ifaces:
        default_idx = "0"
        choice = input(f"\nSelect interface number [{default_idx}]: ").strip() or default_idx
        if choice.isdigit() and 0 <= int(choice) < len(ifaces):
            selected_iface = ifaces[int(choice)]["id"]

    proto_choice = input("Filter protocol (all / tcp / udp / icmp) [all]: ").strip() or "all"

    print("\nStarting packet capture... Press Ctrl+C to stop.")
    success, err = sniffer.start(interface=selected_iface, protocol_filter=proto_choice)
    if not success:
        print(f"\n[Error] {err}")
        return

    try:
        last_id = 0
        while True:
            time.sleep(0.5)
            new_packets = sniffer.get_packets(since_id=last_id, limit=50)
            for pkt in new_packets:
                last_id = max(last_id, pkt["id"])
                print(f"[{pkt['timestamp']}] {pkt['protocol']:<6} {pkt['src_ip']}:{pkt['src_port'] or '-'} -> {pkt['dst_ip']}:{pkt['dst_port'] or '-'} ({pkt['length']} B) | {pkt['info']}")
                if pkt.get("payload_preview"):
                    print(f"       Payload: {pkt['payload_preview']}")

            status = sniffer.get_status()
            if not status["is_running"] and status["last_error"]:
                print(f"\n[Capture Error] {status['last_error']}")
                break

    except KeyboardInterrupt:
        print("\nStopping capture...")
        sniffer.stop()

    status = sniffer.get_status()
    print("\nCapture Summary:")
    print(f"  Total Packets Captured: {status['stats']['total']}")
    print(f"  TCP: {status['stats']['tcp']} | UDP: {status['stats']['udp']} | ICMP: {status['stats']['icmp']} | Other: {status['stats']['other']}")
    print(f"  Total Volume: {status['stats']['bytes_total']} bytes")

    export_ans = input("\nExport captured packets to CSV? (y/n) [n]: ").strip().lower()
    if export_ans == "y":
        import os
        captures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "captures"))
        os.makedirs(captures_dir, exist_ok=True)
        filename = os.path.join(captures_dir, f"capture_{int(time.time())}.csv")
        export_packets_to_csv(sniffer.get_all_packets_for_export(), filepath=filename)
        print(f"Exported to {filename}")


if __name__ == "__main__":
    main()
