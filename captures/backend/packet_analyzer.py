"""
Packet Analyzer Module
Responsible for dissecting network packets, extracting protocol headers,
formatting human-readable packet details, and safely preparing packet data.
"""

import csv
import io
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# Scapy layer imports
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Packet, Raw
except ImportError:
    # Graceful fallback if scapy is being loaded or mocked
    IP = TCP = UDP = ICMP = IPv6 = ARP = Ether = Raw = Packet = None  # type: ignore


# Common ICMP types mapping for educational understanding
ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# Common Well-Known Ports for quick context in UI
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5353: "mDNS",
    8080: "HTTP-Proxy",
}


def safe_decode_payload(raw_bytes: bytes, max_len: int = 60) -> str:
    """
    Safely convert raw payload bytes to a sanitized ASCII preview.
    Replaces non-printable bytes with '.' and prevents XSS or control code injection.
    """
    if not raw_bytes:
        return ""
    
    snippet = raw_bytes[:max_len]
    sanitized = []
    for byte in snippet:
        # Printable ASCII range 32 (space) to 126 (~)
        if 32 <= byte <= 126:
            char = chr(byte)
            # Avoid direct HTML special characters in string representation
            if char == "<":
                sanitized.append("&lt;")
            elif char == ">":
                sanitized.append("&gt;")
            elif char == "&":
                sanitized.append("&amp;")
            else:
                sanitized.append(char)
        else:
            sanitized.append(".")
    
    result = "".join(sanitized)
    if len(raw_bytes) > max_len:
        result += f" ... (+{len(raw_bytes) - max_len} bytes)"
    return result


def get_hex_preview(raw_bytes: bytes, max_len: int = 32) -> str:
    """Return a space-separated hex representation of raw bytes."""
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:max_len]
    hex_str = " ".join(f"{b:02X}" for b in snippet)
    if len(raw_bytes) > max_len:
        hex_str += " ..."
    return hex_str


def get_port_service(port: Optional[int]) -> Optional[str]:
    """Return a well-known service name if recognized, else None."""
    if port is None:
        return None
    return WELL_KNOWN_PORTS.get(port)


def get_tcp_flags_description(tcp_layer: Any) -> str:
    """Extract and format active TCP control flags."""
    if not hasattr(tcp_layer, "flags"):
        return ""
    flags = tcp_layer.flags
    flag_names = []
    # Scapy flags representation
    flag_map = [
        ("S", "SYN"),
        ("A", "ACK"),
        ("F", "FIN"),
        ("R", "RST"),
        ("P", "PSH"),
        ("U", "URG"),
        ("E", "ECE"),
        ("C", "CWR"),
    ]
    str_flags = str(flags)
    for code, name in flag_map:
        if code in str_flags:
            flag_names.append(name)
    return "[" + ", ".join(flag_names) + "]" if flag_names else str(flags)


def analyze_packet(packet: Any, packet_id: int = 1) -> Dict[str, Any]:
    """
    Inspect a network packet and extract comprehensive, structured metadata.
    Handles IPv4, IPv6, ARP, TCP, UDP, ICMP, and non-IP packets safely without crashing.
    """
    # Fallback default packet structure
    pkt_len = len(packet) if hasattr(packet, "__len__") else 0
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S.%f")[:-3]

    result: Dict[str, Any] = {
        "id": packet_id,
        "timestamp": time_str,
        "raw_time": time.time(),
        "length": pkt_len,
        "protocol": "Unknown",
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "src_port": None,
        "dst_port": None,
        "src_service": None,
        "dst_service": None,
        "info": "",
        "payload_preview": "",
        "payload_hex": "",
        "details": {}
    }

    if packet is None:
        result["info"] = "Empty or null packet"
        result["protocol"] = "Non-IP"
        return result

    if not hasattr(packet, "__contains__"):
        result["info"] = "Invalid packet object"
        result["protocol"] = "Non-IP"
        return result

    try:
        # Check for Ethernet / Data Link Layer
        if Ether and Ether in packet:
            ether = packet[Ether]
            result["details"]["src_mac"] = getattr(ether, "src", "N/A")
            result["details"]["dst_mac"] = getattr(ether, "dst", "N/A")
    except Exception:
        pass

    # 1. ARP Packet
    if ARP and ARP in packet:
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["src_ip"] = getattr(arp, "psrc", "N/A")
        result["dst_ip"] = getattr(arp, "pdst", "N/A")
        op_name = "Request" if getattr(arp, "op", 0) == 1 else "Reply" if getattr(arp, "op", 0) == 2 else f"Op={getattr(arp, 'op', 0)}"
        result["info"] = f"ARP {op_name}: Who has {result['dst_ip']}? Tell {result['src_ip']}" if getattr(arp, "op", 0) == 1 else f"ARP {op_name}: {result['src_ip']} is at {getattr(arp, 'hwsrc', 'N/A')}"
        return result

    # 2. IPv4 Packet
    has_ip = False
    if IP and IP in packet:
        has_ip = True
        ip_layer = packet[IP]
        result["src_ip"] = str(getattr(ip_layer, "src", "N/A"))
        result["dst_ip"] = str(getattr(ip_layer, "dst", "N/A"))
        result["details"]["ttl"] = getattr(ip_layer, "ttl", None)
        result["details"]["ip_version"] = 4
    elif IPv6 and IPv6 in packet:
        has_ip = True
        ip_layer = packet[IPv6]
        result["src_ip"] = str(getattr(ip_layer, "src", "N/A"))
        result["dst_ip"] = str(getattr(ip_layer, "dst", "N/A"))
        result["details"]["ip_version"] = 6

    # 3. Transport Layer Analysis
    if TCP and TCP in packet:
        tcp = packet[TCP]
        result["protocol"] = "TCP"
        result["src_port"] = int(getattr(tcp, "sport", 0))
        result["dst_port"] = int(getattr(tcp, "dport", 0))
        result["src_service"] = get_port_service(result["src_port"])
        result["dst_service"] = get_port_service(result["dst_port"])
        
        flags_desc = get_tcp_flags_description(tcp)
        seq = getattr(tcp, "seq", 0)
        ack = getattr(tcp, "ack", 0)
        service_label = result["dst_service"] or result["src_service"] or ""
        service_info = f" ({service_label})" if service_label else ""
        result["info"] = f"TCP {result['src_port']} -> {result['dst_port']}{service_info} {flags_desc} Seq={seq} Ack={ack}"
        result["details"]["tcp_flags"] = flags_desc
        result["details"]["seq"] = seq
        result["details"]["ack"] = ack

    elif UDP and UDP in packet:
        udp = packet[UDP]
        result["protocol"] = "UDP"
        result["src_port"] = int(getattr(udp, "sport", 0))
        result["dst_port"] = int(getattr(udp, "dport", 0))
        result["src_service"] = get_port_service(result["src_port"])
        result["dst_service"] = get_port_service(result["dst_port"])

        service_label = result["dst_service"] or result["src_service"] or ""
        service_info = f" ({service_label})" if service_label else ""
        udp_len = getattr(udp, "len", pkt_len)
        result["info"] = f"UDP {result['src_port']} -> {result['dst_port']}{service_info} Len={udp_len}"
        result["details"]["udp_len"] = udp_len

    elif ICMP and ICMP in packet:
        icmp = packet[ICMP]
        result["protocol"] = "ICMP"
        icmp_type = getattr(icmp, "type", None)
        icmp_code = getattr(icmp, "code", 0)
        type_name = ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}")
        result["info"] = f"ICMP {type_name} (type={icmp_type}, code={icmp_code})"
        result["details"]["icmp_type"] = icmp_type
        result["details"]["icmp_code"] = icmp_code

    elif has_ip:
        # Other IP protocol (e.g. IGMP, GRE, ESP, OSPF, etc.)
        proto_num = getattr(ip_layer, "proto", "Unknown") if IP and IP in packet else getattr(ip_layer, "nh", "Unknown")
        result["protocol"] = f"IP (proto {proto_num})"
        result["info"] = f"IP Protocol {proto_num}"

    else:
        # Non-IP packets
        result["protocol"] = "Non-IP"
        summary = packet.summary() if hasattr(packet, "summary") else "Non-IP packet"
        result["info"] = summary

    # 4. Safe Payload Extraction
    if Raw and Raw in packet:
        raw_payload = bytes(packet[Raw].load)
        result["payload_preview"] = safe_decode_payload(raw_payload, max_len=50)
        result["payload_hex"] = get_hex_preview(raw_payload, max_len=24)
        result["details"]["payload_bytes_len"] = len(raw_payload)

    return result


def export_packets_to_csv(packets: List[Dict[str, Any]], filepath: Optional[str] = None) -> Union[str, io.StringIO]:
    """
    Export captured packet list to CSV format.
    If filepath is provided, writes to the file and returns filepath.
    If filepath is None, returns a StringIO object containing the CSV text.
    """
    fieldnames = [
        "id",
        "timestamp",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length",
        "info",
        "payload_preview",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()

    for pkt in packets:
        # Clean null values to empty strings or clean representations
        row = {
            "id": pkt.get("id", ""),
            "timestamp": pkt.get("timestamp", ""),
            "protocol": pkt.get("protocol", ""),
            "src_ip": pkt.get("src_ip", ""),
            "src_port": pkt.get("src_port") if pkt.get("src_port") is not None else "",
            "dst_ip": pkt.get("dst_ip", ""),
            "dst_port": pkt.get("dst_port") if pkt.get("dst_port") is not None else "",
            "length": pkt.get("length", 0),
            "info": pkt.get("info", ""),
            "payload_preview": pkt.get("payload_preview", ""),
        }
        writer.writerow(row)

    if filepath:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            f.write(output.getvalue())
        return filepath

    return output
