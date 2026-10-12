"""
Automated Test Suite for Packet Analyzer
Uses synthetic packets created via Scapy to verify parsing, protocol detection,
safe payload sanitation, and CSV exporting without needing live traffic or admin privileges.
"""

import io
import os
import sys
import unittest

# Add backend directory to sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "captures", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from packet_analyzer import (
    analyze_packet,
    export_packets_to_csv,
    get_hex_preview,
    safe_decode_payload,
)


class TestPacketAnalyzer(unittest.TestCase):
    """Unit tests for packet analyzer functions."""

    def test_tcp_packet_extraction(self):
        """Test extraction of IPv4 and TCP header fields."""
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
            / TCP(sport=54321, dport=80, flags="S", seq=1000)
            / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )

        result = analyze_packet(pkt, packet_id=101)

        self.assertEqual(result["id"], 101)
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["src_ip"], "192.168.1.50")
        self.assertEqual(result["dst_ip"], "93.184.216.34")
        self.assertEqual(result["src_port"], 54321)
        self.assertEqual(result["dst_port"], 80)
        self.assertEqual(result["dst_service"], "HTTP")
        self.assertIn("SYN", result["details"]["tcp_flags"])
        self.assertEqual(result["details"]["seq"], 1000)
        self.assertIn("GET / HTTP/1.1", result["payload_preview"])

    def test_udp_packet_extraction(self):
        """Test extraction of IPv4 and UDP header fields."""
        pkt = (
            IP(src="10.0.0.15", dst="8.8.8.8")
            / UDP(sport=51234, dport=53)
            / Raw(b"\x00\x01\x01\x00DNS_QUERY_DATA")
        )

        result = analyze_packet(pkt, packet_id=102)

        self.assertEqual(result["id"], 102)
        self.assertEqual(result["protocol"], "UDP")
        self.assertEqual(result["src_ip"], "10.0.0.15")
        self.assertEqual(result["dst_ip"], "8.8.8.8")
        self.assertEqual(result["src_port"], 51234)
        self.assertEqual(result["dst_port"], 53)
        self.assertEqual(result["dst_service"], "DNS")
        self.assertIn("53", result["info"])

    def test_icmp_packet_extraction(self):
        """Test extraction of ICMP Echo Request and Reply."""
        # Echo Request (type 8, code 0)
        echo_req = (
            IP(src="192.168.1.10", dst="192.168.1.1")
            / ICMP(type=8, code=0)
            / Raw(b"ping_payload_12345")
        )
        result_req = analyze_packet(echo_req, packet_id=103)
        self.assertEqual(result_req["protocol"], "ICMP")
        self.assertEqual(result_req["src_ip"], "192.168.1.10")
        self.assertEqual(result_req["dst_ip"], "192.168.1.1")
        self.assertIn("Echo Request", result_req["info"])
        self.assertEqual(result_req["details"]["icmp_type"], 8)

        # Echo Reply (type 0, code 0)
        echo_reply = (
            IP(src="192.168.1.1", dst="192.168.1.10")
            / ICMP(type=0, code=0)
        )
        result_reply = analyze_packet(echo_reply, packet_id=104)
        self.assertEqual(result_reply["protocol"], "ICMP")
        self.assertIn("Echo Reply", result_reply["info"])

    def test_ipv6_packet_handling(self):
        """Test handling of IPv6 packets."""
        pkt = (
            IPv6(src="2001:db8::1", dst="2001:db8::2")
            / TCP(sport=443, dport=55123, flags="A")
        )
        result = analyze_packet(pkt, packet_id=105)
        self.assertEqual(result["protocol"], "TCP")
        self.assertEqual(result["src_ip"], "2001:db8::1")
        self.assertEqual(result["dst_ip"], "2001:db8::2")
        self.assertEqual(result["src_port"], 443)
        self.assertEqual(result["src_service"], "HTTPS")

    def test_arp_packet_handling(self):
        """Test extraction of ARP requests and replies."""
        arp_pkt = ARP(
            op=1,
            hwsrc="00:11:22:33:44:55",
            psrc="192.168.1.20",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
        result = analyze_packet(arp_pkt, packet_id=106)
        self.assertEqual(result["protocol"], "ARP")
        self.assertEqual(result["src_ip"], "192.168.1.20")
        self.assertEqual(result["dst_ip"], "192.168.1.1")
        self.assertIn("ARP Request", result["info"])

    def test_non_ip_packet_handling(self):
        """Test handling of raw non-IP Ethernet frames."""
        raw_frame = Ether(type=0x88F7)  # Precision Time Protocol
        result = analyze_packet(raw_frame, packet_id=107)
        self.assertEqual(result["protocol"], "Non-IP")
        self.assertEqual(result["src_ip"], "N/A")
        self.assertEqual(result["dst_ip"], "N/A")

    def test_invalid_and_corrupt_packet_handling(self):
        """Ensure analyzer does not crash on None or corrupt inputs."""
        none_result = analyze_packet(None, packet_id=108)
        self.assertEqual(none_result["id"], 108)
        self.assertEqual(none_result["src_ip"], "N/A")
        self.assertIn("Empty or null", none_result["info"])

        # Arbitrary object
        class CorruptPkt:
            pass

        corrupt_result = analyze_packet(CorruptPkt(), packet_id=109)
        self.assertEqual(corrupt_result["protocol"], "Non-IP")

    def test_safe_payload_preview(self):
        """Verify that payload preview strips/escapes control bytes and HTML tags."""
        payload = b"Normal Text <script>alert(1)</script> \x00\x01\x02\xff"
        preview = safe_decode_payload(payload)

        # Characters '<' and '>' must be escaped
        self.assertNotIn("<script>", preview)
        self.assertIn("&lt;script&gt;", preview)
        # Non-printable characters must be converted to dots
        self.assertIn("....", preview)

        # Truncation check
        long_payload = b"A" * 200
        preview_long = safe_decode_payload(long_payload, max_len=30)
        self.assertIn("... (+170 bytes)", preview_long)

    def test_csv_export(self):
        """Test exporting packet list to CSV."""
        sample_packets = [
            {
                "id": 1,
                "timestamp": "12:00:01.123",
                "protocol": "TCP",
                "src_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_ip": "10.0.0.2",
                "dst_port": 80,
                "length": 64,
                "info": "TCP HTTP handshake",
                "payload_preview": "GET /",
            },
            {
                "id": 2,
                "timestamp": "12:00:02.456",
                "protocol": "UDP",
                "src_ip": "192.168.1.5",
                "src_port": 5353,
                "dst_ip": "224.0.0.251",
                "dst_port": 5353,
                "length": 120,
                "info": "mDNS Multicast",
                "payload_preview": "",
            },
        ]

        csv_output = export_packets_to_csv(sample_packets, filepath=None)
        csv_text = csv_output.getvalue()

        # Check CSV header
        self.assertIn("id,timestamp,protocol,src_ip,src_port,dst_ip,dst_port,length,info,payload_preview", csv_text)
        # Check rows
        self.assertIn("1,12:00:01.123,TCP,10.0.0.1,12345,10.0.0.2,80,64,TCP HTTP handshake,GET /", csv_text)
        self.assertIn("2,12:00:02.456,UDP,192.168.1.5,5353,224.0.0.251,5353,120,mDNS Multicast,", csv_text)


if __name__ == "__main__":
    unittest.main()
