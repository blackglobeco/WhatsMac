from scapy.all import sniff, IP, UDP, wrpcap
from core.ip_filter import is_whatsapp_ip
import os

class PacketSniffer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.packets = []
        # Ensure logs directory exists
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Check if packet matches WhatsApp IPs or ports
            if is_whatsapp_ip(src_ip) or is_whatsapp_ip(dst_ip):
                print(f"[+] Captured WhatsApp Packet: {src_ip} -> {dst_ip}")
                self.packets.append(packet)

    def start_sniffing(self, iface=None, count=100):
        print("[*] Starting packet sniffing...")
        # If no interface specified, let Scapy choose the default
        sniff_params = {
            "filter": "udp",
            "prn": self.process_packet,
            "count": count,
            "store": 0
        }
        
        if iface:
            sniff_params["iface"] = iface
            
        sniff(**sniff_params)
        self.save_packets()

    def save_packets(self):
        if self.packets:
            print(f"[*] Saving {len(self.packets)} captured packets to {self.log_file}")
            wrpcap(self.log_file, self.packets)
        else:
            print("[!] No WhatsApp packets captured")
