from scapy.all import conf, get_if_list
from core.packet_sniffer import PacketSniffer
from utils.geo_ip import get_geo_info
import os
import sys


def check_permissions():
    """Check if script is running with root privileges on macOS."""
    if os.geteuid() != 0:
        print("[!] ERROR: This script requires root privileges on macOS.")
        print("[!] Please run with: sudo python3 main.py")
        sys.exit(1)


def list_interfaces():
    """Lists all available network interfaces."""
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    print("\n💡 Common macOS interfaces:")
    print("   - en0: Usually your primary Ethernet/Wi-Fi")
    print("   - en1: Usually secondary network adapter")
    print("   - lo0: Loopback interface (localhost)")
    return interfaces


def choose_interface(interfaces):
    """Prompts the user to select a network interface."""
    while True:
        try:
            choice = int(input("\nEnter the number of the interface you want to use: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            else:
                print(f"Invalid choice. Please select a number between 0 and {len(interfaces) - 1}.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n[!] Cancelled by user")
            sys.exit(0)


def main():
    print("=" * 60)
    print("WhatsApp P2P IP Tracker - macOS Version")
    print("=" * 60)
    
    # Check for root privileges on macOS
    check_permissions()
    
    print("\n[*] Network Interface Selection")
    interfaces = list_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"\n[+] You selected: {selected_interface}")
    print("[*] Make sure you're connected to the network you want to monitor")
    print("[*] Start a WhatsApp voice/video call to capture packets...")
    print()

    # Start packet sniffing
    sniffer = PacketSniffer(log_file="logs/packet_logs.pcap")
    
    try:
        sniffer.start_sniffing(iface=selected_interface, count=100)
    except KeyboardInterrupt:
        print("\n[!] Sniffing interrupted by user")
    except Exception as e:
        print(f"[!] Error during sniffing: {e}")
        sys.exit(1)

    # Post-processing: Analyze captured IPs and get geolocation data
    if sniffer.packets:
        print("\n[*] Analyzing captured packets...")
        unique_ips = set()
        
        for pkt in sniffer.packets:
            if hasattr(pkt, 'src'):
                unique_ips.add(pkt[1].src)
            if hasattr(pkt, 'dst'):
                unique_ips.add(pkt[1].dst)
        
        print(f"[*] Found {len(unique_ips)} unique IP addresses\n")
        
        for ip in unique_ips:
            # Skip local/private IPs
            if ip.startswith(('192.168.', '10.', '172.', '127.')):
                continue
                
            geo_info = get_geo_info(ip)
            if geo_info:
                print(f"[+] IP: {geo_info['ip']} - {geo_info['city']}, {geo_info['country']} "
                      f"({geo_info['latitude']}, {geo_info['longitude']})")
    else:
        print("\n[!] No WhatsApp packets were captured.")
        print("[!] Tips:")
        print("    - Make sure you selected the correct network interface")
        print("    - Try making a WhatsApp call while the sniffer is running")
        print("    - Check if WhatsApp is using the expected IP ranges")


if __name__ == "__main__":
    main()
