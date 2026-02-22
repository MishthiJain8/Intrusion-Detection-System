from scapy.all import sniff, TCP, IP
from collections import defaultdict
import logging

# Set up logging
logging.basicConfig(filename="ids_alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Dictionary to track port scan attempts
port_scans = defaultdict(set)

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        port_scans[src_ip].add(dst_port)

        # Trigger alert if more than 0 unique ports accessed (lowered threshold for testing)
        if len(port_scans[src_ip]) > 0:
            alert_msg = f"🚨 Port scan detected from {src_ip}! Accessed ports: {sorted(port_scans[src_ip])}"
            print(alert_msg)
            logging.info(alert_msg)

def main():
    print("🔍 Sniffing for suspicious activity... (Press Ctrl+C to stop)\n")
    
    # Use this line if unsure (basic sniffing):
    # sniff(filter="tcp", prn=detect_port_scan, store=0)

    # Use this line for macOS Wi-Fi interface sniffing:
    sniff(filter="tcp", prn=detect_port_scan, store=0)

if __name__ == "__main__":
    main()


