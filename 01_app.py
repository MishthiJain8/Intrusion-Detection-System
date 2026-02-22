from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict

app = Flask(__name__)

# Store alerts in a list to display them on the webpage
alerts = []

# Dictionary to track source IP and accessed ports
ip_ports = defaultdict(list)
scan_threshold = 3
time_window = 10  # seconds

# Guard to prevent launching multiple sniff threads
sniffing_active = False

# This function checks for port scans
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport

        # Debug print to show packet info
        print(f"Packet received: {source_ip} -> Port {dest_port}")

        current_time = time.time()
        ip_ports[source_ip].append((dest_port, current_time))

        # Remove old entries that are out of the time window
        ip_ports[source_ip] = [
            (port, timestamp)
            for port, timestamp in ip_ports[source_ip]
            if current_time - timestamp < time_window
        ]

        # Debug print for accessed ports
        accessed_ports = {port for port, _ in ip_ports[source_ip]}
        print(f"Accessed ports from {source_ip}: {accessed_ports}")

        # If the number of distinct ports accessed by the IP exceeds the threshold, it's a port scan
        if len(accessed_ports) >= scan_threshold:
            alert_message = f"Port scan detected from {source_ip}!"
            if alert_message not in alerts:
                print(alert_message)
                alerts.append(alert_message)

# Function to start sniffing (runs in a background thread)
def start_sniffing_thread():
    global sniffing_active
    try:
        sniff(filter="tcp", prn=detect_port_scan, store=0)
    finally:
        sniffing_active = False
        if not alerts:
            alerts.append("No port scans detected during monitoring session.")

# The route for your webpage
@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

# Start sniffing — returns immediately, sniffing runs in background
@app.route('/start_sniffing', methods=["POST"])
def start_sniffing():
    global sniffing_active
    if sniffing_active:
        return jsonify(message="Sniffing is already running!")

    sniffing_active = True
    sniff_thread = Thread(target=start_sniffing_thread, daemon=True)
    sniff_thread.start()
    return jsonify(message="Sniffing started! Monitoring for suspicious activity.")

# Live alerts polling endpoint
@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True, port=5002)
