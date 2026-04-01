from flask import Flask, render_template, jsonify
from threading import Thread
from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict
import json

app = Flask(__name__)

# Store alerts in a list to display them on the webpage
alerts = []

# Dictionary to track source IP and accessed ports
ip_ports = defaultdict(list)
scan_threshold = 3
time_window = 10  # seconds

# Guard to prevent launching multiple sniff threads
sniffing_active = False

# Incident response data
incident_data = {
    'session_start': None,
    'session_end': None,
    'total_packets': 0,
    'unique_ips': set(),
    'port_scans_detected': [],
    'detailed_logs': []
}

# This function checks for port scans
def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_port = packet[TCP].dport

        current_time = time.time()
        incident_data['total_packets'] += 1
        incident_data['unique_ips'].add(source_ip)
        
        # Log detailed packet info
        packet_log = {
            'timestamp': current_time,
            'source_ip': source_ip,
            'dest_port': dest_port,
            'protocol': 'TCP'
        }
        incident_data['detailed_logs'].append(packet_log)

        ip_ports[source_ip].append((dest_port, current_time))

        # Remove old entries that are out of the time window
        ip_ports[source_ip] = [
            (port, timestamp)
            for port, timestamp in ip_ports[source_ip]
            if current_time - timestamp < time_window
        ]

        # Debug print for accessed ports
        accessed_ports = {port for port, _ in ip_ports[source_ip]}

        # If the number of distinct ports accessed by the IP exceeds the threshold, it's a port scan
        if len(accessed_ports) >= scan_threshold:
            alert_message = f"Port scan detected from {source_ip}!"
            if alert_message not in alerts:
                print(alert_message)
                alerts.append(alert_message)
                
                # Record port scan incident
                scan_incident = {
                    'timestamp': current_time,
                    'source_ip': source_ip,
                    'ports_accessed': sorted(list(accessed_ports)),
                    'total_ports': len(accessed_ports)
                }
                incident_data['port_scans_detected'].append(scan_incident)

# Function to generate incident response report
def generate_incident_report():
    if incident_data['session_start'] and incident_data['session_end']:
        duration = incident_data['session_end'] - incident_data['session_start']
        report = {
            'session_summary': {
                'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident_data['session_start'])),
                'end_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident_data['session_end'])),
                'duration_seconds': round(duration, 2),
                'total_packets_captured': incident_data['total_packets'],
                'unique_source_ips': len(incident_data['unique_ips']),
                'port_scans_detected': len(incident_data['port_scans_detected'])
            },
            'incidents': incident_data['port_scans_detected'],
            'recommendations': []
        }
        
        # Add recommendations based on findings
        if report['session_summary']['port_scans_detected'] > 0:
            report['recommendations'].append("Block suspicious IP addresses at the firewall level")
            report['recommendations'].append("Monitor the affected systems for unauthorized access")
            report['recommendations'].append("Review firewall logs for additional suspicious activity")
            report['recommendations'].append("Consider implementing rate limiting on network ports")
        else:
            report['recommendations'].append("Network monitoring session completed successfully - no threats detected")
            report['recommendations'].append("Continue regular monitoring to maintain security posture")
        
        # Save report to file
        report_filename = f"incident_report_{int(incident_data['session_start'])}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    return None

# Function to start sniffing (runs in a background thread)
def start_sniffing_thread():
    global sniffing_active
    try:
        incident_data['session_start'] = time.time()
        # Sniff for 30 seconds
        sniff(filter="tcp", prn=detect_port_scan, store=0, timeout=30)
    finally:
        incident_data['session_end'] = time.time()
        sniffing_active = False
        
        # Generate incident report
        report = generate_incident_report()
        if report:
            alerts.append(f"📋 Incident Response Report Generated: {report['session_summary']['port_scans_detected']} port scans detected")
            print("Incident Response Report Generated:")
            print(json.dumps(report, indent=2))
        else:
            alerts.append("No port scans detected during monitoring session.")

# The route for your webpage
@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

# Start sniffing — returns immediately, sniffing runs in background
@app.route('/start_sniffing', methods=["POST"])
def start_sniffing():
    global sniffing_active, alerts, ip_ports, incident_data
    if sniffing_active:
        return jsonify(message="Sniffing is already running!")

    # Reset data for new session
    alerts = []
    ip_ports.clear()
    incident_data = {
        'session_start': None,
        'session_end': None,
        'total_packets': 0,
        'unique_ips': set(),
        'port_scans_detected': [],
        'detailed_logs': []
    }

    sniffing_active = True
    sniff_thread = Thread(target=start_sniffing_thread, daemon=True)
    sniff_thread.start()
    return jsonify(message="Sniffing started! Monitoring for suspicious activity.")

# Live alerts polling endpoint
@app.route('/alerts')
def get_alerts():
    return jsonify(alerts=alerts)

# Get incident report
@app.route('/report')
def get_report():
    report = generate_incident_report()
    if report:
        return jsonify(report)
    return jsonify({"error": "No report available"}), 404

if __name__ == "__main__":
    app.run(debug=True, port=5002)
