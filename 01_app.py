from flask import Flask, render_template, jsonify
from flask_cors import CORS
from threading import Thread
from scapy.all import sniff, IP, TCP
import time
from collections import defaultdict
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store alerts in a list to display them on the webpage
alerts = []

# Dictionary to track source IP and accessed ports
ip_ports = defaultdict(list)
scan_threshold = 3
time_window = 10  # seconds

# Enhanced detection: packet rate tracking
packet_count_per_ip = defaultdict(int)
packet_rate_threshold = 100  # packets per 30sec session

# Guard to prevent launching multiple sniff threads
sniffing_active = False

# Incident response data
incident_data = {
    'session_start': None,
    'session_end': None,
    'total_packets': 0,
    'unique_ips': set(),
    'port_scans_detected': [],
    'high_packet_rate_ips': [],
    'detailed_logs': [],
    'threat_summary': {}
}

# Reports directory
REPORTS_DIR = 'incident_reports'
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

def calculate_risk_score(incident_type, count=1):
    """Calculate risk score based on incident type and frequency."""
    risk_map = {
        'port_scan': 7,
        'high_packet_rate': 6,
        'syn_like_pattern': 8,
        'multiple_protocols': 5
    }
    return risk_map.get(incident_type, 3) * count

def detect_intrusions(packet):
    """Enhanced intrusion detection: port scans, packet rate anomalies, protocol patterns."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    source_ip = packet[IP].src
    dest_port = packet[TCP].dport
    current_time = time.time()
    
    # Track overall metrics
    incident_data['total_packets'] += 1
    incident_data['unique_ips'].add(source_ip)
    packet_count_per_ip[source_ip] += 1
    
    # Log detailed packet info
    packet_log = {
        'timestamp': current_time,
        'source_ip': source_ip,
        'dest_port': dest_port,
        'protocol': 'TCP',
        'flags': str(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else 'unknown'
    }
    incident_data['detailed_logs'].append(packet_log)

    # ===== Detection 1: Port Scan =====
    ip_ports[source_ip].append((dest_port, current_time))
    ip_ports[source_ip] = [
        (port, timestamp)
        for port, timestamp in ip_ports[source_ip]
        if current_time - timestamp < time_window
    ]

    accessed_ports = {port for port, _ in ip_ports[source_ip]}
    if len(accessed_ports) >= scan_threshold:
        alert_message = f"🔍 Port scan detected from {source_ip}: accessed {len(accessed_ports)} ports!"
        if alert_message not in alerts:
            alerts.append(alert_message)
            incident_data['port_scans_detected'].append({
                'timestamp': current_time,
                'source_ip': source_ip,
                'ports_accessed': sorted(list(accessed_ports)),
                'total_ports': len(accessed_ports),
                'risk_score': calculate_risk_score('port_scan', len(accessed_ports))
            })

    # ===== Detection 2: Unusual Packet Rate =====
    if packet_count_per_ip[source_ip] > packet_rate_threshold:
        alert_message = f"⚡ Unusual packet rate from {source_ip}: {packet_count_per_ip[source_ip]} packets!"
        if alert_message not in alerts:
            alerts.append(alert_message)
            incident_data['high_packet_rate_ips'].append({
                'timestamp': current_time,
                'source_ip': source_ip,
                'packet_count': packet_count_per_ip[source_ip],
                'risk_score': calculate_risk_score('high_packet_rate', packet_count_per_ip[source_ip] // 50)
            })

def simulate_traffic_when_no_privileges():
    """Fallback simulation when raw packet capture is not available."""
    simulation_ips = ['192.168.0.50', '192.168.0.51']
    current_time = time.time()

    for sim_ip in simulation_ips:
        simulated_ports = [22, 80, 443, 8080, 3389, 5900]
        
        for port in simulated_ports:
            incident_data['total_packets'] += 1
            incident_data['unique_ips'].add(sim_ip)
            incident_data['detailed_logs'].append({
                'timestamp': current_time,
                'source_ip': sim_ip,
                'dest_port': port,
                'protocol': 'TCP (simulated)',
                'flags': 'SYN (simulated)'
            })
            ip_ports[sim_ip].append((port, current_time))

        accessed_ports = {p for p, _ in ip_ports[sim_ip]}
        if len(accessed_ports) >= scan_threshold:
            alert_message = f"🔍 Simulated port scan detected from {sim_ip}: accessed {len(accessed_ports)} ports!"
            if alert_message not in alerts:
                alerts.append(alert_message)
                incident_data['port_scans_detected'].append({
                    'timestamp': current_time,
                    'source_ip': sim_ip,
                    'ports_accessed': sorted(list(accessed_ports)),
                    'total_ports': len(accessed_ports),
                    'risk_score': calculate_risk_score('port_scan', len(accessed_ports))
                })

def generate_incident_report():
    """Generate comprehensive incident response report with risk assessment."""
    if not incident_data['session_start'] or not incident_data['session_end']:
        return None

    duration = incident_data['session_end'] - incident_data['session_start']
    
    # Calculate summary statistics
    total_incidents = len(incident_data['port_scans_detected']) + len(incident_data['high_packet_rate_ips'])
    total_risk_score = 0
    
    for incident in incident_data['port_scans_detected']:
        total_risk_score += incident.get('risk_score', 0)
    for incident in incident_data['high_packet_rate_ips']:
        total_risk_score += incident.get('risk_score', 0)
    
    severity = 'Critical' if total_risk_score > 50 else 'High' if total_risk_score > 30 else 'Medium' if total_risk_score > 10 else 'Low'
    
    report = {
        'session_summary': {
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident_data['session_start'])),
            'end_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident_data['session_end'])),
            'duration_seconds': round(duration, 2),
            'total_packets_captured': incident_data['total_packets'],
            'unique_source_ips': len(incident_data['unique_ips']),
            'total_incidents': total_incidents,
            'overall_risk_score': total_risk_score,
            'severity': severity
        },
        'threats_detected': {
            'port_scans': incident_data['port_scans_detected'],
            'high_packet_rate': incident_data['high_packet_rate_ips']
        },
        'recommendations': [],
        'detailed_logs_sample': incident_data['detailed_logs'][:50]  # First 50 logs
    }
    
    # Generate context-aware recommendations
    if len(incident_data['port_scans_detected']) > 0:
        report['recommendations'].append("🔴 Port scan activity detected - implement rate limiting and IP-based filtering")
        report['recommendations'].append("🔴 Consider deploying IDS/IPS signatures for reconnaissance patterns")
    
    if len(incident_data['high_packet_rate_ips']) > 0:
        report['recommendations'].append("🟠 Unusual packet rates detected - check for DDoS or data exfiltration")
        report['recommendations'].append("🟠 Review traffic patterns and consider implementing traffic shaping")
    
    if total_risk_score == 0:
        report['recommendations'].append("🟢 No significant threats detected - network appears secure")
        report['recommendations'].append("🟢 Continue regular monitoring to maintain baseline")
    
    report['recommendations'].append(f"📊 Severity Level: {severity}")
    report['recommendations'].append("📧 Archive this report for compliance and audit trails")
    
    # Save report to file
    timestamp = int(incident_data['session_start'])
    report_filename = os.path.join(REPORTS_DIR, f"incident_report_{timestamp}.json")
    try:
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        alerts.append(f"💾 Report saved to {report_filename}")
    except Exception as e:
        print(f"Error saving report: {e}")
    
    return report

def start_sniffing_thread():
    """Start sniffing in background thread with error handling."""
    global sniffing_active
    incident_data['session_start'] = time.time()

    try:
        # Sniff for 30 seconds with enhanced detection
        sniff(filter="tcp", prn=detect_intrusions, store=0, timeout=30)
    except PermissionError as perm_err:
        print("PermissionError in sniff():", perm_err)
        alerts.append("⚠️ Permission denied for packet sniffing. Running in simulation mode.")
        simulate_traffic_when_no_privileges()
    except Exception as e:
        print("Sniffing failed with error:", e)
        alerts.append(f"⚠️ Packet capture failed: {str(e)}. Running in simulation mode.")
        simulate_traffic_when_no_privileges()
    finally:
        incident_data['session_end'] = time.time()
        sniffing_active = False

        # Generate incident report
        report = generate_incident_report()
        if report:
            alerts.append(f"📋 Incident Response Report Generated (Severity: {report['session_summary']['severity']})")
            print("Incident Response Report Generated:")
            print(json.dumps(report, indent=2))
        else:
            alerts.append("No intrusions detected during monitoring session.")

# The route for your webpage
@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

# Start sniffing — returns immediately, sniffing runs in background
@app.route('/start_sniffing', methods=["POST"])
def start_sniffing():
    global sniffing_active, alerts, ip_ports, incident_data, packet_count_per_ip
    if sniffing_active:
        return jsonify(message="Sniffing is already running!")

    # Reset data for new session
    alerts = []
    ip_ports.clear()
    packet_count_per_ip.clear()
    incident_data = {
        'session_start': None,
        'session_end': None,
        'total_packets': 0,
        'unique_ips': set(),
        'port_scans_detected': [],
        'high_packet_rate_ips': [],
        'detailed_logs': [],
        'threat_summary': {}
    }

    sniffing_active = True
    sniff_thread = Thread(target=start_sniffing_thread, daemon=True)
    sniff_thread.start()
    return jsonify(message="🚀 Network intrusion detection started! Monitoring for suspicious activity...")

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

# List all saved reports
@app.route('/reports_list')
def reports_list():
    try:
        reports = []
        if os.path.exists(REPORTS_DIR):
            for filename in os.listdir(REPORTS_DIR):
                if filename.endswith('.json'):
                    filepath = os.path.join(REPORTS_DIR, filename)
                    reports.append({
                        'filename': filename,
                        'timestamp': os.path.getmtime(filepath)
                    })
        return jsonify(reports=sorted(reports, key=lambda x: x['timestamp'], reverse=True))
    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5002, debug=True)
