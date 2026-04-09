# 🛡️ Intrusion Detection System (IDS)

A lightweight Network Intrusion Detection System (NIDS) designed to monitor TCP traffic and detect potential port scans in real-time. This system uses **Scapy** for packet sniffing and **Flask** for a modern web-based monitoring dashboard.

## 🚀 Features

- **Real-time Packet Sniffing**: Captures TCP traffic using the Scapy library.
- **Port Scan Detection**: Detects suspicious activity when multiple unique ports are accessed by a single IP within a short time window.
- **Web Dashboard**: Modern, responsive UI to start/stop monitoring and view live alerts.
- **Incident Reports**: Automatically generates detailed JSON reports including session summaries, detected incidents, and security recommendations.
- **CLI Mode**: Simple command-line interface for quick monitoring and logging.

## 📋 Prerequisites

- **Python 3.x**
- **Administrator/Root Privileges**: Required for Scapy to capture network packets.
- **Npcap** (Windows): Ensure Npcap is installed (usually with Wireshark) for packet sniffing support.

## 🛠️ Installation

1. Clone or download this repository.
2. Open a terminal (as Administrator on Windows).
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Option 1: Web Interface (Recommended)
1. Run the Flask application:
   ```bash
   python 01_app.py
   ```
2. Open your browser and navigate to `http://127.0.0.1:5002`.
3. Click "Start Monitoring" to begin a 30-second capture session.
4. View real-time alerts and the generated incident report.

### Option 2: Command Line Interface
1. Run the CLI script:
   ```bash
   python main.py
   ```
2. Alerts will be printed to the terminal and logged to `ids_alerts.log`.

## 🧪 How to Verify it's Working

You can use the included `test_scan.py` script to simulate a port scan and verify that the system detects it.

1. **Start the IDS**: Run either `01_app.py` (and click "Start Monitoring") or `main.py`.
2. **Run the Test Simulation**:
   ```bash
   python test_scan.py
   ```
3. **Check for Alerts**:
   - In **Web Mode**, you should see "Port scan detected from 127.0.0.1!" in the Detection Log.
   - In **CLI Mode**, you should see the alert in the terminal and `ids_alerts.log`.
4. **Review Report**: In Web Mode, an incident report JSON will be created in the project directory after the session ends.

## ⚙️ Configuration

- **Threshold**: Currently set to detect a scan if 3 or more unique ports are accessed within 10 seconds.
- **Monitoring Duration**: The web session runs for 30 seconds by default.
- These can be adjusted in `01_app.py`.

---
