# FRV SNIFFER

Network Traffic Analyzer with Real-Time Anomaly Detection

## Features

- Real-time packet capture and analysis
- Port scan detection
- Connection flooding detection
- DNS anomaly detection
- Minimalist black & white dashboard
- CSV export functionality

## Installation

### Requirements

- Python 3.8+
- scapy
- flask
- flask-cors

### Quick Install

```bash
pip install -r requirements.txt --break-system-packages
```

## Usage

### Option 1: Automatic Start (Recommended)

```bash
sudo ./start.sh
```

### Option 2: Manual Start (Two Terminals)

**Terminal 1 - Dashboard:**
```bash
./start-dashboard.sh
```

**Terminal 2 - Sniffer:**
```bash
sudo python3 backend/sniffer.py
```

### Access Dashboard

Open your browser: **http://localhost:8000**

## Advanced Usage

### Capture on Specific Interface

```bash
sudo python3 backend/sniffer.py -i eth0
```

### Capture Limited Packets

```bash
sudo python3 backend/sniffer.py -c 1000
```

### Apply BPF Filter

```bash
# HTTP/HTTPS only
sudo python3 backend/sniffer.py -f "port 80 or port 443"

# Specific IP
sudo python3 backend/sniffer.py -f "host 192.168.1.100"

# TCP only
sudo python3 backend/sniffer.py -f "tcp"
```

## Project Structure

```
frv-sniffer/
├── backend/
│   ├── sniffer.py      # Packet capture engine
│   └── api_server.py   # Dashboard web server
├── frontend/
│   └── index.html      # Black & white dashboard
├── data/               # Captured packets (auto-created)
├── logs/               # Analysis reports (auto-created)
├── start.sh            # Automatic startup
├── start-dashboard.sh  # Dashboard only
└── requirements.txt    # Python dependencies
```

## Dashboard Features

- **Real-time statistics**: Packets, protocols, IPs, alerts
- **Protocol distribution**: Pie/bar chart visualization
- **Traffic timeline**: Packets per second over time
- **Live packet table**: Search and filter capabilities
- **Security alerts**: Automatic anomaly detection
- **CSV export**: Download all captured data

## Detection Capabilities

### Port Scanning
- Threshold: 10+ ports in 10 seconds
- Severity: High

### Connection Flooding
- Threshold: 50+ connections per IP
- Severity: Medium

### DNS Anomalies
- Threshold: 30+ queries to same domain
- Severity: Medium

## Troubleshooting

### "Unable to connect" on localhost:8000
**Solution**: Start the dashboard server
```bash
./start-dashboard.sh
```

### "Permission denied"
**Solution**: Run with sudo
```bash
sudo python3 backend/sniffer.py
```

### "scapy not installed"
**Solution**: Install dependencies
```bash
pip install scapy flask flask-cors --break-system-packages
```

## Ethical Use

This tool is for:
- ✓ Educational purposes
- ✓ Your own networks
- ✓ Authorized security testing
- ✓ Network research

Do NOT use for:
- ✗ Unauthorized network monitoring
- ✗ Privacy violations
- ✗ Malicious activities

## License

Educational and research purposes only.

---

**FRV SNIFFER** - Network Traffic Analysis System
