#!/usr/bin/env python3
"""
API Server for Network Traffic Analyzer Dashboard
Provides real-time data endpoints for the web interface
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
from datetime import datetime
from collections import defaultdict

app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Use paths relative to script location
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
PACKETS_FILE = os.path.join(DATA_DIR, "packets.jsonl")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")

# Create data directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)


@app.route('/')
def index():
    """Serve the dashboard"""
    return send_from_directory('../frontend', 'index.html')


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)
            return jsonify(stats)
        return jsonify({
            "total_packets": 0,
            "protocol_distribution": {},
            "top_ips": {},
            "alerts_count": 0,
            "recent_alerts": [],
            "suspicious_ips": [],
            "uptime": 0,
            "packets_per_second": 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/packets/recent')
def get_recent_packets():
    """Get most recent packets"""
    try:
        packets = []
        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                # Read last 100 lines
                lines = f.readlines()
                for line in lines[-100:]:
                    try:
                        packets.append(json.loads(line))
                    except:
                        pass
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/packets/stream')
def get_packet_stream():
    """Get real-time packet stream (Server-Sent Events)"""
    def generate():
        last_position = 0
        while True:
            try:
                if os.path.exists(PACKETS_FILE):
                    with open(PACKETS_FILE, 'r') as f:
                        f.seek(last_position)
                        new_data = f.read()
                        if new_data:
                            for line in new_data.strip().split('\n'):
                                if line:
                                    yield f"data: {line}\n\n"
                        last_position = f.tell()
                import time
                time.sleep(0.5)
            except:
                pass
    
    return app.response_class(generate(), mimetype='text/event-stream')


@app.route('/api/protocols')
def get_protocol_breakdown():
    """Get detailed protocol breakdown with timestamps"""
    try:
        protocol_timeline = defaultdict(list)
        
        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line)
                        protocol_timeline[packet['protocol']].append({
                            'timestamp': packet['timestamp'],
                            'length': packet['length']
                        })
                    except:
                        pass
        
        return jsonify(dict(protocol_timeline))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """Get all security alerts"""
    try:
        stats = {}
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)
        
        return jsonify(stats.get('recent_alerts', []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/traffic/timeline')
def get_traffic_timeline():
    """Get traffic timeline for visualization"""
    try:
        timeline = []
        bucket_size = 5  # 5 second buckets
        buckets = defaultdict(lambda: {"count": 0, "bytes": 0})
        
        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line)
                        timestamp = packet['timestamp'][:19]  # Remove milliseconds
                        dt = datetime.fromisoformat(timestamp)
                        bucket_key = dt.replace(second=dt.second - (dt.second % bucket_size))
                        
                        buckets[bucket_key]["count"] += 1
                        buckets[bucket_key]["bytes"] += packet.get('length', 0)
                    except:
                        pass
        
        # Convert to list and sort
        for timestamp, data in sorted(buckets.items()):
            timeline.append({
                "timestamp": timestamp.isoformat(),
                "packets": data["count"],
                "bytes": data["bytes"]
            })
        
        return jsonify(timeline[-100:])  # Last 100 data points
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/export/csv')
def export_csv():
    """Export packets as CSV"""
    try:
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Timestamp', 'Protocol', 'Source IP', 'Dest IP', 
                        'Source Port', 'Dest Port', 'Length', 'Info', 'Anomaly'])
        
        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line)
                        writer.writerow([
                            packet.get('id', ''),
                            packet.get('timestamp', ''),
                            packet.get('protocol', ''),
                            packet.get('src_ip', ''),
                            packet.get('dst_ip', ''),
                            packet.get('src_port', ''),
                            packet.get('dst_port', ''),
                            packet.get('length', ''),
                            packet.get('info', ''),
                            packet.get('anomaly', False)
                        ])
                    except:
                        pass
        
        output.seek(0)
        return app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=network_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                       FRV SNIFFER                            ║
║                    Dashboard Server                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Dashboard: http://localhost:8000
  API: http://localhost:8000/api/
  
  Servidor iniciado y esperando conexiones...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
    
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
