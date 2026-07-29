#!/usr/bin/env python3
"""
API Server for FRV Sniffer Dashboard
Provides real-time data endpoints with caching and optimized file reads
"""

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import json
import os
import time
from datetime import datetime
from collections import defaultdict

app = Flask(__name__, static_folder='../frontend')
CORS(app)

# Paths relative to project root
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
PACKETS_FILE = os.path.join(DATA_DIR, "packets.jsonl")
STATS_FILE = os.path.join(DATA_DIR, "stats.json")

os.makedirs(DATA_DIR, exist_ok=True)

# Response cache
_cache = {}
_cache_ttl = 1.0  # 1 second TTL


def _get_cached(key, ttl=None):
    """Returns cached value if still valid"""
    if ttl is None:
        ttl = _cache_ttl
    entry = _cache.get(key)
    if entry and (time.time() - entry["time"]) < ttl:
        return entry["data"]
    return None


def _set_cache(key, data):
    """Store data in cache"""
    _cache[key] = {"data": data, "time": time.time()}


def _read_last_n_lines(filepath, n=100):
    """Efficiently read last N lines of a file using seek"""
    try:
        if not os.path.exists(filepath):
            return []

        with open(filepath, 'rb') as f:
            f.seek(0, 2)  # seek to end
            file_size = f.tell()

            if file_size == 0:
                return []

            # Read in chunks from end
            lines = []
            chunk_size = min(8192, file_size)
            pos = file_size
            buffer = b''

            while pos > 0 and len(lines) < n + 1:
                read_size = min(chunk_size, pos)
                pos -= read_size
                f.seek(pos)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                lines = buffer.split(b'\n')

            # Return last N non-empty lines
            result = []
            for line in lines[-n:]:
                line = line.strip()
                if line:
                    try:
                        result.append(json.loads(line))
                    except (json.JSONDecodeError, ValueError):
                        pass
            return result
    except Exception:
        return []


@app.route('/')
def index():
    """Serve the dashboard"""
    return send_from_directory('../frontend', 'index.html')


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    sniffer_active = False
    if os.path.exists(STATS_FILE):
        try:
            mtime = os.path.getmtime(STATS_FILE)
            sniffer_active = (time.time() - mtime) < 5  # updated in last 5s
        except OSError:
            pass

    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "sniffer_active": sniffer_active,
        "data_dir": DATA_DIR,
        "packets_file_exists": os.path.exists(PACKETS_FILE),
        "packets_file_size": os.path.getsize(PACKETS_FILE) if os.path.exists(PACKETS_FILE) else 0
    })


@app.route('/api/stats')
def get_stats():
    """Get current statistics (cached)"""
    cached = _get_cached("stats")
    if cached:
        return jsonify(cached)

    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)
            _set_cache("stats", stats)
            return jsonify(stats)
        return jsonify({
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_distribution": {},
            "top_ips": {},
            "top_connections": {},
            "alerts_count": 0,
            "recent_alerts": [],
            "all_alerts": [],
            "suspicious_ips": [],
            "uptime": 0,
            "packets_per_second": 0,
            "bandwidth_history": [],
            "dns_top": {}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/packets/recent')
def get_recent_packets():
    """Get most recent packets (optimized read)"""
    cached = _get_cached("recent_packets")
    if cached:
        return jsonify(cached)

    try:
        count = request.args.get('count', 100, type=int)
        count = min(count, 500)  # cap at 500
        packets = _read_last_n_lines(PACKETS_FILE, count)
        _set_cache("recent_packets", packets)
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/packets/stream')
def get_packet_stream():
    """Get real-time packet stream (Server-Sent Events)"""
    def generate():
        last_position = 0
        if os.path.exists(PACKETS_FILE):
            last_position = os.path.getsize(PACKETS_FILE)

        while True:
            try:
                if os.path.exists(PACKETS_FILE):
                    current_size = os.path.getsize(PACKETS_FILE)
                    if current_size > last_position:
                        with open(PACKETS_FILE, 'r') as f:
                            f.seek(last_position)
                            new_data = f.read()
                            if new_data:
                                for line in new_data.strip().split('\n'):
                                    if line:
                                        yield f"data: {line}\n\n"
                            last_position = f.tell()
                    elif current_size < last_position:
                        last_position = 0  # File was truncated/rotated
                time.sleep(0.5)
            except Exception:
                pass

    return app.response_class(generate(), mimetype='text/event-stream')


@app.route('/api/protocols')
def get_protocol_breakdown():
    """Get detailed protocol breakdown"""
    cached = _get_cached("protocols", ttl=2.0)
    if cached:
        return jsonify(cached)

    try:
        protocol_counts = defaultdict(int)

        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line)
                        protocol_counts[packet['protocol']] += 1
                    except (json.JSONDecodeError, KeyError):
                        pass

        result = dict(protocol_counts)
        _set_cache("protocols", result)
        return jsonify(result)
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

        return jsonify(stats.get('all_alerts', stats.get('recent_alerts', [])))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/connections')
def get_connections():
    """Get top IP-to-IP connections"""
    try:
        stats = {}
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)

        return jsonify(stats.get('top_connections', {}))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/bandwidth')
def get_bandwidth():
    """Get bandwidth history"""
    try:
        stats = {}
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                stats = json.load(f)

        return jsonify(stats.get('bandwidth_history', []))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/traffic/timeline')
def get_traffic_timeline():
    """Get traffic timeline for visualization"""
    cached = _get_cached("timeline", ttl=2.0)
    if cached:
        return jsonify(cached)

    try:
        bucket_size = 5  # 5 second buckets
        buckets = defaultdict(lambda: {"count": 0, "bytes": 0})

        if os.path.exists(PACKETS_FILE):
            with open(PACKETS_FILE, 'r') as f:
                for line in f:
                    try:
                        packet = json.loads(line)
                        timestamp = packet['timestamp'][:19]
                        dt = datetime.fromisoformat(timestamp)
                        bucket_key = dt.replace(second=dt.second - (dt.second % bucket_size))

                        buckets[bucket_key]["count"] += 1
                        buckets[bucket_key]["bytes"] += packet.get('length', 0)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass

        timeline = []
        for timestamp, data in sorted(buckets.items()):
            timeline.append({
                "timestamp": timestamp.isoformat(),
                "packets": data["count"],
                "bytes": data["bytes"]
            })

        result = timeline[-100:]
        _set_cache("timeline", result)
        return jsonify(result)
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
                          'Source Port', 'Dest Port', 'Length', 'Info', 'Anomaly', 'Alert Type'])

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
                            packet.get('anomaly', False),
                            packet.get('alert_type', '')
                        ])
                    except (json.JSONDecodeError, KeyError):
                        pass

        output.seek(0)
        return app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=frv_sniffer_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
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
  API:       http://localhost:8000/api/
  Health:    http://localhost:8000/api/health

  Endpoints:
    GET /api/stats           — Estadísticas generales
    GET /api/packets/recent  — Últimos paquetes capturados
    GET /api/packets/stream  — Stream SSE en tiempo real
    GET /api/alerts          — Alertas de seguridad
    GET /api/connections     — Top conexiones IP→IP
    GET /api/bandwidth       — Historial de ancho de banda
    GET /api/protocols       — Distribución de protocolos
    GET /api/traffic/timeline— Timeline de tráfico
    GET /api/export/csv      — Exportar a CSV
    GET /api/health          — Health check

  Servidor iniciado y esperando conexiones...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
