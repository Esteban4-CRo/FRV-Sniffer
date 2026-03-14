#!/usr/bin/env python3
"""
FRV Sniffer - Network Traffic Analyzer
Advanced packet capture and anomaly detection system
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("=" * 70)
    print("ERROR: scapy no está instalado")
    print("=" * 70)
    print("\nPor favor ejecuta:")
    print("  pip install scapy --break-system-packages")
    print("=" * 70)
    sys.exit(1)


class PacketAnalyzer:
    """Analiza paquetes y detecta anomalías"""
    
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_connections = defaultdict(int)
        self.port_scans = defaultdict(lambda: {"ports": set(), "timestamps": deque(maxlen=100)})
        self.dns_queries = defaultdict(int)
        self.suspicious_ips = set()
        self.alerts = []
        self.traffic_history = deque(maxlen=1000)
        self.start_time = time.time()
        
        # Umbrales de detección
        self.PORT_SCAN_THRESHOLD = 10
        self.PORT_SCAN_WINDOW = 10
        self.CONNECTION_THRESHOLD = 50
        self.DNS_QUERY_THRESHOLD = 30
        
    def analyze_packet(self, packet) -> Dict:
        """Analiza un paquete y retorna información"""
        self.packet_count += 1
        timestamp = datetime.now().isoformat()
        
        packet_info = {
            "id": self.packet_count,
            "timestamp": timestamp,
            "protocol": "Unknown",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "length": len(packet),
            "info": "",
            "anomaly": False,
            "alert_type": None
        }
        
        # Capa IP
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["protocol"] = packet[IP].proto
            
            self.ip_connections[packet[IP].src] += 1
            
            if self.ip_connections[packet[IP].src] > self.CONNECTION_THRESHOLD:
                self.add_alert("connection_flood", packet[IP].src, 
                             f"Excesivas conexiones desde {packet[IP].src}")
                packet_info["anomaly"] = True
                packet_info["alert_type"] = "connection_flood"
        
        # Capa de Transporte
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["info"] = f"{packet[TCP].sport} → {packet[TCP].dport}"
            
            if IP in packet:
                self.check_port_scan(packet[IP].src, packet[TCP].dport, timestamp)
                if packet[IP].src in self.suspicious_ips:
                    packet_info["anomaly"] = True
                    packet_info["alert_type"] = "port_scan"
            
            flags = packet[TCP].flags
            if flags:
                packet_info["info"] += f" [{flags}]"
                
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            packet_info["info"] = f"{packet[UDP].sport} → {packet[UDP].dport}"
            
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            packet_info["info"] = f"Type {packet[ICMP].type}"
        
        # Capa de Aplicación
        if DNS in packet:
            packet_info["protocol"] = "DNS"
            if packet.haslayer(DNS) and packet[DNS].qd:
                try:
                    query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    packet_info["info"] = f"Query: {query}"
                    self.dns_queries[query] += 1
                    
                    if self.dns_queries[query] > self.DNS_QUERY_THRESHOLD:
                        self.add_alert("dns_anomaly", query,
                                     f"Queries excesivas para {query}")
                        packet_info["anomaly"] = True
                        packet_info["alert_type"] = "dns_anomaly"
                except:
                    pass
        
        if packet.haslayer(HTTPRequest):
            packet_info["protocol"] = "HTTP"
            try:
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode() if http_layer.Method else "GET"
                host = http_layer.Host.decode() if http_layer.Host else ""
                path = http_layer.Path.decode() if http_layer.Path else "/"
                packet_info["info"] = f"{method} {host}{path}"
            except:
                packet_info["info"] = "HTTP Request"
        
        if ARP in packet:
            packet_info["protocol"] = "ARP"
            packet_info["info"] = f"Op: {packet[ARP].op}"
        
        self.protocol_stats[packet_info["protocol"]] += 1
        self.traffic_history.append({
            "timestamp": timestamp,
            "protocol": packet_info["protocol"],
            "length": packet_info["length"]
        })
        
        return packet_info
    
    def check_port_scan(self, src_ip: str, dst_port: int, timestamp: str):
        """Detecta escaneo de puertos"""
        scan_data = self.port_scans[src_ip]
        scan_data["ports"].add(dst_port)
        scan_data["timestamps"].append(time.time())
        
        if len(scan_data["timestamps"]) >= 2:
            time_diff = scan_data["timestamps"][-1] - scan_data["timestamps"][0]
            if time_diff <= self.PORT_SCAN_WINDOW and len(scan_data["ports"]) >= self.PORT_SCAN_THRESHOLD:
                if src_ip not in self.suspicious_ips:
                    self.suspicious_ips.add(src_ip)
                    self.add_alert("port_scan", src_ip,
                                 f"Posible escaneo de puertos desde {src_ip} ({len(scan_data['ports'])} puertos)")
    
    def add_alert(self, alert_type: str, source: str, message: str):
        """Agrega una alerta de seguridad"""
        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "source": source,
            "message": message,
            "severity": self.get_severity(alert_type)
        }
        self.alerts.append(alert)
        print(f"\n⚠ ALERTA: {message}")
    
    def get_severity(self, alert_type: str) -> str:
        """Determina severidad de alerta"""
        severity_map = {
            "port_scan": "high",
            "connection_flood": "medium",
            "dns_anomaly": "medium",
            "suspicious_traffic": "low"
        }
        return severity_map.get(alert_type, "low")
    
    def get_stats(self) -> Dict:
        """Obtiene estadísticas actuales"""
        uptime = int(time.time() - self.start_time)
        pps = self.packet_count / max(1, uptime)
        
        return {
            "total_packets": self.packet_count,
            "protocol_distribution": dict(self.protocol_stats),
            "top_ips": dict(sorted(self.ip_connections.items(), 
                                  key=lambda x: x[1], reverse=True)[:10]),
            "alerts_count": len(self.alerts),
            "recent_alerts": self.alerts[-5:],
            "suspicious_ips": list(self.suspicious_ips),
            "uptime": uptime,
            "packets_per_second": round(pps, 2)
        }


class FRVSniffer:
    """FRV Sniffer - Analizador principal de red"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.analyzer = PacketAnalyzer()
        self.running = False
        self.packet_queue = deque(maxlen=100)
        
        # Rutas relativas al script
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(script_dir, "data")
        self.logs_dir = os.path.join(script_dir, "logs")
        
        # Crear directorios
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        
        self.data_file = os.path.join(self.data_dir, "packets.jsonl")
        self.stats_file = os.path.join(self.data_dir, "stats.json")
        
    def packet_handler(self, packet):
        """Maneja cada paquete capturado"""
        try:
            packet_info = self.analyzer.analyze_packet(packet)
            self.packet_queue.append(packet_info)
            
            with open(self.data_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(packet_info, ensure_ascii=False) + '\n')
                
        except Exception as e:
            pass
    
    def save_stats(self):
        """Guarda estadísticas periódicamente"""
        while self.running:
            try:
                stats = self.analyzer.get_stats()
                with open(self.stats_file, 'w', encoding='utf-8') as f:
                    json.dump(stats, f, indent=2, ensure_ascii=False)
                time.sleep(2)
            except Exception as e:
                pass
    
    def start_capture(self, packet_count=0, filter_str=None):
        """Inicia captura de paquetes"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                       FRV SNIFFER                            ║
║             Network Traffic Analysis System                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Interface: {self.interface or 'Auto-detectada'}
  Dashboard: http://localhost:8000
  
  Presiona Ctrl+C para detener

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
        
        self.running = True
        
        # Iniciar thread de estadísticas
        stats_thread = threading.Thread(target=self.save_stats, daemon=True)
        stats_thread.start()
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                count=packet_count,
                filter=filter_str
            )
        except KeyboardInterrupt:
            print("\n\n✓ Captura detenida por el usuario")
        except PermissionError:
            print("\n✗ Error: Se requieren permisos de administrador")
            print("  Ejecuta con: sudo python3 backend/sniffer.py")
        except Exception as e:
            print(f"\n✗ Error: {e}")
        finally:
            self.running = False
            self.generate_report()
    
    def generate_report(self):
        """Genera reporte final"""
        stats = self.analyzer.get_stats()
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                     REPORTE DE ANÁLISIS                      ║
╚══════════════════════════════════════════════════════════════╝

ESTADÍSTICAS GENERALES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total de paquetes: {stats['total_packets']:,}
  Tiempo de captura: {stats['uptime']}s
  Paquetes/segundo:  {stats['packets_per_second']:.2f}
  Alertas generadas: {stats['alerts_count']}

DISTRIBUCIÓN DE PROTOCOLOS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        for protocol, count in sorted(stats['protocol_distribution'].items(), 
                                     key=lambda x: x[1], reverse=True):
            percentage = (count / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            bar = '█' * int(percentage / 2)
            report += f"  {protocol:10s} {count:6,} ({percentage:5.1f}%) {bar}\n"
        
        if stats['top_ips']:
            report += f"\nTOP DIRECCIONES IP\n"
            report += "━" * 62 + "\n"
            for ip, count in list(stats['top_ips'].items())[:5]:
                report += f"  {ip:20s} {count:6,} conexiones\n"
        
        if stats['suspicious_ips']:
            report += f"\nIPs SOSPECHOSAS\n"
            report += "━" * 62 + "\n"
            for ip in stats['suspicious_ips']:
                report += f"  ⚠ {ip}\n"
        
        if stats['recent_alerts']:
            report += f"\nALERTAS RECIENTES\n"
            report += "━" * 62 + "\n"
            for alert in stats['recent_alerts']:
                severity_symbol = "●" if alert['severity'] == 'high' else "○"
                report += f"  {severity_symbol} [{alert['severity'].upper()}] {alert['message']}\n"
        
        report += "\n" + "═" * 62 + "\n"
        print(report)
        
        # Guardar reporte
        report_file = os.path.join(self.logs_dir, 
                                   f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Reporte guardado: {report_file}\n")


def main():
    """Punto de entrada principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='FRV Sniffer - Network Traffic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python sniffer.py                    # Captura en interface por defecto
  python sniffer.py -i eth0            # Interface específica
  python sniffer.py -c 1000            # Captura 1000 paquetes
  python sniffer.py -f "port 80"       # Filtra solo HTTP
        """
    )
    
    parser.add_argument('-i', '--interface', help='Interface de red')
    parser.add_argument('-c', '--count', type=int, default=0, 
                       help='Número de paquetes (0 = infinito)')
    parser.add_argument('-f', '--filter', help='Filtro BPF')
    
    args = parser.parse_args()
    
    sniffer = FRVSniffer(interface=args.interface)
    sniffer.start_capture(packet_count=args.count, filter_str=args.filter)


if __name__ == "__main__":
    main()
