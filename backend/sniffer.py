#!/usr/bin/env python3
"""
FRV Sniffer - Network Traffic Analyzer
Advanced packet capture and anomaly detection system
By EstebanCRO
"""

import os
import sys
import json
import time
import signal
import socket
import logging
import threading
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Optional, List, Tuple

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether, conf
    from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
    from scapy.layers.http import HTTPRequest
except ImportError:
    print("=" * 70)
    print("ERROR: scapy no está instalado")
    print("=" * 70)
    print("\nPor favor ejecuta:")
    print("  pip install scapy --break-system-packages")
    print("=" * 70)
    sys.exit(1)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('FRV-Sniffer')

VERSION = "2.0.0"
AUTHOR = "EstebanCRO"


class PacketAnalyzer:
    """Analiza paquetes y detecta anomalías con thread-safety"""

    def __init__(self):
        self._lock = threading.Lock()
        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats = defaultdict(int)
        self.ip_connections = defaultdict(int)
        self.connection_pairs = defaultdict(int)  # src->dst pair tracking
        self.port_scans = defaultdict(lambda: {"ports": set(), "timestamps": deque(maxlen=100)})
        self.dns_queries = defaultdict(int)
        self.suspicious_ips = set()
        self.alerts = []
        self.traffic_history = deque(maxlen=1000)
        self.start_time = time.time()

        # ARP spoofing detection
        self.arp_table = {}  # IP -> MAC mapping

        # SYN flood detection
        self.syn_tracker = defaultdict(lambda: {"count": 0, "last_reset": time.time()})
        self.SYN_FLOOD_THRESHOLD = 100  # SYNs per window
        self.SYN_FLOOD_WINDOW = 10     # seconds

        # Bandwidth tracking
        self.bandwidth_history = deque(maxlen=300)  # 5 min at 1s intervals
        self._bytes_this_second = 0
        self._last_bw_tick = time.time()

        # Detection thresholds
        self.PORT_SCAN_THRESHOLD = 10
        self.PORT_SCAN_WINDOW = 10
        self.CONNECTION_THRESHOLD = 50
        self.DNS_QUERY_THRESHOLD = 30

    def analyze_packet(self, packet) -> Dict:
        """Analiza un paquete y retorna información estructurada"""
        with self._lock:
            self.packet_count += 1
            pkt_len = len(packet)
            self.total_bytes += pkt_len
            self._bytes_this_second += pkt_len

        timestamp = datetime.now().isoformat()

        packet_info = {
            "id": self.packet_count,
            "timestamp": timestamp,
            "protocol": "Unknown",
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "length": pkt_len,
            "info": "",
            "anomaly": False,
            "alert_type": None
        }

        # ARP layer — detect spoofing
        if ARP in packet:
            packet_info["protocol"] = "ARP"
            packet_info["info"] = f"Op: {packet[ARP].op}"
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            packet_info["src_ip"] = src_ip

            if packet[ARP].op == 2:  # ARP reply
                self._check_arp_spoofing(src_ip, src_mac)

        # IP layer
        if IP in packet:
            packet_info["src_ip"] = packet[IP].src
            packet_info["dst_ip"] = packet[IP].dst
            packet_info["protocol"] = str(packet[IP].proto)

            with self._lock:
                self.ip_connections[packet[IP].src] += 1
                pair_key = f"{packet[IP].src} → {packet[IP].dst}"
                self.connection_pairs[pair_key] += 1

            if self.ip_connections[packet[IP].src] > self.CONNECTION_THRESHOLD:
                self._add_alert("connection_flood", packet[IP].src,
                                f"Excesivas conexiones desde {packet[IP].src}")
                packet_info["anomaly"] = True
                packet_info["alert_type"] = "connection_flood"

        # Transport layer
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
            packet_info["info"] = f"{packet[TCP].sport} → {packet[TCP].dport}"

            flags = packet[TCP].flags
            if flags:
                packet_info["info"] += f" [{flags}]"

            # SYN flood detection
            if flags and 'S' in str(flags) and 'A' not in str(flags):
                if IP in packet:
                    self._check_syn_flood(packet[IP].dst)

            # Port scan detection
            if IP in packet:
                self._check_port_scan(packet[IP].src, packet[TCP].dport, timestamp)
                if packet[IP].src in self.suspicious_ips:
                    packet_info["anomaly"] = True
                    packet_info["alert_type"] = "port_scan"

        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport
            packet_info["info"] = f"{packet[UDP].sport} → {packet[UDP].dport}"

        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                          11: "TTL Exceeded", 5: "Redirect"}
            packet_info["info"] = f"Type {packet[ICMP].type} ({icmp_types.get(packet[ICMP].type, 'Other')})"

        # Application layer
        if DNS in packet:
            packet_info["protocol"] = "DNS"
            if packet.haslayer(DNS) and packet[DNS].qd:
                try:
                    query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    packet_info["info"] = f"Query: {query}"
                    with self._lock:
                        self.dns_queries[query] += 1

                    if self.dns_queries[query] > self.DNS_QUERY_THRESHOLD:
                        self._add_alert("dns_anomaly", query,
                                        f"Queries excesivas para {query}")
                        packet_info["anomaly"] = True
                        packet_info["alert_type"] = "dns_anomaly"
                except (UnicodeDecodeError, AttributeError):
                    pass

        if packet.haslayer(HTTPRequest):
            packet_info["protocol"] = "HTTP"
            try:
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode() if http_layer.Method else "GET"
                host = http_layer.Host.decode() if http_layer.Host else ""
                path = http_layer.Path.decode() if http_layer.Path else "/"
                packet_info["info"] = f"{method} {host}{path}"
            except (UnicodeDecodeError, AttributeError):
                packet_info["info"] = "HTTP Request"

        with self._lock:
            self.protocol_stats[packet_info["protocol"]] += 1
            self.traffic_history.append({
                "timestamp": timestamp,
                "protocol": packet_info["protocol"],
                "length": packet_info["length"]
            })

        return packet_info

    def _check_arp_spoofing(self, ip: str, mac: str):
        """Detecta ARP spoofing comparando IP→MAC mappings"""
        with self._lock:
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    self._add_alert("arp_spoofing", ip,
                                    f"ARP Spoofing detectado: {ip} cambió de {self.arp_table[ip]} a {mac}")
                    self.suspicious_ips.add(ip)
            self.arp_table[ip] = mac

    def _check_syn_flood(self, target_ip: str):
        """Detecta SYN flood por volumen de SYN hacia un destino"""
        with self._lock:
            tracker = self.syn_tracker[target_ip]
            now = time.time()

            if now - tracker["last_reset"] > self.SYN_FLOOD_WINDOW:
                tracker["count"] = 0
                tracker["last_reset"] = now

            tracker["count"] += 1

            if tracker["count"] >= self.SYN_FLOOD_THRESHOLD:
                self._add_alert("syn_flood", target_ip,
                                f"Posible SYN Flood hacia {target_ip} ({tracker['count']} SYNs en {self.SYN_FLOOD_WINDOW}s)")
                tracker["count"] = 0  # Reset para no spamear alertas

    def _check_port_scan(self, src_ip: str, dst_port: int, timestamp: str):
        """Detecta escaneo de puertos"""
        with self._lock:
            scan_data = self.port_scans[src_ip]
            scan_data["ports"].add(dst_port)
            scan_data["timestamps"].append(time.time())

            if len(scan_data["timestamps"]) >= 2:
                time_diff = scan_data["timestamps"][-1] - scan_data["timestamps"][0]
                if time_diff <= self.PORT_SCAN_WINDOW and len(scan_data["ports"]) >= self.PORT_SCAN_THRESHOLD:
                    if src_ip not in self.suspicious_ips:
                        self.suspicious_ips.add(src_ip)
                        self._add_alert("port_scan", src_ip,
                                        f"Posible escaneo de puertos desde {src_ip} ({len(scan_data['ports'])} puertos)")

    def _add_alert(self, alert_type: str, source: str, message: str):
        """Agrega una alerta de seguridad"""
        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "source": source,
            "message": message,
            "severity": self._get_severity(alert_type)
        }
        self.alerts.append(alert)
        severity = alert["severity"].upper()
        logger.warning(f"⚠ ALERTA [{severity}]: {message}")

    def _get_severity(self, alert_type: str) -> str:
        """Determina severidad de alerta"""
        severity_map = {
            "port_scan": "high",
            "syn_flood": "critical",
            "arp_spoofing": "critical",
            "connection_flood": "medium",
            "dns_anomaly": "medium",
            "suspicious_traffic": "low"
        }
        return severity_map.get(alert_type, "low")

    def update_bandwidth(self):
        """Actualiza métricas de ancho de banda (llamar cada segundo)"""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_bw_tick
            if elapsed >= 1.0:
                bps = self._bytes_this_second / max(elapsed, 0.001)
                self.bandwidth_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "bytes_per_second": round(bps, 2),
                    "bytes": self._bytes_this_second
                })
                self._bytes_this_second = 0
                self._last_bw_tick = now

    def get_stats(self) -> Dict:
        """Obtiene estadísticas actuales (thread-safe)"""
        with self._lock:
            uptime = int(time.time() - self.start_time)
            pps = self.packet_count / max(1, uptime)

            return {
                "total_packets": self.packet_count,
                "total_bytes": self.total_bytes,
                "protocol_distribution": dict(self.protocol_stats),
                "top_ips": dict(sorted(self.ip_connections.items(),
                                       key=lambda x: x[1], reverse=True)[:10]),
                "top_connections": dict(sorted(self.connection_pairs.items(),
                                               key=lambda x: x[1], reverse=True)[:10]),
                "alerts_count": len(self.alerts),
                "recent_alerts": self.alerts[-10:],
                "all_alerts": list(self.alerts),
                "suspicious_ips": list(self.suspicious_ips),
                "uptime": uptime,
                "packets_per_second": round(pps, 2),
                "bandwidth_history": list(self.bandwidth_history)[-60:],
                "dns_top": dict(sorted(self.dns_queries.items(),
                                       key=lambda x: x[1], reverse=True)[:10])
            }


class FRVSniffer:
    """FRV Sniffer - Analizador principal de red"""

    def __init__(self, interface: Optional[str] = None, search_str: Optional[str] = None):
        self.interface = interface
        self.search_str = search_str
        self.analyzer = PacketAnalyzer()
        self.running = False
        self.packet_queue = deque(maxlen=100)
        self._file_lock = threading.Lock()

        # Paths relative to project root
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.data_dir = os.path.join(script_dir, "data")
        self.logs_dir = os.path.join(script_dir, "logs")

        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

        self.data_file = os.path.join(self.data_dir, "packets.jsonl")
        self.stats_file = os.path.join(self.data_dir, "stats.json")

    def packet_handler(self, packet):
        """Maneja cada paquete capturado"""
        try:
            packet_info = self.analyzer.analyze_packet(packet)

            # Si hay un filtro de búsqueda de contenido en paquetes
            if self.search_str:
                search_term = self.search_str.lower()
                match = False
                
                # Campos clave donde buscar coincidencia
                if packet_info["src_ip"] and search_term in packet_info["src_ip"].lower():
                    match = True
                elif packet_info["dst_ip"] and search_term in packet_info["dst_ip"].lower():
                    match = True
                elif packet_info["protocol"] and search_term in packet_info["protocol"].lower():
                    match = True
                elif packet_info["info"] and search_term in packet_info["info"].lower():
                    match = True
                
                # Si no coincide con el filtro, descartamos el paquete sin registrarlo ni contarlo
                if not match:
                    return

            self.packet_queue.append(packet_info)

            with self._file_lock:
                with open(self.data_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(packet_info, ensure_ascii=False) + '\n')

        except Exception as e:
            logger.debug(f"Error procesando paquete: {e}")

    def save_stats(self):
        """Guarda estadísticas periódicamente"""
        while self.running:
            try:
                self.analyzer.update_bandwidth()
                stats = self.analyzer.get_stats()
                with self._file_lock:
                    with open(self.stats_file, 'w', encoding='utf-8') as f:
                        json.dump(stats, f, indent=2, ensure_ascii=False)
                time.sleep(1)
            except Exception as e:
                logger.debug(f"Error guardando stats: {e}")

    def _signal_handler(self, signum, frame):
        """Manejo limpio de señales de terminación"""
        sig_name = signal.Signals(signum).name
        logger.info(f"Señal {sig_name} recibida, deteniendo captura...")
        self.running = False

    def start_capture(self, packet_count: int = 0, filter_str: Optional[str] = None):
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
  Filter BPF:{filter_str or 'Ninguno'}
  Búsqueda:  {self.search_str or 'Ninguno'}
  Dashboard: http://localhost:8000

  Detección activa:
    ✓ Port Scanning (>{self.analyzer.PORT_SCAN_THRESHOLD} puertos/{self.analyzer.PORT_SCAN_WINDOW}s)
    ✓ SYN Flood (>{self.analyzer.SYN_FLOOD_THRESHOLD} SYNs/{self.analyzer.SYN_FLOOD_WINDOW}s)
    ✓ ARP Spoofing (IP→MAC inconsistente)
    ✓ Connection Flood (>{self.analyzer.CONNECTION_THRESHOLD} conexiones/IP)
    ✓ DNS Anomaly (>{self.analyzer.DNS_QUERY_THRESHOLD} queries/dominio)

  Presiona Ctrl+C para detener

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

        self.running = True

        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        # Stats thread
        stats_thread = threading.Thread(target=self.save_stats, daemon=True)
        stats_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                count=packet_count,
                filter=filter_str,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            logger.error("Se requieren permisos de administrador")
            logger.error("Ejecuta con: sudo python3 backend/sniffer.py")
        except Exception as e:
            logger.error(f"Error durante captura: {e}")
        finally:
            self.running = False
            self.generate_report()

    def generate_report(self):
        """Genera reporte final"""
        stats = self.analyzer.get_stats()

        def format_bytes(b):
            for unit in ['B', 'KB', 'MB', 'GB']:
                if b < 1024:
                    return f"{b:.1f} {unit}"
                b /= 1024
            return f"{b:.1f} TB"

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║                     REPORTE DE ANÁLISIS                      ║
╚══════════════════════════════════════════════════════════════╝

ESTADÍSTICAS GENERALES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total de paquetes:  {stats['total_packets']:,}
  Datos transferidos: {format_bytes(stats['total_bytes'])}
  Tiempo de captura:  {stats['uptime']}s
  Paquetes/segundo:   {stats['packets_per_second']:.2f}
  Alertas generadas:  {stats['alerts_count']}

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

        if stats['top_connections']:
            report += f"\nTOP CONEXIONES\n"
            report += "━" * 62 + "\n"
            for pair, count in list(stats['top_connections'].items())[:5]:
                report += f"  {pair:40s} {count:6,}\n"

        if stats['suspicious_ips']:
            report += f"\nIPs SOSPECHOSAS\n"
            report += "━" * 62 + "\n"
            for ip in stats['suspicious_ips']:
                report += f"  ⚠ {ip}\n"

        if stats['all_alerts']:
            report += f"\nTODAS LAS ALERTAS ({len(stats['all_alerts'])})\n"
            report += "━" * 62 + "\n"
            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            for alert in stats['all_alerts']:
                icon = severity_icons.get(alert['severity'], "○")
                report += f"  {icon} [{alert['severity'].upper():8s}] {alert['message']}\n"

        report += "\n" + "═" * 62 + "\n"
        print(report)

        # Save report
        report_file = os.path.join(self.logs_dir,
                                   f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Reporte guardado: {report_file}")
        except Exception as e:
            logger.error(f"Error guardando reporte: {e}")



def list_interfaces() -> List[Tuple[str, str, str]]:
    """Lista todas las interfaces de red disponibles con IP y MAC"""
    interfaces = []
    try:
        iface_list = get_if_list()
        for iface in iface_list:
            try:
                ip = get_if_addr(iface)
                try:
                    mac = get_if_hwaddr(iface)
                except Exception:
                    mac = "N/A"
                if ip == "0.0.0.0":
                    ip = "(no IP)"
                interfaces.append((iface, ip, mac))
            except Exception:
                interfaces.append((iface, "(error)", "N/A"))
    except Exception as e:
        logger.error(f"Error listando interfaces: {e}")

    return interfaces


def select_interface_interactive() -> Optional[str]:
    """Menú interactivo para seleccionar interfaz de red (estilo Wireshark)"""
    interfaces = list_interfaces()

    if not interfaces:
        logger.error("No se encontraron interfaces de red")
        return None

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                       FRV SNIFFER v{VERSION}                     ║
║             Network Traffic Analysis System                  ║
║                      By {AUTHOR}                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  INTERFACES DE RED DISPONIBLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

    # Header
    print(f"  {'#':>3}  {'INTERFAZ':<20} {'DIRECCIÓN IP':<18} {'MAC ADDRESS':<20}")
    print(f"  {'─'*3}  {'─'*20} {'─'*18} {'─'*20}")

    for idx, (iface, ip, mac) in enumerate(interfaces, 1):
        # Highlight interfaces with valid IPs
        marker = "●" if ip not in ("(no IP)", "(error)") else "○"
        print(f"  {idx:>3}  {marker} {iface:<18} {ip:<18} {mac:<20}")

    # Default interface suggestion
    default_iface = conf.iface if hasattr(conf, 'iface') else None
    default_idx = None
    if default_iface:
        for idx, (iface, _, _) in enumerate(interfaces, 1):
            if iface == default_iface:
                default_idx = idx
                break

    print()
    print("━" * 62)

    default_hint = f" [default: {default_idx} - {default_iface}]" if default_idx else ""
    print(f"\n  0 = Todas las interfaces (captura en todas)")

    while True:
        try:
            prompt = f"\n  ▶ Selecciona interfaz (1-{len(interfaces)}, 0=todas){default_hint}: "
            choice = input(prompt).strip()

            if choice == "" and default_idx:
                selected = interfaces[default_idx - 1][0]
                print(f"\n  ✓ Seleccionada: {selected} (default)")
                return selected

            choice = int(choice)

            if choice == 0:
                print(f"\n  ✓ Captura en TODAS las interfaces")
                return None

            if 1 <= choice <= len(interfaces):
                selected = interfaces[choice - 1][0]
                selected_ip = interfaces[choice - 1][1]
                print(f"\n  ✓ Seleccionada: {selected} ({selected_ip})")
                return selected

            print(f"  ✗ Opción inválida. Usa 0-{len(interfaces)}")

        except ValueError:
            print(f"  ✗ Ingresa un número válido (0-{len(interfaces)})")
        except (EOFError, KeyboardInterrupt):
            print("\n\n  ✗ Cancelado por el usuario")
            sys.exit(0)


def print_banner():
    """Imprime el banner principal de FRV Sniffer"""
    RS = "\033[0m"
    Y = "\033[93m"
    M = "\033[95m"
    C = "\033[96m"
    print(f"""{C}    ██████╗██████╗  ██████╗  ██████╗██╗  ██╗
  ██╔════╝██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝
  ██║     ██████╔╝██║   ██║██║     █████╔╝ 
  ██║     ██╔══██╗██║   ██║██║     ██╔═██╗ 
  ╚██████╗██║  ██║╚██████╔╝╚██████╗██║  ██╗
   ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{RS}
    {Y}Sniffer FRV{RS}
                 {M}by EstebanCRO{RS}
""")


def main():
    """Punto de entrada principal"""
    import argparse

    parser = argparse.ArgumentParser(
        description=f'FRV Sniffer v{VERSION} By {AUTHOR} - Network Traffic Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Ejemplos de uso:
  python sniffer.py                    # Modo interactivo (seleccionar interfaz)
  python sniffer.py -i eth0            # Interface específica
  python sniffer.py -l                 # Listar interfaces disponibles
  python sniffer.py -c 1000            # Captura 1000 paquetes
  python sniffer.py -p tcp             # Filtrar solo TCP
  python sniffer.py -p dns             # Filtrar solo DNS
  python sniffer.py -f "port 80"       # Filtra solo puerto 80 (HTTP)
  python sniffer.py -f "host 10.0.0.1" # Solo tráfico de/hacia una IP

FRV Sniffer v{VERSION} — By {AUTHOR}
        """
    )

    parser.add_argument('-i', '--interface', help='Interface de red (omitir para selección interactiva)')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Número de paquetes (0 = infinito)')
    parser.add_argument('-f', '--filter', help='Filtro BPF adicional')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp', 'dns', 'http', 'https', 'ftp', 'ssh', 'all'],
                        help='Filtrar captura por protocolo específico')
    parser.add_argument('-s', '--search', help='Filtro de búsqueda de texto dentro del paquete (IP, protocolo, info)')
    parser.add_argument('-l', '--list', action='store_true',
                        help='Listar interfaces de red disponibles y salir')

    args = parser.parse_args()

    print_banner()

    # List interfaces mode
    if args.list:
        interfaces = list_interfaces()
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("  INTERFACES DE RED DISPONIBLES")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"\n  {'#':>3}  {'INTERFAZ':<20} {'DIRECCIÓN IP':<18} {'MAC ADDRESS':<20}")
        print(f"  {'─'*3}  {'─'*20} {'─'*18} {'─'*20}")
        for idx, (iface, ip, mac) in enumerate(interfaces, 1):
            marker = "●" if ip not in ("(no IP)", "(error)") else "○"
            print(f"  {idx:>3}  {marker} {iface:<18} {ip:<18} {mac:<20}")
        print(f"\n  Total: {len(interfaces)} interfaces")
        print(f"\n  Default: {conf.iface if hasattr(conf, 'iface') else 'N/A'}\n")
        sys.exit(0)

    # Interface selection
    interface = args.interface
    if interface is None:
        # Interactive mode — let user choose
        interface = select_interface_interactive()

    # Protocol to BPF mapping
    proto_bpf = ""
    if args.protocol and args.protocol != 'all':
        mapping = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'dns': 'udp port 53',
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'ftp': 'tcp port 21 or tcp port 20',
            'ssh': 'tcp port 22'
        }
        proto_bpf = mapping.get(args.protocol, "")

    # Combine BPF filters
    final_filter = args.filter
    if proto_bpf:
        if final_filter:
            final_filter = f"({proto_bpf}) and ({final_filter})"
        else:
            final_filter = proto_bpf

    sniffer = FRVSniffer(interface=interface, search_str=args.search)
    sniffer.start_capture(packet_count=args.count, filter_str=final_filter)


if __name__ == "__main__":
    main()

