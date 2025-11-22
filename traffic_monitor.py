import csv
import datetime
import ipaddress
import os
import socket
import struct
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

INTERNET_LOG = "internet.csv"
TRANSPORTE_LOG = "transporte.csv"
APLICACAO_LOG = "aplicacao.csv"
TUNNEL_NET = ipaddress.ip_network("172.31.66.0/24")
MONITOR_IFACE = os.environ.get("MONITOR_INTERFACE", "tun0")

STATS_LOCK = threading.Lock()
traffic_counts = {
    "ip": Counter(),          # IPv4, IPv6, ICMP, Other
    "transport": Counter(),   # TCP, UDP, Other
    "application": Counter(), # HTTP, DHCP, DNS, NTP, Other
    "total_packets": 0,
}
client_view = defaultdict(
    lambda: {
        "packets": 0,
        "bytes": 0,
        "remotes": defaultdict(
            lambda: {"packets": 0, "bytes": 0, "ports": Counter(), "protocols": Counter()}
        ),
    }
)


def ensure_log(file_path: str, header: list[str]):
    path = Path(file_path)
    if not path.exists():
        with path.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def reset_log(file_path: str, header: list[str]):
    with Path(file_path).open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)


def append_row(file_path: str, row: list[str]):
    with Path(file_path).open("a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(row)


def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def packet_length(packet: bytes) -> int:
    return len(packet)


def is_client_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in TUNNEL_NET
    except ValueError:
        return False


def update_client_stats(src_ip: str, dst_ip: str, proto_name: str, src_port: int | None, dst_port: int | None, size: int):
    client_ip = None
    remote_ip = None
    if is_client_ip(src_ip):
        client_ip = src_ip
        remote_ip = dst_ip
        port_seen = dst_port
    elif is_client_ip(dst_ip):
        client_ip = dst_ip
        remote_ip = src_ip
        port_seen = src_port
    else:
        return

    with STATS_LOCK:
        cstats = client_view[client_ip]
        cstats["packets"] += 1
        cstats["bytes"] += size
        rem = cstats["remotes"][remote_ip]
        rem["packets"] += 1
        rem["bytes"] += size
        if port_seen:
            rem["ports"][port_seen] += 1
        if proto_name:
            rem["protocols"][proto_name] += 1


def log_internet(proto_name: str, src_ip: str, dst_ip: str, carried_proto: int, extra_info: str, size: int):
    append_row(
        INTERNET_LOG,
        [timestamp(), proto_name, src_ip, dst_ip, carried_proto, extra_info or "-", size],
    )


def log_transporte(proto_name: str, src_ip: str, src_port: int | None, dst_ip: str, dst_port: int | None, size: int):
    append_row(
        TRANSPORTE_LOG,
        [timestamp(), proto_name, src_ip, src_port or "-", dst_ip, dst_port or "-", size],
    )


def log_aplicacao(proto_name: str, info: str):
    append_row(APLICACAO_LOG, [timestamp(), proto_name, info or "-"])


def increment_counter(layer: str, key: str):
    with STATS_LOCK:
        traffic_counts[layer][key] += 1
        if layer == "ip":
            traffic_counts["total_packets"] += 1


def parse_ethernet(packet: bytes):
    """Parse Ethernet, handling optional VLAN tags."""
    if len(packet) < 14:
        return None, None
    offset = 14
    _, _, proto = struct.unpack("!6s6sH", packet[:14])

    # VLAN tagging (802.1Q or QinQ)
    if proto in (0x8100, 0x88A8) and len(packet) >= offset + 4:
        _, proto = struct.unpack("!HH", packet[offset : offset + 4])
        offset += 4

    return proto, packet[offset:]


def process_packet(packet: bytes):
    eth_proto, payload = parse_ethernet(packet)
    if payload is None:
        return

    if eth_proto == 0x0800:
        process_ipv4_packet(payload)
    elif eth_proto == 0x86DD:
        process_ipv6_packet(payload)
    else:
        increment_counter("ip", "Other")
        log_internet("Other", "-", "-", eth_proto, "Non-IP frame", packet_length(packet))


def process_ipv4_packet(data: bytes):
    if len(data) < 20:
        return
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl:
        return
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    proto = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    total_length = iph[2]

    proto_name = "IPv4"
    extra_info = "-"
    if proto == 1:
        proto_name = "ICMP"
        extra_info = process_icmp_packet(data[ihl:total_length], src_ip, dst_ip, total_length)
    elif proto == 6:
        process_tcp_packet(data[ihl:total_length], src_ip, dst_ip, total_length)
    elif proto == 17:
        process_udp_packet(data[ihl:total_length], src_ip, dst_ip, total_length)
    else:
        extra_info = f"Proto {proto}"

    increment_counter("ip", proto_name)
    log_internet(proto_name, src_ip, dst_ip, proto, extra_info, total_length)


def process_ipv6_packet(data: bytes):
    if len(data) < 40:
        return
    ver_tc_flow, payload_len, next_header, hop_limit, src_raw, dst_raw = struct.unpack("!IHBB16s16s", data[:40])
    version = ver_tc_flow >> 28
    if version != 6:
        return
    src_ip = socket.inet_ntop(socket.AF_INET6, src_raw)
    dst_ip = socket.inet_ntop(socket.AF_INET6, dst_raw)
    payload = data[40:]
    total_length = payload_len + 40

    proto_name = "IPv6"
    extra_info = "-"
    if next_header == 58:  # ICMPv6
        proto_name = "ICMP"
        extra_info = process_icmp_packet(payload, src_ip, dst_ip, total_length, icmpv6=True)
    elif next_header == 6:
        process_tcp_packet(payload, src_ip, dst_ip, total_length)
    elif next_header == 17:
        process_udp_packet(payload, src_ip, dst_ip, total_length)

    increment_counter("ip", proto_name)
    log_internet(proto_name, src_ip, dst_ip, next_header, extra_info, total_length)


def describe_icmp(type_code: int, icmpv6: bool) -> str:
    icmp_types = {
        0: "Echo Reply",
        3: "Dest Unreachable",
        8: "Echo Request",
        11: "Time Exceeded",
    }
    icmpv6_types = {
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
    }
    return (icmpv6_types if icmpv6 else icmp_types).get(type_code, f"Type {type_code}")


def process_icmp_packet(data: bytes, src_ip: str, dst_ip: str, total_length: int, icmpv6: bool = False) -> str:
    if len(data) < 4:
        return "-"
    icmp_type, code, _ = struct.unpack("!BBH", data[:4])
    info = f"{describe_icmp(icmp_type, icmpv6)} (code {code})"
    update_client_stats(src_ip, dst_ip, "ICMP", None, None, total_length)
    return info


def process_tcp_packet(data: bytes, src_ip: str, dst_ip: str, total_length: int):
    if len(data) < 20:
        return
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    src_port, dst_port = tcph[0], tcph[1]
    data_offset = (tcph[4] >> 4) * 4
    payload = data[data_offset:]

    increment_counter("transport", "TCP")
    log_transporte("TCP", src_ip, src_port, dst_ip, dst_port, total_length)
    update_client_stats(src_ip, dst_ip, "TCP", src_port, dst_port, total_length)
    detect_application("TCP", src_ip, dst_ip, src_port, dst_port, payload)


def process_udp_packet(data: bytes, src_ip: str, dst_ip: str, total_length: int):
    if len(data) < 8:
        return
    src_port, dst_port, length, _ = struct.unpack("!HHHH", data[:8])
    payload = data[8:length] if length <= len(data) else data[8:]

    increment_counter("transport", "UDP")
    log_transporte("UDP", src_ip, src_port, dst_ip, dst_port, total_length)
    update_client_stats(src_ip, dst_ip, "UDP", src_port, dst_port, total_length)
    detect_application("UDP", src_ip, dst_ip, src_port, dst_port, payload)


def detect_application(proto: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes):
    app_proto = "Other"
    info = ""
    ports = {src_port, dst_port}

    if 53 in ports:
        app_proto, info = "DNS", describe_dns(payload)
    elif 67 in ports or 68 in ports:
        app_proto, info = "DHCP", describe_dhcp(payload)
    elif 123 in ports:
        app_proto, info = "NTP", describe_ntp(payload)
    elif any(p in ports for p in (80, 8080, 8000, 443, 3128)):
        app_proto, info = "HTTP", describe_http(payload)

    increment_counter("application", app_proto)
    log_aplicacao(app_proto, info)
    update_client_stats(src_ip, dst_ip, app_proto, src_port, dst_port, len(payload))


def describe_http(payload: bytes) -> str:
    try:
        text = payload[:200].decode("utf-8", errors="replace")
    except Exception:
        return "HTTP payload"
    line = text.splitlines()[0].strip() if text else ""
    http_starts = ("GET ", "POST ", "PUT ", "HEAD ", "PATCH ", "DELETE ", "OPTIONS ", "HTTP/1", "HTTP/2")
    if line.startswith(http_starts):
        return line or "HTTP data"
    sample = payload[:50]
    if sample:
        nonprint = sum(
            1
            for b in sample
            if b < 9 or (13 < b < 32) or b > 126
        )
        if nonprint / len(sample) > 0.3:
            return "TLS/Encrypted payload"
    return line or "HTTP data"


def describe_dns(payload: bytes) -> str:
    if len(payload) < 12:
        return "DNS packet"
    tid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    qr = (flags >> 15) & 1
    rcode = flags & 0xF
    role = "Response" if qr else "Query"
    return f"{role} id={tid} qd={qdcount} an={ancount} rcode={rcode}"


def describe_dhcp(payload: bytes) -> str:
    if len(payload) < 240:
        return "DHCP/BOOTP packet"
    options = payload[240:]
    msg_type = None
    idx = 0
    while idx < len(options):
        opt = options[idx]
        if opt == 255:
            break
        if opt == 0:
            idx += 1
            continue
        if idx + 1 >= len(options):
            break
        length = options[idx + 1]
        value = options[idx + 2 : idx + 2 + length]
        if opt == 53 and value:
            msg_type = value[0]
            break
        idx += 2 + length
    msg_names = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        5: "ACK",
        6: "NAK",
        7: "Release",
    }
    return f"DHCP {msg_names.get(msg_type, 'Message')}" if msg_type is not None else "DHCP packet"


def describe_ntp(payload: bytes) -> str:
    if not payload:
        return "NTP packet"
    li_vn_mode = payload[0]
    mode = li_vn_mode & 0x07
    modes = {
        1: "Sym Active",
        2: "Sym Passive",
        3: "Client",
        4: "Server",
    }
    return f"NTP mode={modes.get(mode, mode)}"


def print_status_loop(stop_event: threading.Event, refresh: float = 2.0):
    while not stop_event.is_set():
        time.sleep(refresh)
        with STATS_LOCK:
            ip_counts = traffic_counts["ip"].copy()
            transport_counts = traffic_counts["transport"].copy()
            app_counts = traffic_counts["application"].copy()
            total = traffic_counts["total_packets"]
            clients_snapshot = {
                c: {
                    "packets": data["packets"],
                    "bytes": data["bytes"],
                    "remotes": {
                        r: {
                            "packets": rem["packets"],
                            "bytes": rem["bytes"],
                            "top_ports": rem["ports"].most_common(3),
                            "top_protocols": rem["protocols"].most_common(3),
                        }
                        for r, rem in data["remotes"].items()
                    },
                }
                for c, data in client_view.items()
            }
        print("\033[2J\033[H", end="")  # clear
        print(f"Monitor de Trafego ({MONITOR_IFACE})")
        print(f"Total de pacotes: {total}")
        print("\nCamada Internet:")
        for k in ("IPv4", "IPv6", "ICMP", "Other"):
            print(f"  {k:<5}: {ip_counts.get(k, 0)}")
        print("\nCamada Transporte:")
        for k in ("TCP", "UDP", "Other"):
            print(f"  {k:<3}: {transport_counts.get(k, 0)}")
        print("\nCamada Aplicacao:")
        for k in ("HTTP", "DNS", "DHCP", "NTP", "Other"):
            print(f"  {k:<4}: {app_counts.get(k, 0)}")
        if clients_snapshot:
            print("\nClientes tunel:")
            for client, data in clients_snapshot.items():
                print(f"  {client} pkts={data['packets']} bytes={data['bytes']}")
                for remote, rem in list(data["remotes"].items())[:3]:
                    ports = ", ".join(f"{p}:{cnt}" for p, cnt in rem["top_ports"])
                    prots = ", ".join(f"{p}:{cnt}" for p, cnt in rem["top_protocols"])
                    print(f"    -> {remote} pkts={rem['packets']} bytes={rem['bytes']} ports[{ports}] prot[{prots}]")


def monitor_traffic(interface: str = "tun0"):
    global MONITOR_IFACE
    MONITOR_IFACE = interface
    print(f"Iniciando captura em {interface} (RAW SOCKET)...")
    print("Necessario executar como root (sudo). Ctrl+C para sair.")
    reset_log(INTERNET_LOG, ["timestamp", "protocolo", "src_ip", "dst_ip", "proto_interno", "info", "tamanho_bytes"])
    reset_log(TRANSPORTE_LOG, ["timestamp", "protocolo", "src_ip", "src_port", "dst_ip", "dst_port", "tamanho_bytes"])
    reset_log(APLICACAO_LOG, ["timestamp", "protocolo", "info"])

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))

    stop_event = threading.Event()
    display = threading.Thread(target=print_status_loop, args=(stop_event,), daemon=True)
    display.start()

    try:
        while True:
            packet, _ = sock.recvfrom(65535)
            process_packet(packet)
    except KeyboardInterrupt:
        print("\nEncerrando monitor...")
    finally:
        stop_event.set()
        display.join(timeout=1)
        sock.close()


if __name__ == "__main__":
    iface = os.environ.get("MONITOR_INTERFACE", "tun0")
    monitor_traffic(iface)
