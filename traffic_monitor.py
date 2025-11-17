import socket
import struct
import datetime

LOG_FILE = "traffic_log.txt"

# -----------------------------
# Helper: salva informação no log
# -----------------------------
def log_traffic_info(info: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {info}\n")


# -----------------------------
# Processa cada pacote bruto
# -----------------------------
def process_packet(packet):

    # -------------------------------------
    # 1. Cabeçalho Ethernet (14 bytes)
    # -------------------------------------
    eth_header = packet[:14]
    eth = struct.unpack("!6s6sH", eth_header)
    eth_proto = socket.ntohs(eth[2])

    # Tipos Ethernet relevantes
    if eth_proto == 0x0800:   # IPv4
        process_ipv4_packet(packet[14:])
    elif eth_proto == 0x86DD: # IPv6
        log_traffic_info("IPv6 packet captured")
    elif eth_proto == 0x0806: # ARP
        log_traffic_info("ARP packet captured")
    else:
        log_traffic_info(f"Other Ethernet protocol: {hex(eth_proto)}")


# -------------------------------------
# Processa cabeçalho IPv4
# -------------------------------------
def process_ipv4_packet(data):
    # Primeiro byte contém versão + IHL
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4

    # Campos básicos do IPv4
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    proto = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # Log de nível IP
    log_traffic_info(f"IPv4 | Proto={proto} | {src_ip} -> {dst_ip}")

    # -------------------------------------
    # Encaminha para parser do protocolo
    # -------------------------------------
    if proto == 1:
        process_icmp_packet(data[ihl:], src_ip, dst_ip)
    elif proto == 6:
        process_tcp_packet(data[ihl:], src_ip, dst_ip)
    elif proto == 17:
        process_udp_packet(data[ihl:], src_ip, dst_ip)
    else:
        log_traffic_info(f"IPv4 Other Protocol={proto}")


# -------------------------------------
# ICMP
# -------------------------------------
def process_icmp_packet(data, src_ip, dst_ip):
    icmph = struct.unpack("!BBH", data[:4])
    icmp_type = icmph[0]
    log_traffic_info(f"ICMP | Type={icmp_type} | {src_ip} -> {dst_ip}")


# -------------------------------------
# TCP
# -------------------------------------
def process_tcp_packet(data, src_ip, dst_ip):
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]

    log_traffic_info(f"TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


# -------------------------------------
# UDP
# -------------------------------------
def process_udp_packet(data, src_ip, dst_ip):
    udph = struct.unpack("!HHHH", data[:8])
    src_port = udph[0]
    dst_port = udph[1]

    log_traffic_info(f"UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")


# -------------------------------------
# Função principal: captura pacotes brutos
# -------------------------------------
def monitor_traffic():
    print("Iniciando captura de pacotes (RAW SOCKET)...")
    print("Necessário executar como root (sudo).")

    # Captura todos os pacotes Ethernet (promiscuous mode)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        packet, addr = sock.recvfrom(65535)
        process_packet(packet)


# Executa se for chamado diretamente
if __name__ == "__main__":
    monitor_traffic()
