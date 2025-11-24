import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Ajuste os nomes dos arquivos se forem diferentes
ARQ_APLICACAO = Path("aplicacao.csv")
ARQ_INTERNET = Path("internet.csv")
ARQ_TRANSPORTE = Path("transporte.csv")  # se o seu for "transposte.csv", troque aqui

def carregar_dados():
    # parse_dates converte timestamp pra datetime (bom pra agrupar por tempo depois)
    df_app = pd.read_csv(ARQ_APLICACAO, parse_dates=["timestamp"])
    df_net = pd.read_csv(ARQ_INTERNET, parse_dates=["timestamp"])
    
    df_transp = pd.read_csv(ARQ_TRANSPORTE, parse_dates=["timestamp"])
    # garante que tamanho_bytes é numérico
    for df in (df_net, df_transp):
        df["tamanho_bytes"] = pd.to_numeric(df["tamanho_bytes"], errors="coerce").fillna(0).astype(int)

    return df_app, df_net, df_transp

def grafico_aplicacao(df_app):
    """Gráficos da camada de aplicação."""
    # Contagem de pacotes por protocolo (HTTP, DNS, etc.)
    contagem = df_app["protocolo"].value_counts()

    plt.figure()
    contagem.plot(kind="bar")
    plt.title("Camada de Aplicação - Pacotes por Protocolo")
    plt.xlabel("Protocolo")
    plt.ylabel("Quantidade de Pacotes")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()

    # Pacotes por segundo na aplicação (atividade ao longo do tempo)
    df_app_res = df_app.set_index("timestamp").resample("1S").size()

    plt.figure()
    df_app_res.plot()
    plt.title("Camada de Aplicação - Pacotes por Segundo")
    plt.xlabel("Tempo (s)")
    plt.ylabel("Qtd de Pacotes")
    plt.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()

def grafico_internet(df_net):
    """Gráficos da camada Internet."""
    # Bytes por protocolo (IPv4, IPv6, ICMP, Other)
    bytes_por_proto = df_net.groupby("protocolo")["tamanho_bytes"].sum()

    plt.figure()
    bytes_por_proto.plot(kind="bar")
    plt.title("Camada Internet - Bytes por Protocolo")
    plt.xlabel("Protocolo")
    plt.ylabel("Total de Bytes")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()

    # Top 5 IPs de destino por volume de dados
    df_ip = df_net[df_net["dst_ip"] != "-"]  # ignora frames sem IP
    if not df_ip.empty:
        top_dst = (
            df_ip.groupby("dst_ip")["tamanho_bytes"]
            .sum()
            .sort_values(ascending=False)
            .head(5)
        )

        plt.figure()
        top_dst.plot(kind="bar")
        plt.title("Camada Internet - Top 5 IPs de Destino por Bytes")
        plt.xlabel("IP de Destino")
        plt.ylabel("Total de Bytes")
        plt.xticks(rotation=45, ha="right")
        plt.grid(axis="y", linestyle="--", alpha=0.5)
        plt.tight_layout()

def grafico_transporte(df_transp):
    """Gráficos da camada de transporte."""
    # Bytes por protocolo (TCP/UDP) – no seu caso deve ser só TCP, mas já fica genérico
    bytes_por_proto = df_transp.groupby("protocolo")["tamanho_bytes"].sum()

    plt.figure()
    bytes_por_proto.plot(kind="bar")
    plt.title("Camada de Transporte - Bytes por Protocolo")
    plt.xlabel("Protocolo")
    plt.ylabel("Total de Bytes")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()

    # Top 5 portas de destino por tráfego
    top_ports = (
        df_transp.groupby("dst_port")["tamanho_bytes"]
        .sum()
        .sort_values(ascending=False)
        .head(5)
    )

    plt.figure()
    top_ports.plot(kind="bar")
    plt.title("Camada de Transporte - Top 5 Portas de Destino por Bytes")
    plt.xlabel("Porta de Destino")
    plt.ylabel("Total de Bytes")
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()

def main():
    df_app, df_net, df_transp = carregar_dados()

    grafico_aplicacao(df_app)
    grafico_internet(df_net)
    grafico_transporte(df_transp)

    # Mostra todas as figuras abertas
    plt.show()

if __name__ == "__main__":
    main()
