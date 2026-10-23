import argparse
import os
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName


def load_pcap(file_path):
    """
    Reads a PCAP file and returns all packets.
    """
    return rdpcap(file_path)


def save2csv(packet_data, csv_file="output/packet_info.csv"):
    os.makedirs(os.path.dirname(csv_file), exist_ok=True)
    df = pd.DataFrame(packet_data)
    df.to_csv(csv_file, index=False)
    return df


def extractSNI(packet):
    """
    Returns SNI hostname if present in TLSClientHello.
    """
    if TLSClientHello not in packet:
        return None
    client_hello = packet[TLSClientHello]

    if not hasattr(client_hello, "ext") or not client_hello.ext:
        return None

    for ext in client_hello.ext:
        if isinstance(ext, TLS_Ext_ServerName):
            if hasattr(ext, "servernames") and ext.servernames:
                try:
                    sname = ext.servernames[0].servername
                    return sname.decode("utf-8", errors="ignore") if isinstance(sname, bytes) else str(sname)
                except Exception:
                    pass
    return None


def extract_packet_info(packets):
    """
    Extract useful metadata from IP packets.
    """
    packet_data = []

    for index, packet in enumerate(packets, start=1):
        if IP in packet:
            src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
            dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)

            proto_name = "TCP" if TCP in packet else ("UDP" if UDP in packet else str(packet[IP].proto))
            sni = extractSNI(packet)

            packet_data.append({
                "Packet No": index,
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Protocol": proto_name,
                "Length": len(packet),
                "Timestamp": float(packet.time),
                "SNI": sni if sni else ""
            })

    return packet_data


def parse_pcap(pcap_path, output_csv="output/packet_info.csv"):
    """
    Helper for direct programmatic call from Streamlit or API.
    """
    packets = load_pcap(pcap_path)
    packet_data = extract_packet_info(packets)
    df = save2csv(packet_data, output_csv)
    return packets, df


def display_packet_info(df):
    print("=" * 60)
    print("TLSProfiler - Packet Summary")
    print("=" * 60)
    print(f"Total IP Packets: {len(df)}\n")
    if not df.empty:
        print(df.head(10).to_string(index=False))


def main():
    parser = argparse.ArgumentParser(description="TLSProfiler PCAP Parser")
    parser.add_argument(
        "pcap",
        nargs="?",
        default="captures/reddit.pcap",
        help="Path to the PCAP file"
    )

    args = parser.parse_args()

    try:
        packets, df = parse_pcap(args.pcap)
        display_packet_info(df)
    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")
    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()