import argparse
import os
import math
import hashlib
import pandas as pd

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedEllipticCurves,
    TLS_Ext_SupportedPointFormat
)


GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}


def load_pcap(file_path):
    """
    Read all packets from a PCAP file.
    """
    return rdpcap(file_path)


def get_tls_version(version):
    """
    Convert numeric TLS version into a readable string.
    """
    versions = {
        769: "TLS 1.0",
        770: "TLS 1.1",
        771: "TLS 1.2",
        772: "TLS 1.3",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3"
    }
    return versions.get(version, f"Unknown ({version})")


def calculate_shannon_entropy(text):
    """
    Calculate Shannon Entropy for a string: H(X) = -sum(p(x) * log2(p(x)))
    """
    if not text:
        return 0.0
    text_len = len(text)
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    entropy = 0.0
    for count in frequencies.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def filter_grease(val_list):
    """
    Filter out GREASE values from integer lists.
    """
    if not val_list:
        return []
    clean = []
    for item in val_list:
        try:
            val = int(item)
            if val not in GREASE_VALUES:
                clean.append(val)
        except (ValueError, TypeError):
            continue
    return clean


def extract_ja3(packet):
    """
    Extract JA3 string and MD5 hash from a TLS ClientHello packet.
    Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    if TLSClientHello not in packet:
        return "", ""

    ch = packet[TLSClientHello]
    version = getattr(ch, "version", 0)

    # Extract Cipher Suites
    raw_ciphers = getattr(ch, "ciphers", [])
    ciphers = filter_grease(raw_ciphers)
    ciphers_str = "-".join(map(str, ciphers))

    extensions = []
    curves = []
    ec_formats = []

    if hasattr(ch, "ext") and ch.ext:
        for ext in ch.ext:
            ext_type = getattr(ext, "type", None)
            if ext_type is not None:
                extensions.append(ext_type)

            # Supported Groups (Elliptic Curves)
            if isinstance(ext, (TLS_Ext_SupportedGroups, TLS_Ext_SupportedEllipticCurves)):
                if hasattr(ext, "groups"):
                    curves.extend(getattr(ext, "groups", []))
                elif hasattr(ext, "elliptic_curves"):
                    curves.extend(getattr(ext, "elliptic_curves", []))

            # Supported Point Formats
            if isinstance(ext, TLS_Ext_SupportedPointFormat):
                if hasattr(ext, "ecpl"):
                    ec_formats.extend(getattr(ext, "ecpl", []))
                elif hasattr(ext, "formats"):
                    ec_formats.extend(getattr(ext, "formats", []))


    extensions = filter_grease(extensions)
    curves = filter_grease(curves)
    ec_formats = filter_grease(ec_formats)

    ext_str = "-".join(map(str, extensions))
    curves_str = "-".join(map(str, curves))
    formats_str = "-".join(map(str, ec_formats))

    ja3_string = f"{version},{ciphers_str},{ext_str},{curves_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3_string.encode("utf-8")).hexdigest()

    return ja3_string, ja3_hash


def extract_ja3s(packet):
    """
    Extract JA3S string and MD5 hash from a TLS ServerHello packet.
    Format: TLSVersion,Cipher,Extensions
    """
    if TLSServerHello not in packet:
        return "", ""

    sh = packet[TLSServerHello]
    version = getattr(sh, "version", 0)
    cipher = getattr(sh, "cipher", 0)

    try:
        cipher = int(cipher)
    except (ValueError, TypeError):
        cipher = 0

    extensions = []
    if hasattr(sh, "ext") and sh.ext:
        for ext in sh.ext:
            ext_type = getattr(ext, "type", None)
            if ext_type is not None:
                extensions.append(ext_type)

    extensions = filter_grease(extensions)
    ext_str = "-".join(map(str, extensions))

    ja3s_string = f"{version},{cipher},{ext_str}"
    ja3s_hash = hashlib.md5(ja3s_string.encode("utf-8")).hexdigest()

    return ja3s_string, ja3s_hash


def extract_sni(packet):
    """
    Extract SNI hostname from ClientHello.
    """
    if TLSClientHello not in packet:
        return ""
    ch = packet[TLSClientHello]
    if not hasattr(ch, "ext") or not ch.ext:
        return ""
    for ext in ch.ext:
        if isinstance(ext, TLS_Ext_ServerName) and hasattr(ext, "servernames") and ext.servernames:
            try:
                sname = ext.servernames[0].servername
                return sname.decode("utf-8", errors="ignore") if isinstance(sname, bytes) else str(sname)
            except Exception:
                pass
    return ""


def extract_tls_features(packets):
    """
    Extract metadata, JA3/JA3S fingerprints, and entropy from TLS packets.
    """
    tls_data = []

    for index, packet in enumerate(packets, start=1):
        if IP in packet and TCP in packet and TLS in packet:
            tls_layer = packet[TLS]
            tcp_layer = packet[TCP]

            # Determine Handshake Record Type
            record_type = "TLS Record"
            if TLSClientHello in packet:
                record_type = "ClientHello"
            elif TLSServerHello in packet:
                record_type = "ServerHello"

            ja3_str, ja3_h = extract_ja3(packet)
            ja3s_str, ja3s_h = extract_ja3s(packet)
            sni = extract_sni(packet)
            entropy = calculate_shannon_entropy(sni)

            # String counts for numeric feature engineering
            ciphers_cnt = len(ja3_str.split(",")[1].split("-")) if ja3_str and ja3_str.split(",")[1] else 0
            ext_cnt = len(ja3_str.split(",")[2].split("-")) if ja3_str and ja3_str.split(",")[2] else 0
            curves_cnt = len(ja3_str.split(",")[3].split("-")) if ja3_str and ja3_str.split(",")[3] else 0

            tls_ver_raw = getattr(tls_layer, "version", 771)
            tls_ver_str = get_tls_version(tls_ver_raw)

            tls_data.append({
                "Packet No": index,
                "Source IP": packet[IP].src,
                "Destination IP": packet[IP].dst,
                "Source Port": tcp_layer.sport,
                "Destination Port": tcp_layer.dport,
                "TLS Version": tls_ver_str,
                "Record Type": record_type,
                "Length": len(packet),
                "Timestamp": float(packet.time),
                "SNI": sni,
                "Domain_Entropy": entropy,
                "JA3_String": ja3_str,
                "JA3_Hash": ja3_h,
                "JA3S_String": ja3s_str,
                "JA3S_Hash": ja3s_h,
                "Cipher_Suite_Count": ciphers_cnt,
                "Extension_Count": ext_cnt,
                "Elliptic_Curve_Count": curves_cnt
            })

    return tls_data


def save_to_csv(data, output_file="output/tls_features.csv"):
    """
    Save extracted data to CSV file.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    return df


def extract_tls_from_pcap(pcap_path, output_csv="output/tls_features.csv"):
    """
    Direct function interface for Streamlit or programmatic invocation.
    """
    packets = load_pcap(pcap_path)
    tls_data = extract_tls_features(packets)
    df = save_to_csv(tls_data, output_csv)
    return df


def display_tls_info(df):
    print("=" * 90)
    print("TLSProfiler - TLS Features & JA3 Fingerprints")
    print("=" * 90)
    print(f"Total TLS Packets: {len(df)}\n")

    if df.empty:
        print("No TLS packets found.")
    else:
        display_cols = ["Packet No", "Source IP", "Destination IP", "TLS Version", "Record Type", "SNI", "JA3_Hash"]
        cols = [c for c in display_cols if c in df.columns]
        print(df[cols].head(10).to_string(index=False))

    print("=" * 90)


def main():
    parser = argparse.ArgumentParser(description="TLSProfiler - TLS Feature Extractor")
    parser.add_argument(
        "pcap",
        nargs="?",
        default="captures/reddit.pcap",
        help="Path to the PCAP file"
    )

    args = parser.parse_args()

    try:
        df = extract_tls_from_pcap(args.pcap)
        display_tls_info(df)
        print("\nCSV saved to: output/tls_features.csv")
    except FileNotFoundError:
        print(f"\nError: '{args.pcap}' not found.")
    except Exception as error:
        print(f"\nUnexpected Error: {error}")


if __name__ == "__main__":
    main()