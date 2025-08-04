import argparse
import json
import logging
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR

packet_log = []
packet_count = {"total": 0, "TCP": 0, "UDP": 0, "Other": 0}

# Logging setup
logging.basicConfig(filename="log.txt", level=logging.INFO, format="%(message)s")

def log_packet(packet_data):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info(f"[{timestamp}] {packet_data}")
    packet_log.append({ "timestamp": timestamp, **packet_data })

def parse_dns(packet):
    if DNS in packet and packet[DNS].qd:
        qname = packet[DNS].qd.qname.decode("utf-8", errors="ignore")
        return { "dns_query": qname }
    return {}

def analyze_packet(packet, protocol_filter):
    if IP in packet:
        ip_layer = packet[IP]
        proto = packet.proto
        protocol = "TCP" if proto == 6 else "UDP" if proto == 17 else str(proto)

        # Respect CLI protocol filter
        if protocol_filter and protocol != protocol_filter:
            return

        packet_count["total"] += 1
        if protocol in packet_count:
            packet_count[protocol] += 1
        else:
            packet_count["Other"] += 1

        packet_data = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": protocol
        }

        if protocol == "TCP":
            tcp_layer = packet[TCP]
            packet_data.update({
                "src_port": tcp_layer.sport,
                "dst_port": tcp_layer.dport
            })
        elif protocol == "UDP":
            udp_layer = packet[UDP]
            packet_data.update({
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport
            })

        # Decode DNS payload if present
        dns_info = parse_dns(packet)
        packet_data.update(dns_info)

        log_packet(packet_data)

def sniff_packets(filter_proto):
    sniff(prn=lambda pkt: analyze_packet(pkt, filter_proto), store=False)

def save_json():
    with open("log.json", "w") as f:
        json.dump(packet_log, f, indent=4)

def print_summary():
    print("\n📊 Packet Capture Summary:")
    for k, v in packet_count.items():
        print(f"  {k}: {v}")
    print("✅ Logs saved to log.txt and log.json")

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Scapy")
    parser.add_argument("--protocol", choices=["TCP", "UDP"], help="Filter by protocol")
    args = parser.parse_args()

    print(f"🛡️ Starting packet sniffer (protocol: {args.protocol or 'All'})... Press Ctrl+C to stop.\n")

    sniffer_thread = threading.Thread(target=sniff_packets, args=(args.protocol,))
    sniffer_thread.start()

    try:
        sniffer_thread.join()
    except KeyboardInterrupt:
        save_json()
        print_summary()

if __name__ == "__main__":
    main()