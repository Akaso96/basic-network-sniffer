from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        payload = bytes(packet.payload)

        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))

        print(f"[{protocol_name}] {src_ip} -> {dst_ip}")
        print(f"Payload: {payload[:100]}\n")

def start_sniffer(interface=None):
    print("Starting packet capture... Press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=process_packet, iface=interface, store=0)

if __name__ == "__main__":
    start_sniffer()
