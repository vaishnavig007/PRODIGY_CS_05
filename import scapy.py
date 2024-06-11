import scapy.all as scapy

def sniff_packets(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto

        print(f"Source: {src_ip}  Destination: {dst_ip}  Protocol: {proto}")

        if packet.haslayer(scapy.Raw):
            data = packet[scapy.Raw].load
            print(f"Data: {data}")

def start_sniffing(interface):
    scapy.sniff(iface=interface, prn=sniff_packets, store=False)

if __name__ == "__main__":
    net_interface = input("Enter network interface to sniff (e.g., eth0): ")
    start_sniffing(net_interface)
