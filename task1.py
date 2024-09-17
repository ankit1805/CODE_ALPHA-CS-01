from scapy.all import sniff

# Function to handle each captured packet
def packet_handler(packet):
    # Print a summary of the packet
    print(packet.summary())
    
    # Check if it's an IP packet
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

        # If it's a TCP packet, print additional details
        if packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            print(f"    [+] TCP Segment: {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"    [+] Flags: {tcp_layer.flags}")
        
        # If it's a UDP packet, print additional details
        elif packet.haslayer("UDP"):
            udp_layer = packet["UDP"]
            print(f"    [+] UDP Segment: {udp_layer.sport} -> {udp_layer.dport}")

# Sniff packets on the network
def start_sniffer(interface="eth0"):
    print(f"[*] Starting network sniffer on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    # Start the sniffer on the default interface or specify your network interface
    start_sniffer("eth0")

