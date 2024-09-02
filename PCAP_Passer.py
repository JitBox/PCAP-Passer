from scapy.all import *
import socket

#Makes a network connection to Google DNS to grab current Interface/Private IP Address
def get_private_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    finally:
        s.close()
    return ip_address

#simply grabs the active Network Interface
def get_default_iface():
    return conf.iface

#Variable Assigning 
private_ip = get_private_ip()
iface = get_default_iface()
pcapng_file = "<Location on disk with PCAP/PCAPNG File>" #CHANGE ME: PCAP/PCAPNG file on disk
packets = rdpcap(pcapng_file)

for packet in packets:
    if IP in packet:
        packet[IP].src = private_ip
        del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
        elif UDP in packet:
            del packet[UDP].chksum

        # Fragment the packet if it is too large
        frags = fragment(packet, fragsize=1400)
        for frag in frags:
            sendp(frag, iface=iface)
    else:
        sendp(packet, iface=iface)
        