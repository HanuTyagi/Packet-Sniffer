from scapy.all import *

def packet_callback(packet):
    print(packet.show())

# sniff packets on the eth0 interface
sniff(iface="wlan0", prn=packet_callback, store=0)
