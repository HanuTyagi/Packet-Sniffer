# Packet Sniffer
A packet sniffer is a tool that can capture and analyze network traffic. This project is a packet sniffer that can capture and display information about network packets, including the source and destination IP addresses, the protocol, and the packet payload.

# Installation
To use the packet sniffer, you will need to have Python 3 and the Scapy library installed on your system. You can install Scapy using pip:

`pip install scapy`

# Usage
To start the packet sniffer, simply run the script with Python:

`python packet_sniffer.py`

The packet sniffer will begin capturing packets and displaying information about them in the terminal. You can press `CTRL+C` to stop the packet sniffer.

# Options
The packet sniffer has a few command line options that you can use to customize its behavior:

- Specify the network interface to capture packets on. Example Wi-Fi  , Ethernet
- Save http URL and captured login credentials in a Text File Path `C:\Sniffer\captured.txt`

# Additional Note
Please be aware that Packet sniffing can be illegal in certain jurisdictions, so please make sure you have the right to use this tool in your area before using it.

# References
[Scapy documentation](https://scapy.readthedocs.io/)

# Contributing
If you have any suggestions or improvements for the packet sniffer, please feel free to open an issue or submit a pull request.
