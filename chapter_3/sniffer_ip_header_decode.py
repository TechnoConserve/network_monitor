"""
Made changes from original Blackhat Python book as per
SO recommendations: https://stackoverflow.com/a/29307402
"""
import socket

import os
import struct
from ctypes import *


# Host to listen on
host = "155.99.213.219"


# Our IP header
class IP(Structure):
    _fields_ = [
        ("ihl",             c_ubyte, 4),
        ("version",         c_ubyte, 4),
        ("tos",             c_ubyte),
        ("len",             c_ushort),
        ("id",              c_ushort),
        ("offset",          c_ushort),
        ("ttl",             c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum",             c_ushort),
        ("src",             c_uint32),
        ("dst",             c_uint32)
    ]

    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # Map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # Human readable IP Addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # Human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


# Create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))

# We want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

"""
If we're using Windows, we need to send an IOCTL
to setup promiscuous mode.
"""
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:

        # Read in a packet
        raw_buffer = sniffer.recvfrom(65565)[0]

        # Create an IP header from the first 20 bytes of the buffer
        ip_header = IP(raw_buffer[0:20])

        # Print out the protocol that was detected as well as the hosts
        print("Protocol: {} {} -> {}".format(ip_header.protocol, ip_header.src_address, ip_header.dst_address))

# Handle CTRL-C
except KeyboardInterrupt:

    # If we're using Windows, turn off promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

    os.system(exit(0))
