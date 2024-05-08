from scapy.all import *

conf.iface = "en0"
# Load the captured pcap file
packets = rdpcap('traffic.pcap')

# 1) Load proportion of different transport layer protocols
transport_protocols = {'TCP': 0, 'UDP': 0, 'ICMP':0, 'ARP':0 }
for packet in packets:
    if IP in packet:
        if TCP in packet:
            transport_protocols['TCP'] += 1
        elif UDP in packet:
            transport_protocols['UDP'] += 1
        elif ICMP in packet:
            transport_protocols['ICMP'] += 1
        elif NTP in packet:
            transport_protocols['ARP'] += 1

import matplotlib.pyplot as plt
plt.pie(transport_protocols.values(), labels=transport_protocols.keys(), autopct='%1.1f%%')
plt.title('Proportion of Different Transport Layer Protocols')
plt.show()

# 2) Identify fragmented IP packets
fragmented_packets = []

# Iterate through all packets
for packet in packets:
    # Check if IP header exists
    if IP in packet:
        # Check if packet is fragmented
        if packet[IP].flags & 0x1:  # Check if the 'more fragments' flag is set
            fragmented_packets.append(packet)
        elif packet[IP].frag != 0:  # Check if fragment offset is non-zero, indicating fragmented packet
            fragmented_packets.append(packet)

print("Number of fragmented IP packets:", len(fragmented_packets))


# 3) Cumulative distribution curve of IP packet length
tcp_lengths = [len(packet) for packet in packets if IP in packet and TCP in packet]
udp_lengths = [len(packet) for packet in packets if IP in packet and UDP in packet]

import numpy as np
plt.hist(tcp_lengths, bins=np.arange(0, max(tcp_lengths), 100), cumulative=True, density=True, histtype='step', label='TCP')
plt.hist(udp_lengths, bins=np.arange(0, max(udp_lengths), 100), cumulative=True, density=True, histtype='step', label='UDP')
plt.xlabel('IP Packet Length')
plt.ylabel('Cumulative Probability')
plt.title('Cumulative Distribution of IP Packet Length')
plt.legend()
plt.show()

# 4) Find broadcast packets
broadcast_packets = [packet for packet in packets if Ether in packet and packet[Ether].dst == 'ff:ff:ff:ff:ff:ff']

# Print number of broadcast packets
print("Number of broadcast packets:", len(broadcast_packets))
