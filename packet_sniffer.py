# import necessary functions and classes from scapy

from scapy.all import sniff, IP

# Define a callback function that processes each packet captured

def packet_callback(packet):
    # check if the packet has an IP layer

    if IP in packet:
        ip_layer = packet(IP) # Extract the IP layer from the packet

        # Print the source and destination IP addresses and the protocol number

        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst} | Protocol: {ip_layer.proto}")

        
         