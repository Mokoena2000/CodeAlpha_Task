# import necessary functions and classes from scapy

from scapy.all import sniff, IP

# Define a callback function that processes each packet captured

def packet_callback(packet):
    # check if the packet has an IP layer

    if IP in packet:
        ip_layer = packet(IP) # Extract the IP layer from the packet

        # Print the source and destination IP addresses and the protocol number

        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst} | Protocol: {ip_layer.proto}")

       # If the packet has a raw layer which contains payload data print it 

        if packet.haslayer('Raw'):
            print(f"Payload: {bytes(packet['Raw'].load)}") # Display the payload as raw bytes

        # Best to print a seperstor for readability

        print("-" * 80)

# Best to let the usser know snifing has started

print("Sniffing started.... Press Ctrl+C to stop...enjoy.")

# Start sniffing packets
# call our function with necessary scapy dependancys

sniff(prn=packet_callback, store=0)
         