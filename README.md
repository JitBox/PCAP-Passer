# PCAP-Passer

## What is it? 
PCAP-Passer is a simple python program that will replay a provided PCAP file, emulating the network traffic included in the PCAP file. PCAP-Passer will identify the source device's primary Network Interface and public IP, and strip the PCAP file of the original source IP and replace with the originating host's Private IP. This allows any PCAP sample to be emulated as if it was network traffic originating from the source testing device. 

