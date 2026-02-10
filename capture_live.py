from scapy.all import sniff
import pandas as pd
import time

packets_list = []

def process_packet(packet):
    try:
        src = packet[0][1].src if hasattr(packet[0][1], "src") else None
        dst = packet[0][1].dst if hasattr(packet[0][1], "dst") else None
        proto = packet.lastlayer().name
        length = len(packet)

        packet_data = {
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "packet_length": length,
            "timestamp": time.time()
        }

        packets_list.append(packet_data)

        print(packet_data)

    except Exception as e:
        print("Error packet:", e)


def start_capture():
    print("Starting Live Capture… (Ctrl + C to stop)")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_capture()
