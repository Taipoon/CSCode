from scapy.all import sniff
from scapy.layers.inet import TCP, IP


def packet_callback(packet_object):
    if packet_object[TCP].payload:
        mail_packet = str(packet_object[TCP].payload)
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print(f"[*] Server: {packet_object[IP].dst} ")
            print(f"[*] {packet_object[TCP].payload} ")


if __name__ == '__main__':

    sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",
          prn=packet_callback, count=1, store=0)

