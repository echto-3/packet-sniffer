import ipaddress
import socket
import struct
import sys
import argparse
import csv
import os

# Argument parsing
parser = argparse.ArgumentParser(description='Network packet sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
opts = parser.parse_args()

# Packet parsing class
class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('!BBHHHBBH4s4s', self.packet[0:20])  # Network order

        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xf
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)

        self.parse_transport_layer()  # Call method inside class

    def parse_transport_layer(self):
        ip_header_length = self.ihl * 4
        if self.protocol == 'TCP':
            tcp_header = struct.unpack('!HHLLBBHHH', self.packet[ip_header_length:ip_header_length+20])
            self.src_port = tcp_header[0]
            self.dst_port = tcp_header[1]
            self.tcp_flags = tcp_header[5]  # flags are in the 6th byte of TCP header
        elif self.protocol == 'UDP':
            udp_header = struct.unpack('!HHHH', self.packet[ip_header_length:ip_header_length+8])
            self.src_port = udp_header[0]
            self.dst_port = udp_header[1]
        elif self.protocol == 'ICMP':
            icmp_header = struct.unpack('!BBH4s', self.packet[ip_header_length:ip_header_length+8])
            self.icmp_type = icmp_header[0]
            self.icmp_code = icmp_header[1]
            self.src_port = None
            self.dst_port = None
        else:
            self.src_port = None
            self.dst_port = None
        def parse_application_layer(self):
    ip_header_length = self.ihl * 4
    if self.protocol == 'TCP' and (self.src_port == 80 or self.dst_port == 80):
        tcp_header_length = (self.packet[ip_header_length + 12] >> 4) * 4
        payload_start = ip_header_length + tcp_header_length
        payload = self.packet[payload_start:]
        try:
            http_data = payload.decode('utf-8')
            self.http_info = http_data.split('\r\n')[0]  # first line of HTTP header
        except:
            self.http_info = None
    elif self.protocol == 'UDP' and (self.src_port == 53 or self.dst_port == 53):
        # DNS header is 12 bytes; parse it accordingly
        udp_header_length = 8
        dns_start = ip_header_length + udp_header_length
        dns_header = self.packet[dns_start:dns_start+12]
        if len(dns_header) == 12:
            transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('!HHHHHH', dns_header)
            self.dns_transaction_id = transaction_id
        else:
            self.dns_transaction_id = None
    else:
        self.http_info = None
        self.dns_transaction_id = None




filename = "packetlog.csv"
def init_packet_log():
    if not os.path.exists(filename):
        fields = ['Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'TTL']
        with open(filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(fields)

def append_packet_to_csv(protocol, src, src_port, dst, dst_port, ttl):
    with open(filename, 'a', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow([protocol, src, src_port, dst, dst_port, ttl])

# Sniffer function
def sniff():
    init_packet_log()  # Initialize CSV file with headers before sniffing

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((opts.ip, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if sys.platform == 'win32':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print(f"[*] Sniffing on {opts.ip}...\nPress Ctrl+C to stop.\n")

        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            pkt = Packet(raw_data)

            src_port = pkt.src_port if pkt.src_port is not None else ''
            dst_port = pkt.dst_port if pkt.dst_port is not None else ''

            # Append packet info to CSV
            append_packet_to_csv(pkt.protocol, str(pkt.src_addr), src_port, str(pkt.dst_addr), dst_port, pkt.ttl)

            print(f"{pkt.protocol} | {pkt.src_addr}:{src_port} -> {pkt.dst_addr}:{dst_port} | TTL={pkt.ttl}")

    except KeyboardInterrupt:
        print("\n[!] Stopping sniffer...")
        if sys.platform == 'win32':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sniffer.close()

# Run it
if __name__ == '__main__':
    init_packet_log()  # Clears file and writes header
    sniff()
