import socket
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

#unpack ethrent frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#Return properly formated MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#unpacks IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

#Returns properly formatted IPv4 address
def ipv4(addr):
    return ','.join(map(str, addr))

# Unpacks ICMP Packet 
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

#Unpacks TCP Segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowldgement, offset_reversed_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reversed_flag >> 12) * 4
    flag_urg = (offset_reversed_flag & 32) >> 5
    flag_ack = (offset_reversed_flag & 16) >> 4
    flag_psh = (offset_reversed_flag & 8) >> 3
    flag_rst = (offset_reversed_flag & 4) >> 2
    flag_syn = (offset_reversed_flag & 2) >> 1
    flag_fin = (offset_reversed_flag & 1)
    return src_port, dest_port, sequence, acknowldgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size[8:]

main()