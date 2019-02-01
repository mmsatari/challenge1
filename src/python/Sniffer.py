import IN
import socket
import sys
from struct import *


class Sniffer:

    def __init__(self, ifname):
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, (ifname))

        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

    def eth_addr(self, eth):
        return ':'.join("{:02X}".format(c) for c in eth[0:6])

    def start(self):
        while True:
            packet = self.sock.recvfrom(65565)

            # packet string from tuple
            packet = packet[0]

            # parse ethernet header
            eth_length = 14

            eth_header = packet[:eth_length]
            eth = unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            print('Destination MAC : ' + self.eth_addr(packet[0:6]) +
                  ' Source MAC : ' + self.eth_addr(packet[6:12]) +
                  ' Protocol : ' + str(eth_protocol))

            # Parse IP packets, IP Protocol number = 8
            if eth_protocol == 8:
                # Parse IP header
                # take first 20 characters for the ip header
                ip_header = packet[eth_length:20 + eth_length]

                # now unpack them
                iph = unpack('!BBHHHBBH4s4s', ip_header)

                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF

                iph_length = ihl * 4

                ttl = iph[5]
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])

                print('Source Address : {}  Destination Address : {} Version : {} IP Header Length : {} '
                      .format(s_addr, d_addr, version, ihl))

                # UDP packets
                if protocol == 17:
                    u = iph_length + eth_length
                    udph_length = 8
                    udp_header = packet[u:u + 8]

                    # now unpack them
                    udph = unpack('!HHHH', udp_header)

                    source_port = udph[0]
                    dest_port = udph[1]

                    print(' Source Port : {} Dest Port : {} '
                          .format(source_port, dest_port))


                # TCP protocol
                if protocol == 6:
                    t = iph_length + eth_length
                    tcp_header = packet[t:t + 20]

                    # now unpack them :)
                    tcph = unpack('!HHLLBBHHH', tcp_header)

                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    doff_reserved = tcph[4]
                    tcph_length = doff_reserved >> 4

                    print('Source Port : {} Dest Port : {}  Sequence Number : {} '
                          'Acknowledgement : {} TCP header length : {} '
                          .format(source_port,dest_port,sequence,acknowledgement,tcph_length))
                else:
                    print('Protocol other than TCP/UDP')

                print()


if __name__ == '__main__':
    ifname = input("Please enter interface name: ")
    try:
        sniffer = Sniffer(bytearray(ifname, "utf-8"))
        sniffer.start()
    except KeyboardInterrupt:
        print("Ctrl C - Stopping server")
        sys.exit(1)
