from scapy.all import *

# packets = rdpcap("trace-5.pcap")
#
# print(packets[0])
#
# print(len(packets))

from scapy.utils import RawPcapReader

# def process_pcap(file_name):
#     print('1. Opening {}...'.format(file_name))
#
#     count = 0
#     for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
#         count += 1
#
#     print('{} contains {} packets'.format(file_name, count))

#
# process_pcap("trace-5.pcap")

from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def process_pcap(file_name):
    print('2. Opening {}...'.format(file_name))

    count = 1
    interesting_packet_count = 0

    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started\n")
    file1.close()
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        print("\n" + str(count) + "=> ")

        #print(pkt_data)

        #print(bytes_hex(pkt_data))

        ##dekodovane na string
        p = bytes_hex(pkt_data).decode("utf-8")
        print(p)
        counter = 0
        file1 = open("hexramce.txt", "a")
        file1.write("ramec " + str(count) + "\n")
        api = ((len(p) + 1) // 2)
        medium = ((len(p) + 1) // 2) + 4
        file1.write("dlzka ramca poskytnuta pcap API - " + str(api) + " B\n")
        file1.write("dlzka ramca prenasaneho po mediu - " + str(medium) + " B\n")

        packet_type = p[24:28]
        print("Packet type is: " + packet_type)
        naslo_ethertype = False

        with open("ethertypes.txt") as search:
            for line in search:
                line = line.rstrip()  # remove '\n' at end of line
                print(line + " .... " + line[0:4])
                if packet_type == line[0:4]:
                    print("NASIEL SOM ZHODU V ETHERTYPE: " + line)
                    file1.write("Ethernet II\n")
                    naslo_ethertype = True

                    smac = p[12:24]
                    file1.write("Zdrojova MAC adresa je: ")
                    for ch in range(0, len(smac), 2):
                        file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")

                    dmac = p[0:12]
                    file1.write("\nCielova MAC adresa je: ")
                    for ch in range(0, len(dmac), 2):
                        file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")

                    file1.write("\n")

                    file1.write(line[5:len(line)] + "\n")

                    if naslo_ethertype == True and line[0:4] == "0800":
                        file1.write("zdrojova IP adresa: ")
                        for cislo in range(0, 8, 2):
                            zdrojip = p[52 + cislo:54 + cislo]
                            zdrojipdec = int(zdrojip, 16)
                            file1.write(str(zdrojipdec))
                            if cislo != 6:
                                file1.write(".")

                        file1.write("\ncielova IP adresa: ")
                        for cislo in range(0, 8, 2):
                            cielip = p[60 + cislo:62 + cislo]
                            cielipdec = int(cielip, 16)
                            file1.write(str(cielipdec))
                            if cislo != 6:
                                file1.write(".")
                        file1.write("\n")

                        print("Protokol zistujem: ")
                        with open("protocols.txt") as protocols:
                            for riadok in protocols:
                                riadok = riadok.rstrip()  # remove '\n' at end of line
                                protocol_type = p[46:48]
                                print(riadok + " .... " + protocol_type)

                                if protocol_type == riadok[0:2]:
                                    print("ZHODA v protokoloch: " + riadok)
                                    file1.write(riadok[3:len(riadok)] + "\n")

                    if naslo_ethertype == True and line[0:4] == "86dd":

                        file1.write("zdrojova IP adresa: ")
                        for cislo in range(0, 32, 4):
                            zdrojip = p[44 + cislo:48 + cislo]
                            # zdrojipdec = int(zdrojip, 16)
                            file1.write(zdrojip)
                            if cislo != 28:
                                file1.write(":")

                        file1.write("\ncielova IP adresa: ")
                        for cislo in range(0, 32, 4):
                            cielip = p[76 + cislo:80 + cislo]
                            # zdrojipdec = int(zdrojip, 16)
                            file1.write(cielip)
                            if cislo != 28:
                                file1.write(":")
                        file1.write("\n")

        if (naslo_ethertype == False):
            with open("saps.txt") as search:
                packet_type = p[28:32]
                for line in search:
                    line = line.rstrip()  # remove '\n' at end of line
                    print(line + " .... " + line[0:4])
                    if packet_type == line[0:4]:
                        print("NASIEL SOM ZHODU V SAPS: " + line)
                        file1.write(line[5:len(line)] + "\n")

                        smac = p[12:24]
                        file1.write("Zdrojova MAC adresa je: ")
                        for ch in range(0, len(smac), 2):
                            file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")

                        dmac = p[0:12]
                        file1.write("\nCielova MAC adresa je: ")
                        for ch in range(0, len(dmac), 2):
                            file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")

                        file1.write("\n")

        ## vypis celeho packetu
        for i in p:
            file1.write(i)
            # print(str(counter) + ". ")
            # print(i)
            if counter % 2 != 0 and counter != 0:
                if counter % 31 == 0:
                    file1.write("\n")
                    counter = 0
                    continue
                if counter % 15 == 0:
                    file1.write("  ")
                else:
                    file1.write(" ")

            counter += 1

        file1.write("\n\n")
        file1.close()
        # print(pkt_metadata)
        count += 1

    #     ether_pkt = Ether(pkt_data)
    #     if 'type' not in ether_pkt.fields:
    #         # LLC frames will have 'len' instead of 'type'.
    #         # We disregard those
    #         continue
    #
    #     if ether_pkt.type != 0x0800:
    #         # disregard non-IPv4 packets
    #         continue
    #
    #     ip_pkt = ether_pkt[IP]
    #     if ip_pkt.proto != 6:
    #         # Ignore non-TCP packet
    #         continue
    #
    #     interesting_packet_count += 1
    #
    # print('{} contains {} packets ({} interesting)'.
    #       format(file_name, count, interesting_packet_count))



## TU SA SPUSTA FUNKCIA

print("Vitaj vo Wiresharku 3000!\n")
print("Zadaj cele meno pcap suboru co chces analyzovat: ")
string = str(input())
process_pcap(string)

#
# def process_pcap(file_name):
#     print('3. Opening {}...'.format(file_name))
#
#     client = '192.168.1.137:57080'
#     server = '152.19.134.43:80'
#
#     (client_ip, client_port) = client.split(':')
#     (server_ip, server_port) = server.split(':')
#
#     count = 0
#     interesting_packet_count = 0
#
#     for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
#         count += 1
#
#         ether_pkt = Ether(pkt_data)
#         if 'type' not in ether_pkt.fields:
#             # LLC frames will have 'len' instead of 'type'.
#             # We disregard those
#             continue
#
#         if ether_pkt.type != 0x0800:
#             # disregard non-IPv4 packets
#             continue
#
#         ip_pkt = ether_pkt[IP]
#
#         if ip_pkt.proto != 6:
#             # Ignore non-TCP packet
#             continue
#
#         if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
#             # Uninteresting source IP address
#             continue
#
#         if (ip_pkt.dst != server_ip) and (ip_pkt.dst != client_ip):
#             # Uninteresting destination IP address
#             continue
#
#         tcp_pkt = ip_pkt[TCP]
#
#         if (tcp_pkt.sport != int(server_port)) and \
#                 (tcp_pkt.sport != int(client_port)):
#             # Uninteresting source TCP port
#             continue
#
#         if (tcp_pkt.dport != int(server_port)) and \
#                 (tcp_pkt.dport != int(client_port)):
#             # Uninteresting destination TCP port
#             continue
#
#         interesting_packet_count += 1
#
#     print('{} contains {} packets ({} interesting)'.
#           format(file_name, count, interesting_packet_count))
#
# # process_pcap("trace-5.pcap")
