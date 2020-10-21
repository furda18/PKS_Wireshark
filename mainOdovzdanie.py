from scapy.all import *
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP


def process_pcap(file_name):
    print('2. Opening {}...'.format(file_name))

    count = 1

    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started in file: " + file_name + "\n")
    file1.close()
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        print("\n" + str(count) + "=> ")

        # print(pkt_data)
        # print(bytes_hex(pkt_data))

        ##dekodovane na string
        p = bytes_hex(pkt_data).decode("utf-8")
        print(p)
        counter = 0
        file1 = open("hexramce.txt", "a")
        file1.write("ramec " + str(count) + "\n")
        api = ((len(p) + 1) // 2)
        medium = ((len(p) + 1) // 2) + 4
        if (api < 60):
            medium = 64
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
                    file1.write("Zdrojova MAC adresa: ")
                    for ch in range(0, len(smac), 2):
                        file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")

                    dmac = p[0:12]
                    file1.write("\nCielova MAC adresa: ")
                    for ch in range(0, len(dmac), 2):
                        file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")

                    file1.write("\n")

                    file1.write(line[5:len(line)] + "\n")

                    # IPv4
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

                                    # TPC
                                    if riadok[0:2] == "06":
                                        print("Tak teda bolo to TCP: ")
                                        with open("tcpports.txt") as tcpports:
                                            for portrow in tcpports:
                                                portrow = portrow.rstrip()  # remove '\n' at end of line
                                                srcport = p[68:72]
                                                dstport = p[72:76]

                                                if int(srcport, 16) >= int(dstport, 16):
                                                    smallerport = dstport
                                                else:
                                                    smallerport = srcport

                                                if smallerport == portrow[0:4]:
                                                    print(portrow + " ,,,, " + smallerport)
                                                    file1.write(portrow[5:len(portrow)] + "\n")
                                                    # print("asa")


                    # IPv6
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
        count += 1

#################################################################################################################################################
#
#################################################################################################################################################

def filter_pcap(file_name, filter_name):
    print('3. Opening {}...'.format(file_name))

    count = 1
    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started in file: " + file_name + "\n")
    file1.close()

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        p = bytes_hex(pkt_data).decode("utf-8")

        vypisRamec = False
        #ideme hladat vsetky TCP
        if(filter_name == "HTTP" or filter_name == "HTTPS" or filter_name == "TELNET" or filter_name == "SSH" or filter_name == "FTP-DATA" or filter_name == "FTP-CONTROL"):
            
            #priradim cislo protokolu do filtername
            with open("tcpports.txt") as filter_port:
                for riadok in filter_port:
                    riadok = riadok.rstrip()  # remove '\n' at end of line
                    #print(riadok)

                    if filter_name == riadok[5:len(riadok)]:
                        print("ZHODA v Portoch co hladam: " + riadok)
                        filter_hex = riadok[0:4]
                        print("Cize " + filter_name + " je hexadecimalne: " + filter_hex)
                        #file1.write(riadok[3:len(riadok)] + "\n")
            
            print("Ideme filtrovat vsetky TCP konverzacie")
            packet_type = p[24:28]
            print("Packet type is: " + packet_type)

            if packet_type == "0800":
                print("Je to ipv4 a Ethernet II")
                protocol_type = p[46:48]
                # to je TCP
                if protocol_type == "06":
                    print("JE to TCP: ")
                    
                    print("Zistim ci aj hladany protokol: ")
                    srcport = p[68:72]
                    dstport = p[72:76]
                    if int(srcport, 16) >= int(dstport, 16):
                        smallerport = dstport
                    else:
                        smallerport = srcport
                    
                    
                    if smallerport == filter_hex:
                        vypisRamec = True
                        print(smallerport + " ,,,, " + filter_hex)
                        # file1.write(portrow[5:len(portrow)] + "\n")
                        print("FINITO, idem zapisovat\n")


        if vypisRamec == True:
             file1 = open("hexramce.txt", "a")
             file1.write("ramec " + str(count) + "\n")

             api = ((len(p) + 1) // 2)
             medium = ((len(p) + 1) // 2) + 4
             if (api < 60):
                 medium = 64
             file1.write("dlzka ramca poskytnuta pcap API - " + str(api) + " B\n")
             file1.write("dlzka ramca prenasaneho po mediu - " + str(medium) + " B\n")

             file1.write("Ethernet II\n")
             smac = p[12:24]
             file1.write("Zdrojova MAC adresa: ")
             for ch in range(0, len(smac), 2):
                 file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")
                 print()
             dmac = p[0:12]
             file1.write("\nCielova MAC adresa: ")
             for ch in range(0, len(dmac), 2):
                 file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")
                 print()
             file1.write("\n")

             file1.write("IPv4\n")

             file1.write("zdrojova IP adresa: ")
             for cislo in range(0, 8, 2):
                 zdrojip = p[52 + cislo:54 + cislo]
                 zdrojipdec = int(zdrojip, 16)
                 file1.write(str(zdrojipdec))
                 if cislo != 6:
                     file1.write(".")
                     print()
             file1.write("\ncielova IP adresa: ")
             for cislo in range(0, 8, 2):
                 cielip = p[60 + cislo:62 + cislo]
                 cielipdec = int(cielip, 16)
                 file1.write(str(cielipdec))
                 if cislo != 6:
                     file1.write(".")
             file1.write("\n")

             file1.write(filter_name + "\n")

             file1.write("Zdrojovy port: " + srcport+ "\n")
             file1.write("Cielovy port: " + dstport + "\n")

             counter = 0
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

        count += 1





             

                        # 
                        # # file1.write("Ethernet II\n")
                        # smac = p[12:24]
                        # # file1.write("Zdrojova MAC adresa: ")
                        # for ch in range(0, len(smac), 2):
                        #     # file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")
                        #     print()
                        # dmac = p[0:12]
                        # # file1.write("\nCielova MAC adresa: ")
                        # for ch in range(0, len(dmac), 2):
                        #     # file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")
                        #     print()
                        # # file1.write("\n")
                        # # file1.write(line[5:len(line)] + "\n")
                        # # IPv4
                        # 
                        #     # file1.write("zdrojova IP adresa: ")
                        #     for cislo in range(0, 8, 2):
                        #         zdrojip = p[52 + cislo:54 + cislo]
                        #         zdrojipdec = int(zdrojip, 16)
                        #         # file1.write(str(zdrojipdec))
                        #         if cislo != 6:
                        #             # file1.write(".")
                        #             print()
                        #     # file1.write("\ncielova IP adresa: ")
                        #     for cislo in range(0, 8, 2):
                        #         cielip = p[60 + cislo:62 + cislo]
                        #         cielipdec = int(cielip, 16)
                        #         file1.write(str(cielipdec))
                        #         if cislo != 6:
                        #             file1.write(".")
                        #     file1.write("\n")


                                   
                                        
        # 
        # 
        # 
        # 
        # print("\n" + str(count) + "=> ")
        # 
        # # print(pkt_data)
        # # print(bytes_hex(pkt_data))
        # 
        # ##dekodovane na string
        # p = bytes_hex(pkt_data).decode("utf-8")
        # print(p)
        # counter = 0
        # file1 = open("hexramce.txt", "a")
        # #file1.write("ramec " + str(count) + "\n")
        # api = ((len(p) + 1) // 2)
        # medium = ((len(p) + 1) // 2) + 4
        # if (api < 60):
        #     medium = 64
        # #file1.write("dlzka ramca poskytnuta pcap API - " + str(api) + " B\n")
        # #file1.write("dlzka ramca prenasaneho po mediu - " + str(medium) + " B\n")
        # 
        # packet_type = p[24:28]
        # print("Packet type is: " + packet_type)
        # naslo_ethertype = False
        # 
        # with open("ethertypes.txt") as search:
        #     for line in search:
        #         line = line.rstrip()  # remove '\n' at end of line
        #         print(line + " .... " + line[0:4])
        #         if packet_type == line[0:4]:
        #             print("NASIEL SOM ZHODU V ETHERTYPE: " + line)
        #             #file1.write("Ethernet II\n")
        #             naslo_ethertype = True
        # 
        #             smac = p[12:24]
        #             #file1.write("Zdrojova MAC adresa: ")
        #             for ch in range(0, len(smac), 2):
        #                 #file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")
        #                 print()
        # 
        #             dmac = p[0:12]
        #             #file1.write("\nCielova MAC adresa: ")
        #             for ch in range(0, len(dmac), 2):
        #                 #file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")
        #                 print()
        # 
        #             #file1.write("\n")
        # 
        #             #file1.write(line[5:len(line)] + "\n")
        # 
        #             # IPv4
        #             if naslo_ethertype == True and line[0:4] == "0800":
        #                 #file1.write("zdrojova IP adresa: ")
        #                 for cislo in range(0, 8, 2):
        #                     zdrojip = p[52 + cislo:54 + cislo]
        #                     zdrojipdec = int(zdrojip, 16)
        #                     #file1.write(str(zdrojipdec))
        #                     if cislo != 6:
        #                         #file1.write(".")
        #                         print()
        # 
        #                 #file1.write("\ncielova IP adresa: ")
        #                 for cislo in range(0, 8, 2):
        #                     cielip = p[60 + cislo:62 + cislo]
        #                     cielipdec = int(cielip, 16)
        #                     file1.write(str(cielipdec))
        #                     if cislo != 6:
        #                         file1.write(".")
        #                 file1.write("\n")
        # 
        #                 print("Protokol zistujem: ")
        #                 with open("protocols.txt") as protocols:
        #                     for riadok in protocols:
        #                         riadok = riadok.rstrip()  # remove '\n' at end of line
        #                         protocol_type = p[46:48]
        #                         print(riadok + " .... " + protocol_type)
        # 
        #                         if protocol_type == riadok[0:2]:
        #                             print("ZHODA v protokoloch: " + riadok)
        #                             file1.write(riadok[3:len(riadok)] + "\n")
        # 
        #                             # TPC
        #                             if riadok[0:2] == "06":
        #                                 print("Tak teda bolo to TCP: ")
        #                                 with open("tcpports.txt") as tcpports:
        #                                     for portrow in tcpports:
        #                                         portrow = portrow.rstrip()  # remove '\n' at end of line
        #                                         srcport = p[68:72]
        #                                         dstport = p[72:76]
        # 
        #                                         if int(srcport, 16) >= int(dstport, 16):
        #                                             smallerport = dstport
        #                                         else:
        #                                             smallerport = srcport
        # 
        #                                         if smallerport == portrow[0:4]:
        #                                             print(portrow + " ,,,, " + smallerport)
        #                                             file1.write(portrow[5:len(portrow)] + "\n")
        #                                             # print("asa")
        # 
        #             # IPv6
        #             if naslo_ethertype == True and line[0:4] == "86dd":
        # 
        #                 file1.write("zdrojova IP adresa: ")
        #                 for cislo in range(0, 32, 4):
        #                     zdrojip = p[44 + cislo:48 + cislo]
        #                     # zdrojipdec = int(zdrojip, 16)
        #                     file1.write(zdrojip)
        #                     if cislo != 28:
        #                         file1.write(":")
        # 
        #                 file1.write("\ncielova IP adresa: ")
        #                 for cislo in range(0, 32, 4):
        #                     cielip = p[76 + cislo:80 + cislo]
        #                     # zdrojipdec = int(zdrojip, 16)
        #                     file1.write(cielip)
        #                     if cislo != 28:
        #                         file1.write(":")
        #                 file1.write("\n")
        # 
        # if (naslo_ethertype == False):
        #     with open("saps.txt") as search:
        #         packet_type = p[28:32]
        #         for line in search:
        #             line = line.rstrip()  # remove '\n' at end of line
        #             print(line + " .... " + line[0:4])
        #             if packet_type == line[0:4]:
        #                 print("NASIEL SOM ZHODU V SAPS: " + line)
        #                 file1.write(line[5:len(line)] + "\n")
        # 
        #                 smac = p[12:24]
        #                 file1.write("Zdrojova MAC adresa je: ")
        #                 for ch in range(0, len(smac), 2):
        #                     file1.write(smac[ch].upper() + smac[ch + 1].upper() + " ")
        # 
        #                 dmac = p[0:12]
        #                 file1.write("\nCielova MAC adresa je: ")
        #                 for ch in range(0, len(dmac), 2):
        #                     file1.write(dmac[ch].upper() + dmac[ch + 1].upper() + " ")
        # 
        #                 file1.write("\n")

        ## vypis celeho packetu


#########################################################################################################################################3
## TU SA SPUSTA FUNKCIA

print("Vitaj vo Wiresharku 3000!\n")
file_name = "trace-20.pcap"
print("Zadaj cislo pre akciu: \n'1' - pre vypis vsetkych ramcov\n'2' - pre specificke komunikacie")
akcia = str(input())
# print("Zadaj cele meno pcap suboru co chces analyzovat: ")
# string = str(input())
# process_pcap(string)
if akcia=='1':
    process_pcap(file_name)

if akcia=='2':
    print("Zadaj ktoru komunikaciu chces vyfiltrovat: \n'1' - HTTP\n")
    komunikacia = str(input())

    if(komunikacia == '1'):
        filter_pcap(file_name, "HTTP")


