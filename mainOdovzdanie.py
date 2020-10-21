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

    file1 = open("statistics.txt", "w")
    file1.write("Statistics:\n")
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

                        #Tu len idem pocitat zdrojove a cielove adresy
                        c = 0
                        r = 0
                        with open('statistics.txt', 'r') as file:
                            # read a list of lines into data
                            data = file.readlines()
                            if(data == str(zdrojipdec)):
                                r = c
                                print("Nasiel som zhodnu Zrojovu Adresu")
                            c+=1

                        if i != 0:
                            data[r] = str(zdrojipdec)
                        # and write everything back
                        with open('stats.txt', 'w') as file:
                            file.writelines(data)
                        file1 = open("statistics.txt", "a")
                        file1.write("Statistics:\n")
                        file1.close()


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

def filter_pcap_tcp(file_name, filter_name):
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

             file1.write("TCP\n")
             file1.write(filter_name + "\n")

             file1.write("Zdrojovy port: " + str(int(srcport,16))+ "\n")
             file1.write("Cielovy port: " + str(int(dstport,16)) + "\n")

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



###########################################################################################################################
#UDP
###########################################################################################################################
def filter_pcap_udp(file_name, filter_name):
    print('3. Opening {}...'.format(file_name))

    count = 1
    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started in file: " + file_name + "\n")
    file1.close()

    otherport = 0

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        p = bytes_hex(pkt_data).decode("utf-8")
        print("\n\nramec " + str(count) + "\n")

        vypisRamec = False
        # ideme hladat vsetky UDP
        if (filter_name == "TFTP"):

            # priradim cislo protokolu do filtername
            with open("udpports.txt") as filter_port:
                for riadok in filter_port:
                    riadok = riadok.rstrip()  # remove '\n' at end of line
                    # print(riadok)

                    if filter_name == riadok[5:len(riadok)]:
                        print("ZHODA v Portoch co hladam: " + riadok)
                        filter_hex = riadok[0:4]
                        print("Cize " + filter_name + " je hexadecimalne: " + filter_hex)
                        # file1.write(riadok[3:len(riadok)] + "\n")

            print("Ideme filtrovat vsetky UDP konverzacie")
            packet_type = p[24:28]
            print("Packet type is: " + packet_type)

            if packet_type == "0800":
                print("Je to ipv4 a Ethernet II")
                protocol_type = p[46:48]
                # to je TCP
                if protocol_type == "11":
                    print("JE to UDP: ")



                    print("Zistim ci aj hladany protokol: ")
                    srcport = p[68:72]
                    dstport = p[72:76]
                    if int(srcport, 16) >= int(dstport, 16):
                        smallerport = dstport
                    else:
                        smallerport = srcport


                    if int(srcport, 16) == 69:
                        otherport = dstport
                    if int(dstport, 16) == 69:
                        otherport = srcport

                    print("Otherport: " + str(otherport))


                    if smallerport == filter_hex:
                        if(count == 1):
                            vypisRamec = True
                            print(smallerport + " ,,,, " + filter_hex)
                            # file1.write(portrow[5:len(portrow)] + "\n")
                            print("FINITO, idem zapisovat\n")

                    if(count>1):
                        if(otherport == srcport or otherport == dstport or smallerport == filter_hex):

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

            file1.write("UDP\n")
            file1.write(filter_name + "\n")

            file1.write("Zdrojovy port: " + str(int(srcport,16)) + "\n")
            file1.write("Cielovy port: " + str(int(dstport,16)) + "\n")

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

###########################################################################################################################
#ICMP
###########################################################################################################################
def filter_pcap_icmp(file_name, filter_name):
    print('3. Opening {}...'.format(file_name))

    count = 1
    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started in file: " + file_name + "\n")
    file1.close()

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        p = bytes_hex(pkt_data).decode("utf-8")
        print("\n\nramec " + str(count) + "\n")

        vypisRamec = False
        # ideme hladat vsetky UDP
        if (filter_name == "ICMP"):

            print("Ideme filtrovat vsetky ICMP konverzacie")
            packet_type = p[24:28]
            print("Packet type is: " + packet_type)

            if packet_type == "0800":
                print("Je to ipv4 a Ethernet II")
                protocol_type = p[46:48]
                # to je TCP
                if protocol_type == "01":
                    print("JE to ICMP: ")

                    print("Zistim ci aj hladany protokol: ")
                    type = p[68:70]
                    code = p[70:72]

                    icmpprotocol = type+code
                    print("Type: " + type + "\nCode: " + code + "\nIcmpprotocol: " + icmpprotocol)

                    with open("icmptypes.txt") as filter_type:
                        for riadok in filter_type:

                            if icmpprotocol == riadok[0:4]:
                                vypisRamec = True
                                print("! " + riadok[5:len(riadok)])
                                icmptypecode = riadok[5:len(riadok)]

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
            file1.write(icmptypecode)


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


###########################################################################################################################
#ARP
###########################################################################################################################
def filter_pcap_arp(file_name, filter_name):
    print('4. Opening {}...'.format(file_name))

    count = 1
    ##zapisem si vsetky hexa veci do suboru
    file1 = open("hexramce.txt", "w")
    file1.write("Lets get it started in file: " + file_name + "\n")
    file1.close()

    file2 = open("arpkomunikacie.txt", "w")
    file2.write("ARP IP adresses\n")
    file2.close()

    rIPodosielatel = ""  # ten co prvy poslal
    rIPprijimatel = ""  # ten co prvy dostal
    rIP = rIPprijimatel + rIPodosielatel

    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):

        p = bytes_hex(pkt_data).decode("utf-8")
        print("\n\nramec " + str(count) + "\n")

        vypisRamec = False
        # ideme hladat vsetky UDP
        if (filter_name == "ARP"):

            print("Ideme filtrovat vsetky ARP konverzacie")
            packet_type = p[24:28]
            print("Packet type is: " + packet_type)

            if packet_type == "0806":
                print("Je to ARP a Ethernet II")

                operation = p[40:44]

                print("Operacia pri ARP: " + operation)
                file1 = open("hexramce.txt", "a")
                #file1.write("ramec " + str(count) + "\n")
                if operation == "0001":

                    ## KEBY TAM NECHCEL VZDY UVADZAT KOMUNIKACIU TAK TO LEN POSUNIEM
                    #file1.write("Komunikacia c." + str(cislokom) + "\n")

                    rIPodosielatel = ""  # ten co prvy poslal
                    rIPprijimatel = ""  # ten co prvy dostal

                    # file1.write("ARP-Request, ")
                    # file1.write("IP adresa: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[76 + cislo:78 + cislo]
                        cielipdec = int(cielip, 16)
                        #file1.write(str(cielipdec))
                        rIPprijimatel += str(cielipdec)
                    #     if cislo != 6:
                    #         file1.write(".")
                    # file1.write(", ")
                    # file1.write("MAC adresa: ???")

                    # file1.write("\nZdrojova IP: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[56 + cislo:58 + cislo]
                        cielipdec = int(cielip, 16)
                        # file1.write(str(cielipdec))
                        rIPodosielatel += str(cielipdec)
                    #     if cislo != 6:
                    #         file1.write(".")
                    # file1.write(", ")

                    # file1.write("Cielova IP: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[76 + cislo:78 + cislo]
                        cielipdec = int(cielip, 16)
                        # file1.write(str(cielipdec))
                        # if cislo != 6:
                        #     file1.write(".")
                    # file1.write("\n")

                    rIP = rIPodosielatel + rIPprijimatel


                    file2 = open("arpkomunikacie.txt", "a")
                    with open("arpkomunikacie.txt") as arpkomunikacie:
                        cislokom = 0
                        zhoda = False
                        for riadokarp in arpkomunikacie:
                            riadokarp = riadokarp.rstrip()
                            cislokom += 1
                            if (riadokarp == rIP):
                                zhoda = True
                                continue

                        if zhoda == False:
                            file2.write(rIP + "\n")
                            print("HNED som aj zapisal: " + rIP)


                    file2.close()

                    file1.write("Komunikacia c." + str(cislokom) + "\n")

                    file1.write("ARP-Request, ")
                    file1.write("IP adresa: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[76 + cislo:78 + cislo]
                        cielipdec = int(cielip, 16)
                        file1.write(str(cielipdec))
                        if cislo != 6:
                            file1.write(".")
                    file1.write(", ")
                    file1.write("MAC adresa: ???")

                    file1.write("\nZdrojova IP: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[56 + cislo:58 + cislo]
                        cielipdec = int(cielip, 16)
                        file1.write(str(cielipdec))
                        if cislo != 6:
                            file1.write(".")
                    file1.write(", ")

                    file1.write("Cielova IP: ")
                    for cislo in range(0, 8, 2):
                        cielip = p[76 + cislo:78 + cislo]
                        cielipdec = int(cielip, 16)
                        file1.write(str(cielipdec))
                        if cislo != 6:
                            file1.write(".")
                    file1.write("\n")


                if operation == "0002":

                    IPodosielatel = ""
                    IPprijimatel = ""
                    IP = IPodosielatel + IPprijimatel

                    for cislo in range(0, 8, 2):
                        cielip = p[76 + cislo:78 + cislo]
                        cielipdec = int(cielip, 16)
                        IPodosielatel += str(cielipdec)

                    for cislo in range(0, 8, 2):
                        cielip = p[56 + cislo:58 + cislo]
                        cielipdec = int(cielip, 16)
                        IPprijimatel += str(cielipdec)

                    IP = IPodosielatel + IPprijimatel
                    print("IP odosielatel a prijimatel: " + IP)

                    with open("arpkomunikacie.txt") as arpkomunikacie:
                        cislokom = 0
                        zhoda = False
                        for riadokarp in arpkomunikacie:
                            riadokarp = riadokarp.rstrip()
                            cislokom += 1
                            print(riadokarp + " ?=? " + IP)
                            if (riadokarp == IP):
                                zhoda = True
                                continue

                        if zhoda == True:
                            file1.write("Komunikacia c." + str(cislokom-1) + "\n")

                            file1.write("ARP-Reply, ")
                            file1.write("IP adresa: ")
                            for cislo in range(0, 8, 2):
                                cielip = p[76 + cislo:78 + cislo]
                                cielipdec = int(cielip, 16)
                                file1.write(str(cielipdec))
                                IPodosielatel += str(cielipdec)
                                if cislo != 6:
                                    file1.write(".")
                            file1.write(", ")

                            file1.write("MAC adresa: ")
                            smacc = p[12:24]
                            for ch in range(0, len(smacc), 2):
                                file1.write(smacc[ch].upper() + smacc[ch + 1].upper() + " ")
                               # print()


                            file1.write("\nZdrojova IP: ")
                            for cislo in range(0, 8, 2):
                                cielip = p[56 + cislo:58 + cislo]
                                cielipdec = int(cielip, 16)
                                file1.write(str(cielipdec))
                                IPprijimatel += str(cielipdec)

                                if cislo != 6:
                                    file1.write(".")
                            file1.write(", ")

                            file1.write("Cielova IP: ")
                            for cislo in range(0, 8, 2):
                                cielip = p[76 + cislo:78 + cislo]
                                cielipdec = int(cielip, 16)
                                file1.write(str(cielipdec))
                                if cislo != 6:
                                    file1.write(".")
                            file1.write("\n")



                file1.write("ramec " + str(count) + "\n")
                api = ((len(p) + 1) // 2)
                medium = ((len(p) + 1) // 2) + 4
                if (api < 60):
                    medium = 64
                file1.write("dlzka ramca poskytnuta pcap API - " + str(api) + " B\n")
                file1.write("dlzka ramca prenasaneho po mediu - " + str(medium) + " B\n")

                file1.write("Ethernet II\n")
                file1.write("ARP\n")

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



#########################################################################################################################################3
## TU SA SPUSTA FUNKCIA

print("Vitaj vo Wiresharku 3000!\n")
file_name = "trace-26.pcap"
print("Zadaj cislo pre akciu: \n'1' - pre vypis vsetkych ramcov\n'2' - pre specificke komunikacie")
akcia = str(input())
# print("Zadaj cele meno pcap suboru co chces analyzovat: ")
# string = str(input())
# process_pcap(string)
if akcia=='1':
    process_pcap(file_name)

if akcia=='2':
    print("Zadaj ktoru komunikaciu chces vyfiltrovat: \n'1' - HTTP\n'2' - HTTPS\n'3' - TELNET\n'4' - SSH\n'5' - FTP-CONTROL\n'"
          "6' - FTP-DATA\n'7' - TFTP\n'8' - ICMP\n'9' - ARP")
    komunikacia = str(input())

    if(komunikacia == '1'):
        filter_pcap_tcp(file_name, "HTTP")

    if (komunikacia == '2'):
        filter_pcap_tcp(file_name, "HTTPS")

    if (komunikacia == '3'):
        filter_pcap_tcp(file_name, "TELNET")

    if (komunikacia == '4'):
        filter_pcap_tcp(file_name, "SSH")

    if (komunikacia == '5'):
        filter_pcap_tcp(file_name, "FTP-CONTROL")

    if (komunikacia == '6'):
        filter_pcap_tcp(file_name, "FTP-DATA")

    if (komunikacia == '7'):
        filter_pcap_udp(file_name, "TFTP")

    if (komunikacia == '8'):
        filter_pcap_icmp(file_name, "ICMP")

    if (komunikacia == '9'):
        filter_pcap_arp(file_name, "ARP")



