import dpkt
import arp
import tcpudp
import sys
import datetime

#--------Fungsi Menulis paket ke dalam file CSV---------

def output_csv(paket,outputcsv):
    file = open(outputcsv,'ab')
    for i in paket:
        file.write(paket+'\n')
        file.close()

#============ Menghilangkan Char '' dari list ==========

#def parcerdata

"""Fungsi Convert List ke String"""

def ListtoString(data):

    dataString = ''
    for i in data:
        dataString = dataString + str(i) +','

    return dataString


""" ============ Fungsi Utama ================
"""" Mengekstrak paket berupa paket IPv4,TCP,UDP,ICMP,IPv6,ARP, dan Other"""
""""no_paket,temstems,app,ip_src,sport,ip_dst,dport,seq,ack,win,flags,ttl,iplen,ipsum,ipid,ipoff,paketlen,icmpcode,icmptype,payload """


def print_pcap(pcap,outputcsv):
    packet_count = 0
    for timestamp, buf in pcap:
        packet_count += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)

            #"""" Mengecek apakah paket bertipe ipv4 """"
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:

                ip = eth.data

                # """"Mengekstrak paket ICMP """"

                if ip.p == dpkt.ip.IP_PROTO_ICMP:
                    paket_icmp = tcpudp.icmp(eth)

                    date = str(datetime.datetime.fromtimestamp(timestamp))
                    #date = convertanggal(date)
                    no_paket = str(packet_count)
                    listtostr = ListtoString(paket_icmp)
                    payload =no_paket+','+date +','+ listtostr
                    print payload
                    output_csv(payload,outputcsv)


                # """"Mengekstrak paket UDP """"

                if ip.p == dpkt.ip.IP_PROTO_UDP:

                    paket_udp = tcpudp.udp(eth)
                    #print 'Paket ke',packet_count,'UDP src',paket_udp[0],'sport',paket_udp[1],'dst',paket_udp[2],'dport',paket_udp[3],'iplen',paket_udp[4],'ttl',paket_udp[5],'udplen',paket_udp[6],str(datetime.datetime.utcfromtimestamp(timestamp))
                    date = str(datetime.datetime.fromtimestamp(timestamp))
                    #date = convertanggal(date)
                    listtostr = ListtoString(paket_udp)
                    no_paket = str(packet_count)
                    payload = no_paket+','+date +','+ listtostr
                    print payload
                    output_csv(payload,outputcsv)

                # """"Mengekstrak paket TCP """"

                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    paket_tcp = tcpudp.tcp(eth)

                    #print 'Paket ke',packet_count,'TCP src',paket_tcp[0],'sport',paket_tcp[1],'dst',paket_tcp[2],'dport',paket_tcp[3],'iplen',paket_tcp[4],'seq',paket_tcp[5],'ack',paket_tcp[6],'ttl',paket_tcp[7],'win',paket_tcp[8],paket_tcp[9],'tcplen',paket_tcp[10],'sum',paket_tcp[11],'id',paket_tcp[12],'off',paket_tcp[13],str(datetime.datetime.utcfromtimestamp(timestamp))
                    date = str(datetime.datetime.fromtimestamp(timestamp))
                    #date = convertanggal(date)
                    no_paket = str(packet_count)
                    listtostr = ListtoString(paket_tcp)
                    payload = no_paket+','+date + ',' + listtostr
                    print payload
                    output_csv(payload,outputcsv)

                # """"Mengekstrak paket tipe ipv4 bukan tcp/udp/icmp """"
                #else :
                #    paket_other = 'otherv4'
                #    date = str(datetime.datetime.utcfromtimestamp(timestamp))
                #    tanggal = date.split('.')
                #    bulan = tanggal[0]
                #    no_paket = str(packet_count)
                #    payload = no_paket+','+bulan + ',' + paket_other
                #    print payload
                #    output_csv(payload)


            # """"Mengekstrak paket IPv6 """"

            #elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            #    paket_v6 = "ipv6"
            #   date = str(datetime.datetime.utcfromtimestamp(timestamp))
            #    tanggal = date.split('.')
            #    bulan = tanggal[0]
            #    no_paket = str(packet_count)
            #    payload =no_paket+','+bulan +','+paket_v6
            #    print payload
            #    output_csv(payload)

            #""""Mengekstrak paket ARP """"

            #if eth.type == dpkt.ethernet.ETH_TYPE_ARP:

             #   paket_arp = arp.decode_arp(eth)
            #    date = str(datetime.datetime.fromtimestamp(timestamp))
                #date = convertanggal(date)
            #    no_paket = str(packet_count)
             #   listtostr = ListtoString(paket_arp)
             #   payload =no_paket+','+date + ',' + listtostr
             #   print payload
             #   output_csv(payload,outputcsv)




            #"""" Exstrak baris paket yang bukan tipe IP """"
            #else:
            #    paket_other = 'other'
            #    date = str(datetime.datetime.utcfromtimestamp(timestamp))
            #    tanggal = date.split('.')
            #    bulan = tanggal[0]
            #    no_paket = str(packet_count)
            #    payload = no_paket+','+bulan +','+paket_other
            #    print payload
            #    output_csv(payload)


        except:
            pass


def Utama():

    """Membuat file output.csv untuk menampung data paket dari file pcap/tcpdump"""
    #Dalam file csv terdapat filed dari
    # (no_paket,temstems, app, ip_src, sport, ip_dst, dport,seq,ack,win,flags, ttl,iplen,ipsum,ipid,ipoff,paketlen,icmpcode,icmptype,payload)

    #file = open('/home/robotumbel/Documents/TA Uwong/SQL BN/uji/pengujian1.csv','wb')
    path_pcap = sys.argv[1].split(".")
    path_pcap = path_pcap[0]+".csv"
    file = open(path_pcap,'wb')
    file.writelines('NO_PAKET,TEMPSTEMS,SERVICE,IP_SRC,IP_DST,SPORT,DPORT,SEQ,ACK,WIN,FLAGS,TTL,IP_LENGTH,IP_CEKSUM,IP_ID,IP_OFF,TCP/UDP/ICMP_LENGTH,PROTOCOL,ICMPCODE,ICMPTYPE,PAYLOAD')
    file.writelines('\n')
    file.close()

    #""" Membaca file pcap/tcpdump """
    with open(sys.argv[1],'rb') as f:

    #with open('/home/robotumbel/Documents/TA Uwong/SQL BN/uji/pengujian1.pcap', 'rb+') as f:
        pcap = dpkt.pcap.Reader(f)
        print_pcap(pcap,path_pcap)
        #print_pcap(pcap,'/home/robotumbel/Documents/TA Uwong/SQL BN/uji/pengujian1.csv')

Utama()

