import dpkt
import socket

with open('/home/robotumbel/pcap_ekstraktor/icmp.pcap', 'rb+') as f:
    pcap = dpkt.pcap.Reader(f)
    packet_count = 0
    for timestamp, buf in pcap:
        packet_count += 1
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            print repr(eth)
            #print repr(eth)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                ip = eth.data
                #print ip
                #print ip.sum
                #print repr(eth)
                #if isinstance(ip.data,dpkt.icmp.ICMP):
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    dat =icmp.data
                    py = dat.data
                    #icmp = ip.data
                    #tcp = icmp.data
                    #ipicmp = tcp.data
                    #dataicmp = ipicmp.data
                    print icmp.type, icmp.code, icmp.sum, repr(icmp.data),py
                    #print repr(icmp)
                    #print repr(ip)
                    print socket.inet_ntoa(ip.src)
                    print socket.inet_ntoa(ip.dst)
                    print (ip.sum)
                    print ip.len
                    print ip.ttl
                    print ip.id
                    print icmp.seq
                    
                    #print
                    #print socket.inet_ntoa(ipicmp.src)
                    #print socket.inet_ntoa(ipicmp.dst)
                    #print repr(icmp)
                    #print icmp.sum
                    #print icmp.type
                    #print icmp.code
                    #print repr(ipicmp)
                    #print socket.inet_ntoa(ipicmp.src)
                    #print repr(dataicmp)

                    #print repr(icmp)
                    #print repr(tcp)
                    #print repr(dataicmp)
                    #print repr(dataicmp.data)

                #else:
                    #print 'bukan'

        except:
            pass
