import dpkt
import socket


def payload(data):

    s ='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,/\;][=-0987654321`~!@#$%^&*()_+{}|:"<>? '
    data = str(data)
    i = 0
    py = ''
    for i in range(len(data)):
        a = data[i]
        if a in s:
            py = py + a
        else:
            py = py + ('.')

        i = +1
    return py


def convert_ip(src,dst):

    ip_src = socket.inet_ntoa(src)
    ip_dst = socket.inet_ntoa(dst)
    return ip_src, ip_dst

def tcp_flags(flags):

    con_flags = ''

    if flags & dpkt.tcp.TH_FIN:
        con_flags = con_flags + 'F'
    if flags & dpkt.tcp.TH_SYN:
        con_flags = con_flags + 'S'
    if flags & dpkt.tcp.TH_RST:
        con_flags = con_flags + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        con_flags = con_flags + 'P'
    if flags & dpkt.tcp.TH_ACK:
        con_flags = con_flags + 'A'
    if flags & dpkt.tcp.TH_URG:
        con_flags = con_flags + 'U'
    if flags & dpkt.tcp.TH_ECE:
        con_flags = con_flags + 'E'
    if flags & dpkt.tcp.TH_CWR:
        con_flags = con_flags + 'C'
    return con_flags


def tcp(eth):
    data_conection = []
    ip = eth.data
    tcp = ip.data
    IP = convert_ip(ip.src, ip.dst)
    tcp_paket_flags = tcp_flags(tcp.flags)
    flags = str(tcp_paket_flags).strip('')
    #print "Paket ke %d TCP Src: %s, %s Dst:%s, %s, len: %d, ttl: %d, %s, %s" %(IP[0],tcp.sport,IP[1],tcp.dport,ip.len,ip.ttl,tcp_paket_flags)

    payload_tcp = payload(tcp.data) #convert pyload human read
    servic = 'TCP'
    ser = str(servic).strip('')


    if tcp.dport == 80 or tcp.sport == 80 :
        data_conection.append("http")

    elif tcp.dport == 21 or tcp.sport == 21 :
        data_conection.append('ftp')

    elif tcp.dport == 22 or tcp.sport == 22 :
        data_conection.append('ssh')

    elif tcp.dport == 23 or tcp.sport == 23 :
        data_conection.append('telnet')

    elif tcp.dport == 443 or tcp.sport == 443 :
        data_conection.append('https')

    elif tcp.dport == 25 or tcp.sport == 25 :
        data_conection.append('smtp')

    elif tcp.dport == 109 or tcp.sport == 109 :
        data_conection.append('pop2')

    elif tcp.dport == 110 or tcp.sport == 110:
        data_conection.append('pop3')

    elif tcp.dport == 143 or tcp.sport == 143 :
        data_conection.append('imap')

    elif tcp.dport == 139 or tcp.sport == 139 :
        data_conection.append('smb')

    elif tcp.dport == 161 or tcp.sport == 161:
        data_conection.append('snmp')

    elif tcp.dport == 20 or tcp.sport == 20:
        data_conection.append('ftp-data')

    #elif tcp.dport == 53 or tcp.sport == 53 :
    #    data_conection.append('dns')

    elif tcp.dport == 514 or tcp.sport == 514:
        data_conection.append('rsh')

    else:
        data_conection.append('tcp')


    data_conection.append(IP[0])  # ip source
    data_conection.append(IP[1])  # ip destination
    data_conection.append(tcp.sport)  # source port
    data_conection.append(tcp.dport)  # destination port
    data_conection.append(tcp.seq)  # seq
    data_conection.append(tcp.ack)  # ack
    data_conection.append(tcp.win)  # window size
    data_conection.append(flags)  # tcp flags
    data_conection.append(ip.ttl)  # time to live
    data_conection.append(ip.len)  # len
    data_conection.append(ip.sum)
    data_conection.append(ip.id)
    data_conection.append(ip.off)
    data_conection.append(tcp.__len__())  # tcp len
    data_conection.append('tcp')
    data_conection.append('')
   # data_conection.append(payload_tcp)
    data_conection.append('')
    data_conection.append(payload_tcp)


    return data_conection

def udp(eth):

    data_conection = []
    ip = eth.data
    udp = ip.data
    IP = convert_ip(ip.src, ip.dst)
    #print "Paket ke %d UDP Src: %s, %s Dst:%s, %s len: %d, ttl: %d, %s" %(IP[0],tcp.sport,IP[1],tcp.dport,ip.len,ip.ttl)


    payload_udp = payload(udp.data)

    if udp.dport == 80 or udp.sport == 80:
        data_conection.append("http")

    elif udp.dport == 21 or udp.sport == 21:
        data_conection.append('ftp')

    elif udp.dport == 22 or udp.sport == 22:
        data_conection.append('ssh')

    elif udp.dport == 23 or udp.sport == 23:
        data_conection.append('telnet')

    elif udp.dport == 443 or udp.sport == 443:
        data_conection.append('https')

    elif udp.dport == 25 or udp.sport == 25:
        data_conection.append('smtp')

    elif udp.dport == 109 or udp.sport == 109:
        data_conection.append('pop2')

    elif udp.dport == 110 or udp.sport == 110:
        data_conection.append('pop3')

    elif udp.dport == 143 or udp.sport == 143:
        data_conection.append('imap')

    elif udp.dport == 139 or udp.sport == 139:
        data_conection.append('smb')

    elif udp.dport == 161 or udp.sport == 161:
        data_conection.append('snmp')

    elif udp.dport == 53 or udp.sport == 53 :
        data_conection.append('dns')

    elif udp.dport == 5353 or udp.sport == 5353 :
        data_conection.append('mdns')

    elif udp.dport == 20 or udp.sport == 20:
        data_conection.append('ftp-data')
    else :
        data_conection.append('udp')

    data_conection.append(IP[0])
    data_conection.append(IP[1])
    data_conection.append(udp.sport)
    data_conection.append(udp.dport)
    data_conection.append('')
    data_conection.append('')
    data_conection.append('')
    data_conection.append('')
    data_conection.append(ip.ttl)
    data_conection.append(ip.len)
    data_conection.append(ip.sum)
    data_conection.append(ip.id)
    data_conection.append(ip.off)
    data_conection.append(udp.__len__())
    data_conection.append('udp')
    data_conection.append('')
    #data_conection.append(payload_udp)
    data_conection.append('')
    data_conection.append(payload_udp)


    return data_conection

def icmp(eth):
	data_conection = []
	ip = eth.data
	icmp = ip.data
	IP = convert_ip(ip.src, ip.dst)
	
    
	if str(icmp.type) == "8":
		
		data_conection.append('icmp')
		data_conection.append(IP[0])
		data_conection.append(IP[1])
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append(ip.ttl)
		data_conection.append(ip.len)
		data_conection.append(ip.sum)
		data_conection.append(ip.id)
		data_conection.append('')
		data_conection.append(icmp.__len__())
		data_conection.append('icmp')
		data_conection.append(icmp.code)
		data_conection.append(icmp.type)
		data_conection.append(repr(icmp.data)+" No response seen to ICMP request")
	
	return data_conection
	"""
    if str(icmp.type) == "3":
		icmp_ = eth.data
		data_icmp = icmp_.data
		isi_icmp = data_icmp.data
		ip = isi_icmp.data
		udp = ip.data
		payload_icmp = payload(udp.data)
		IP = convert_ip(ip.src, ip.dst)
		#ICMP(sum=43079, code=3, type=3, data=Unreach(data=IP(src='\nd\xcb5', dst='\nd\xcb2', sum=34073, len=29, p=17, ttl=128, id=2695,data=UDP(dport=7, sum=33162, sport=54042, ulen=9, data='\x00'))))

		data_conection.append('icmp')
		data_conection.append(IP[0])
		data_conection.append(IP[1])
		data_conection.append(udp.sport)
		data_conection.append(udp.dport)
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append('')
		data_conection.append(ip.ttl)
		data_conection.append(ip.len)
		data_conection.append(ip.sum)
		data_conection.append('')
		data_conection.append('')
		data_conection.append(udp.__len__())
		data_conection.append(data_icmp.code)
		data_conection.append(data_icmp.type)
		data_conection.append('icmp')
		data_conection.append(payload_icmp)
		
	"""

	
		
    
