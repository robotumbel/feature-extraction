
import binascii
import tcpudp

def convert_mac(mac_add):

    s = list()
    for i in range(12/2):
        s.append(mac_add[i*2:i*2+2])
    r = ":".join(s)
    return r

def decode_arp(eth):
    data_conection = []

    arp = eth.arp
    data = arp.data
    #ip_source = socket.inet_ntoa(arp.spa)
    hardware_source = convert_mac(binascii.hexlify(arp.sha))
    #ip_dest = socket.inet_ntoa(arp.tpa)
    hardware_dest = convert_mac(binascii.hexlify(arp.tha))

    #data_conection.append("arp")
    pyload = tcpudp.payload(data)

    data_conection.append('arp')
    data_conection.append(hardware_source)
    data_conection.append(hardware_dest)
    data_conection.append('')
    data_conection.append('')
    data_conection.append('')  # seq
    data_conection.append('')  # ack
    data_conection.append('')  # window size
    data_conection.append('')  # tcp flags
    data_conection.append('')  # time to live
    data_conection.append('')  # len
    data_conection.append('')
    data_conection.append('')
    data_conection.append('')
    data_conection.append('')  # tcp len
    data_conection.append('')
    data_conection.append('')
    #data_conection.append(pyload)

    return data_conection


