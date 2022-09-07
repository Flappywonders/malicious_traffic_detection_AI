import socket
import os
from scapy.all import *

write_folder = "./2022champion_100_100/white/"
write_files = os.walk(write_folder)
black_folder = "./2022champion_100_100/black/"
black_files = os.walk(black_folder)




def get_features(pkgs):
    #store features
    IP_LEN = []
    IP_PROTO = []
    UDP_SPORT = []
    UDP_DPORT = []
    TCP_SPORT = []
    TCP_DPORT = []
    TCP_SEQ = []
    TCP_ACK = []
    TCP_OPTIONS = []
    RAW_LOAD = []
    for pkg in pkgs:
        pkg.show()
        #init features
        ip_len = ''
        ip_proto = ''
        udp_sport = ''
        udp_dport = ''
        tcp_sport = ''
        tcp_dport = ''
        tcp_seq = ''
        tcp_ack = ''
        tcp_options = ''
        raw_load = ''

        if 'IP' in pkg:
            if hasattr(pkg['IP'],'len'):
                ip_len = pkg['IP'].len
            if hasattr(pkg['IP'],ip_proto):
                ip_proto = pkg['IP'].proto
        if 'UDP' in pkg:
            if hasattr(pkg['UDP'],'sport'):
                udp_sport = pkg['UDP'].sport
            if hasattr(pkg['UDP'],'dport'):
                udp_dport = pkg['UDP'].dport
        if 'TCP' in pkg:
            if hasattr(pkg['TCP'],'sport'):
                tcp_sport = pkg['TCP'].sport
            if hasattr(pkg['TCP'],'dport'):
                tcp_dport = pkg['TCP'].dport
            if hasattr(pkg['TCP'],'seq'):
                tcp_seq = pkg['TCP'].seq
            if hasattr(pkg['TCP'],'ack'):
                tcp_ack = pkg['TCP'].ack
            if hasattr(pkg['TCP'],'options'):
                tcp_options = pkg['TCP'].options

        if 'Raw' in pkg:
            if hasattr(pkg['Raw'],'load'):
                raw_load = pkg['Raw'].load

        IP_LEN.append(ip_len)
        IP_PROTO.append(ip_proto)
        UDP_SPORT.append(udp_sport)
        UDP_DPORT.append(udp_dport)
        TCP_SPORT.append(tcp_sport)
        TCP_DPORT.append(tcp_dport)
        TCP_SEQ.append(tcp_seq)
        TCP_ACK.append(tcp_ack)
        TCP_OPTIONS.append(tcp_options)
        RAW_LOAD.append(raw_load)

        features = {}
        features['ip_len'] = IP_LEN
        features['ip_proto'] = IP_PROTO
        features['udp_sport'] = UDP_SPORT
        features['udp_dport'] = UDP_DPORT
        features['tcp_sport'] = TCP_SPORT
        features['tcp_dport'] = TCP_DPORT
        features['tcp_seq'] = TCP_SEQ
        features['tcp_ack'] = TCP_ACK
        features['tcp_options'] = TCP_OPTIONS
        features['raw_load'] = RAW_LOAD

        return features




#white features
for path,dir_list,file_list in write_files:
    for file_name in file_list:
        print(os.path.join(path, file_name) )
        pkgs = rdpcap(os.path.join(path, file_name))
        result_fea = get_features(pkgs)
        print(result_fea)





print("   ")
print("=======================================================")
print("   ")

#black features
for path,dir_list,file_list in black_files:
    for file_name in file_list:
        print(os.path.join(path, file_name) )
        pkgs = rdpcap(os.path.join(path, file_name))
        result_fea = get_features(pkgs)
        print(result_fea)






