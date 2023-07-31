from scapy.all import *
import os
import numpy as np
import pickle
import ipaddress
from fastcrc import crc16, crc32, crc64
n_pkts = 0
colls = 0
    
path = "/home/c310/P4-Project/Traces/Traces_Mal/Tuesday-WorkingHours.pcap"
test_flows = pickle.load(open("/home/c310/P4-Project/Traces/Traces_Mal/test_flows.pkl", "rb"))
    
size = 1024
FIN = 0x01
RST = 0x04
SYN = 0x02
PSH = 0x08
ACK = 0x10
    
def extract_features(pkt_list):
    feats = [0,0,0]
    if TCP in pkt_list[0]: 
        feats[0] = pkt_list[0][TCP].dport
    elif UDP in pkt_list[0]:
        feats[0] = pkt_list[0][UDP].dport

    feats[1] = sum([len(pkt) for pkt in pkt_list])/len(pkt_list)
    feats[2] = max([len(pkt) for pkt in pkt_list])
    return feats
    
def extract_flows():
    clf = pickle.load(open('/home/c310/P4-Project/Traces/Traces_Mal/rf_af_agg.pkl', 'rb'))
    global n_pkts, colls
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    flows = {}
    ids = {}
    packets = PcapReader(path)
    for packet in packets:
        n_pkts += 1
        print(n_pkts)
        src_ip = 0
        dst_ip = 0
        sport = 0
        dport = 0
        prot = 0
        flow_tuple_orig = ()
        flow_tuple = ()
        if IP in packet and (TCP in packet or UDP in packet):
            # Define a tuple that represents the 5-tuple information of the packet
            if TCP in packet:
                flow_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, 6)
            else:
                flow_tuple = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport,17)
    
        flow_tuple_orig = flow_tuple
        if(flow_tuple_orig not in test_flows):
            continue
        
        if IP in packet:
            src_ip = int(ipaddress.ip_address(packet[IP].src))
            dst_ip = int(ipaddress.ip_address(packet[IP].dst))
        if TCP in packet:
            sport=packet[TCP].sport
            dport=packet[TCP].dport
            if IP in packet:
                prot = 6
        elif UDP in packet:
            sport=packet[UDP].sport
            dport=packet[UDP].dport
            if IP in packet:
                prot = 17
    
        # ip1 = min(src_ip, dst_ip)
        # ip2 = max(src_ip, dst_ip)
    
        # port1 = min(sport, dport)
        # port2 = max(sport, dport)
    
        flow_tuple = (src_ip, dst_ip, sport, dport, prot)
        
        idx = 0 
        idx2 = 0
        if(IP in packet):
            idx = crc64.ecma_182(str.encode(str(src_ip)+str(dst_ip)+str(sport)+str(dport)+str(prot)))%size 
            idx2 = crc64.ecma_182(str.encode(str(dst_ip)+str(src_ip)+str(dport)+str(sport)+str(prot)))%size 
        dir = 'f'
        # print("HERE")
        if(idx not in flows):
            if(idx2 in flows):
                dir = 'b'
        if(idx in flows):
            if(idx == ids[idx]):
                flow_feats = np.array(extract_features(flows[idx]))
                flow_feats = flow_feats.reshape(1,3)
                if(len(flows[idx]) == 8):
                    colls += 1
                    c = clf.predict(flow_feats)[0]
                    if(c == 1 and test_flows[flow_tuple_orig] == 1):
                        tp += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 0):
                        tn += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 1):
                        fn += 1
                    else:
                        fp += 1
                    ids[idx] = idx
                    flows[idx] = [(packet, dir)]
                else:
                    ids[idx] = idx
                    flows[idx].append((packet, dir))
            else:
                #Evict on collision
                flow_feats = np.array(extract_features(flows[idx]))
                flow_feats = flow_feats.reshape(1,3)
                c = clf.predict(flow_feats)
                if(c == 1 and test_flows[flow_tuple_orig] == 1):
                    tp += 1
                elif(c == 0 and test_flows[flow_tuple_orig] == 0):
                    tn += 1
                elif(c == 0 and test_flows[flow_tuple_orig] == 1):
                    fn += 1
                else:
                    fp += 1
                ids[idx] = idx
                flows[idx] = [(packet, dir)]
        else:
            flows[idx] = [(packet, dir)]
            ids[idx] = idx
    
    # for i in flows:
    #     flow_feats = np.array(extract_features(flows[i]))
    #     flow_feats = flow_feats.reshape(1,7)
    #     c = clf.predict(flow_feats)[0]
    #     if(c == 1 and test_flows[flow_tuple_orig] == 1):
    #         tp += 1
    #     elif(c == 0 and test_flows[flow_tuple_orig] == 0):
    #         tn += 1
    #     elif(c == 0 and test_flows[flow_tuple_orig] == 1):
    #         fn += 1
    #     else:
    #         fp += 1
    
            
    print("Accuracy = ", (tp+tn)/(tp+tn+fp+fn))
    print("Recall = ", tp/(tp+fn))
    print("Precision = ", tp/(tp+fp))
    print("FPR = ", fp/(tn+fp))
    print("FNR = ", fn/(tp+fn))
    print("Recirculations = ", colls/n_pkts)
    
    
extract_flows()
     
