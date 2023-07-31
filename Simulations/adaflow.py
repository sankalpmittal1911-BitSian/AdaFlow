from scapy.all import *
import os
import numpy as np
import pickle
import ipaddress
from fastcrc import crc16, crc32, crc64
    
path = "/home/c310/P4-Project/Traces/Traces_Mal/Tuesday-WorkingHours.pcap"
    
size = 1024
clf_dt = pickle.load(open('/home/c310/P4-Project/Traces/Traces_Mal/dt_af_agg.pkl', 'rb'))
#clf_xgb = pickle.load(open('xgb_af_agg.pkl', 'rb'))
clf_pkt = pickle.load(open('/home/c310/P4-Project/Traces/Traces_Mal/attack.pkl', 'rb'))
dt_m = 0.8
dt_b = 0.8
idle_timeout = 5
active_timeout = 120
FIN = 0x01
RST = 0x04
SYN = 0x02
PSH = 0x08
ACK = 0x10
recircs = 0
n_pkts = 0
test_flows = pickle.load(open("/home/c310/P4-Project/Traces/Traces_Mal/test_flows.pkl", "rb"))
    
    
def extract_features(pkt_list):
    feats = [0,0,0]
    if TCP in pkt_list[0]: 
        feats[0] = pkt_list[0][TCP].dport
    elif UDP in pkt_list[0]:
        feats[0] = pkt_list[0][UDP].dport

    feats[1] = sum([len(pkt) for pkt in pkt_list])/len(pkt_list)
    feats[2] = max([len(pkt) for pkt in pkt_list])
    return feats
    
def extract_headers(packet):
    features = []
    
    # Extract relevant packet header information
    if IP in packet:
        features.extend([packet[IP].proto, len(packet), packet[IP].tos & 0x3F, packet[IP].ttl])
    else:
        features.extend([0, 0, 0, 0])
        
    
    if TCP in packet:
        features.extend([packet[TCP].dataofs, packet[TCP].window])
    else:
        features.extend([0, 0])
    
    if UDP in packet:
        features.append(packet[UDP].len)
    else:
        features.append(0)
    
    return np.array(features).reshape(1, len(features))
    
def extract_flows():
    global recircs, n_pkts
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    flows = {}
    ids = {}
    classes = {}
    prioritizes = {}
    packets = PcapReader(path)
    nc = 0
    for packet in packets:
        nc+=1
        print(nc)
        n_pkts += 1
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
        # port2 = max(sport, dport)
    
        flow_tuple = (src_ip, dst_ip, sport, dport, prot)
        
        idx = 0 
        idx2 = 0
        if(IP in packet):
            idx = crc16.xmodem(str.encode(str(src_ip)+str(dst_ip)+str(sport)+str(dport)+str(prot)))%size 
            idx2 = crc16.xmodem(str.encode(str(dst_ip)+str(src_ip)+str(dport)+str(sport)+str(prot)))%size 
        dir = 'f'
        # print("HERE")
        if(idx not in flows):
            if(idx2 in flows):
                dir = 'b'
        if(idx in flows):
            if(idx == ids[idx]): #No Collision
                # print(type(extract_features(flows[idx])))
                flow_feats = np.array(extract_features(flows[idx]))
                flow_feats = flow_feats.reshape(1,3)
                c = clf_dt.predict(flow_feats)[0]
                p = max(clf_dt.predict_proba(flow_feats)[0])
                prioritize = 0
                if(c == 0):
                    prioritize = 1 - (p > dt_b)
                else:
                    prioritize = 1 - (p > dt_b)
                if(prioritize == 1):
                    recircs += 1
                classes[idx] = c
                prioritizes[idx] = prioritize
                if((len(flows[idx]) > 0) and (packet.time - flows[idx][-1][0].time > idle_timeout or flows[idx][-1][0].time - flows[idx][0][0].time > active_timeout or  (TCP in packet and (packet['TCP'].flags & FIN or packet['TCP'].flags & RST)))): #Timeout
                    if(c == 1 and test_flows[flow_tuple_orig] == 1):
                        tp += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 0):
                        tn += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 1):
                        fn += 1
                    else:
                        fp += 1
                    headers = extract_headers(packet)
                    c = clf_pkt.predict(headers)
                    p = max(clf_pkt.predict_proba(headers))
                    classes[idx] = c
                    flows[idx] = [(packet, dir)]
                    ids[idx] = idx
                    if(c == 1):
                        prioritizes[idx] = 1 - (p>dt_m)
                    else:
                        prioritizes[idx] = 1 - (p>dt_b)
                else:  #Update
                    classes[idx] = c
                    ids[idx] = idx
                    flows[idx].append((packet, dir))
                    # sures[idx] = 0
            else: #Collision
                c = classes[idx]
                prioritize = prioritizes[idx]
                if(prioritize == 0): #benign, evict and classify or sure malicious
                    if(c == 1 and test_flows[flow_tuple_orig] == 1):
                        tp += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 0):
                        tn += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 1):
                        fn += 1
                    else:
                        fp += 1
                    headers = extract_headers(packet)
                    c = clf_pkt.predict(headers)
                    p = max(clf_pkt.predict_proba(headers))
                    classes[idx] = c
                    flows[idx] = [(packet, dir)]
                    ids[idx] = idx
                    if(c == 1):
                        prioritizes[idx] = 1 - (p>dt_m)
                    else:
                        prioritizes[idx] = 1 - (p>dt_b)
                else: #Collision with unsure malicious
                    headers = extract_headers(packet)
                    c = clf_pkt.predict(headers)
                    if(c == 1 and test_flows[flow_tuple_orig] == 1):
                        tp += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 0):
                        tn += 1
                    elif(c == 0 and test_flows[flow_tuple_orig] == 1):
                        fn += 1
                    else:
                        fp += 1
    
    
    
        else:
            headers = extract_headers(packet)
            c = clf_pkt.predict(headers)
            p = max(clf_pkt.predict_proba(headers))
            classes[idx] = c
            flows[idx] = [(packet,dir)]
            ids[idx] = idx
            if(c == 1):
                prioritizes[idx] = 1 - (p>dt_m)
            else:
                prioritizes[idx] = 1 - (p>dt_b)
    
    print("Accuracy = ", (tp+tn)/(tp+tn+fp+fn))
    print("Recall = ", tp/(tp+fn))
    print("Precision = ", tp/(tp+fp))
    print("FPR = ", fp/(tn+fp))
    print("FNR = ", fn/(tp+fn))
    print("REC RATE = ", recircs/n_pkts)
    
    
extract_flows()
    
