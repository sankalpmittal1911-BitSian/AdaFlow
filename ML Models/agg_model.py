from scapy.all import *
import os
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.tree import DecisionTreeClassifier
    
path = "/home/c310/P4-Project/Traces/Traces_Mal/Tuesday-WorkingHours.pcap"
    
X_train = []
y_train = []
X_test = []
y_test = []
idle_timeout = 5
active_timeout = 120
FIN = 0x01
RST = 0x04
SYN = 0x02
PSH = 0x08
ACK = 0x10
fls_train = 0
fls_test = 0

train_flows = pickle.load(open("train_flows.pkl", "rb"))
test_flows = pickle.load(open("test_flows.pkl", "rb"))
    
def extract_features(pkt_list):
    feats = [0,0,0]
    if TCP in pkt_list[0]: 
        feats[0] = pkt_list[0][TCP].dport
    elif UDP in pkt_list[0]:
        feats[0] = pkt_list[0][UDP].dport

    feats[1] = sum([len(pkt) for pkt in pkt_list])/len(pkt_list)
    feats[2] = max([len(pkt) for pkt in pkt_list])
    return feats
    
def extract_flows(path):
    global fls_test, fls_train, idle_timeout, X_test, y_test, X_train, y_train, train_flows, test_flows
    flows = {}
    c = 0
    # packets = rdpcap(path)
    for packet in PcapReader(path):
        c += 1
        print(c)
        train = True
        flow_tuple = ()
        if IP in packet and (TCP in packet or UDP in packet):
            # Define a tuple that represents the 5-tuple information of the packet
            if TCP in packet:
                flow_tuple = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport, 6)
            else:
                flow_tuple = (packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport,17)
            if(flow_tuple in train_flows):
                train = True
            elif(flow_tuple in test_flows):
                train = False
            else:
                continue
            if(flow_tuple in flows):
                if((len(flows[flow_tuple]) > 0) and (packet.time - flows[flow_tuple][-1].time > idle_timeout or flows[flow_tuple][-1].time - flows[flow_tuple][0].time > active_timeout or  (TCP in packet and (packet['TCP'].flags & FIN or packet['TCP'].flags & RST)))):
                    if(train):
                        X_train.append(extract_features(flows[flow_tuple]))
                        y_train.append(train_flows[flow_tuple])
                        fls_train += 1
                    else:
                        X_test.append(extract_features(flows[flow_tuple]))
                        y_test.append(test_flows[flow_tuple])
                        fls_test += 1
                    flows[flow_tuple] = [packet]
                elif(len(flows[flow_tuple]) > 0 and len(flows[flow_tuple]) % 20 == 0):
                    if(train):
                        X_train.append(extract_features(flows[flow_tuple]))
                        y_train.append(train_flows[flow_tuple])
                    else:
                        X_test.append(extract_features(flows[flow_tuple]))
                        y_test.append(test_flows[flow_tuple])
                    flows[flow_tuple].append(packet)
                elif(len(flows[flow_tuple]) > 0):
                    flows[flow_tuple].append(packet)
            else:
                flows[flow_tuple] = [packet]                  
    for flow_tuple, packets in flows.items():
         train = True
         if(flow_tuple in train_flows):
                train = True
         elif(flow_tuple in test_flows):
            train = False
         else:
            continue
         if(len(packets) <= 1):
             continue
         if(train):
            X_train.append(extract_features(flows[flow_tuple]))
            y_train.append(train_flows[flow_tuple])
            fls_train += 1
         else:
            X_test.append(extract_features(flows[flow_tuple]))
            y_test.append(test_flows[flow_tuple])
            fls_test += 1
    
extract_flows(path)
    
print(fls_train, " Training Flows")
    
print(fls_test, " Testing Flows")
    
    
X_train = np.array(X_train)
y_train = np.array(y_train)
p = np.random.permutation(len(y_train))
X_train, y_train = X_train[p], y_train[p]
    
print(X_train.shape)
X_test = np.array(X_test)
y_test = np.array(y_test)
p = np.random.permutation(len(y_test))
X_test, y_test = X_test[p], y_test[p]
clf = RandomForestClassifier()
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
print("Accuracy = ", (tp+tn)/(tp+tn+fp+fn))
print("Recall = ", tp/(tp+fn))
print("Precision = ", tp/(tp+fp))
print("FPR = ", fp/(tn+fp))
print("FNR = ", fn/(tp+fn))
    
pickle.dump(clf, open('rf_af_agg.pkl', 'wb'))
    
clf = DecisionTreeClassifier()
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
print("Accuracy = ", (tp+tn)/(tp+tn+fp+fn))
print("Recall = ", tp/(tp+fn))
print("Precision = ", tp/(tp+fp))
print("FPR = ", fp/(tn+fp))
print("FNR = ", fn/(tp+fn))
    
pickle.dump(clf, open('dt_af_agg.pkl', 'wb'))
