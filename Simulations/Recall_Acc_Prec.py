from scapy.all import *
import ipaddress
from fastcrc import crc16, crc32
import pickle
import pandas as pd
import numpy as np
 
size = 1024
active_timeout = 120
idle_timeout = 15
FIN = 0x01
RST = 0x04
SYN = 0x02
PSH = 0x08
ACK = 0x10

rf = pickle.load(open("/home/netx2/RF.pkl", 'rb'))
dt = pickle.load(open("/home/netx2/DT.pkl",'rb'))
 
 
flow_cache = {}
#Initialize
for i in range(size):
    flow_cache[i] = [0,0]
 
 
def action_flow0(idx):
    if(flow_cache[idx][0] == 0):
        if(flow_cache[idx][1] == 0):
            flow_cache[idx][0] = 1
            return True
        else:
            return False
    else:
        return True
 
 
def action_flow1(idx):
    if(flow_cache[idx][1] == 0):
        if(flow_cache[idx][0] == 0):
            flow_cache[idx][1] = 1
            return True
        else:
            return False
    else:
        return True
 
 
tuple_reg = {}
#Initialize
for i in range(size):
    tuple_reg[i] = [0,0,0,0,0]
 
def return_tuple(idx, i1, i2, p1, p2, p):
    temp = tuple_reg[idx]
    tuple_reg[idx] = [i1, i2, p1, p2, p]
    return temp
 
flow_dur = {}
#Initialize
for i in range(size):
    flow_dur[i] = 0
 
def flow_duration(idx, time):
    if(flow_dur[idx] == 0):
        flow_dur[idx] = time
    return time - flow_dur[idx]
 
 
last_ts = {}
#Initialize
for i in range(size):
    last_ts[i] = 0
 
def last_time(idx, time):
    if(last_ts[idx] == 0):
        last_ts[idx] = time
        return time
    else:
        temp = last_ts[idx]
        last_ts[idx] = time
        return temp
 
active_ts = {}
#Initialize
for i in range(size):
    active_ts[i] = 0
 
def active_timestamp(idx, time, update = False):
    if(active_ts[idx] == 0):
        active_ts[idx] = time
        return time
    if(update):
        temp = active_ts[idx]
        active_ts[idx] = time
        return temp
    else:
        return active_ts[idx]
 
coll_reg = {}
#Initialize
for i in range(size):
    coll_reg[i] = 0
 
def collision(idx, id):
    flag = False
    if(coll_reg[idx] != id):
        flag = True
    coll_reg[idx] = id
    return flag
 
pkt_reg = {}
#Initialize
for i in range(size):
    pkt_reg[i] = 0
 
def pkt_count(idx, reset):
    temp = pkt_reg[idx]
    if(reset):
        pkt_reg[idx] = 1
    else:
        pkt_reg[idx] = pkt_reg[idx] + 1
        temp = pkt_reg[idx]
    return temp
 
spcf = {}
#Initialize
for i in range(size):
    spcf[i] = [0,0,0]
 
def flags_count(idx, synf, pshf, ackf, reset):
    temp = spcf[idx]
    if(synf):
        if(reset):
            spcf[idx][0] = 1
        else:
            spcf[idx][0] = spcf[idx][0] + 1
    if(pshf):
        if(reset):
            spcf[idx][1] = 1
        else:
            spcf[idx][1] = spcf[idx][1] + 1
    if(ackf):
        if(reset):
            spcf[idx][2] = 1
        else:
            spcf[idx][2] = spcf[idx][2] + 1
    if(not reset):
        temp = spcf[idx]
    return temp
 
lengths_reg = {}
#Initialize
for i in range(size):
    lengths_reg[i] = [0,0]
 
def length_cal(idx, isFwd, cond, init_len, reset):
    temp = lengths_reg[idx]
 
    if(cond):
        if(reset):
            lengths_reg[idx][0] = init_len
            if(isFwd):
                lengths_reg[idx][1] = init_len
        else:
            lengths_reg[idx][0] = lengths_reg[idx][0] + init_len
            if(isFwd):
                lengths_reg[idx][1] = lengths_reg[idx][1] + init_len
            temp = lengths_reg[idx]
    return temp
 
fwindow = {}
#Initialize
for i in range(size):
    fwindow[i] = 0
 
def window_cal(idx, isFwd, cond, init_win):
    temp = fwindow[idx]
    if(cond and isFwd and fwindow[idx] == 0):
        fwindow[idx] = init_win
    return temp
 
 
times_reg = {}
for i in range(size):
    times_reg[i] = [0,0,0]
def times_cal(idx, reset, act_dur, inactive_dur):
    if(reset):
        if(times_reg[idx][0] == 0):
            times_reg[idx][0] = act_dur
        else:
            times_reg[idx][0] = min(times_reg[idx][0], act_dur)
        if(times_reg[idx][1] == 0):
            times_reg[idx][1] = act_dur
        else:
            times_reg[idx][1] = times_reg[idx][1] + act_dur
        if(times_reg[idx][2] == 0):
            times_reg[idx][2] = inactive_dur
        else:
             times_reg[idx][2] = min(times_reg[idx][2], inactive_dur)
    return times_reg[idx]
 
act_segs = {}
for i in range(size):
    act_segs[i] = 0
 
def active_segs(idx, reset, isFwd):
    if(reset and isFwd):
        act_segs[idx] = act_segs[idx] + 1
    return act_segs[idx]
 
 
mal_flows = {}
for i in range(size):
    mal_flows[i] = 0
           
               
pcap_trace = "/home/netx2/Tuesday-WorkingHours.pcap"
 
pcap_flow = PcapReader(pcap_trace)
 
t0 = 1499169212.364079

tp = 0
tn = 0
fn = 0
fp = 0

for pkt in pcap_flow:
    src_ip = 0
    dst_ip = 0
    sport = 0
    dport = 0
    prot = 0
    reset = False
    if IP in pkt:
        src_ip = int(ipaddress.ip_address(pkt[IP].src))
        dst_ip = int(ipaddress.ip_address(pkt[IP].dst))
    if TCP in pkt:
        sport=pkt[TCP].sport
        dport=pkt[TCP].dport
        if IP in pkt:
            prot = 6
    elif UDP in pkt:
        sport=pkt[UDP].sport
        dport=pkt[UDP].dport
        if IP in pkt:
            prot = 17
 
    ip1 = min(src_ip, dst_ip)
    ip2 = max(src_ip, dst_ip)
 
    port1 = min(sport, dport)
    port2 = max(sport, dport)
 
    cache_idx = crc16.xmodem(str.encode(str(ip1)+str(ip2)))%size
    isFwd = False
    if(ip1 == src_ip):
        isFwd = action_flow0(cache_idx)
    else:
        isFwd = action_flow1(cache_idx)
    
    srcAddr = 0
    dstAddr = 0
    srcPort = 0
    dstPort = 0
 
    if(isFwd):
        srcAddr = src_ip    
        dstAddr = dst_ip
        srcPort = sport
        dstPort = dport
    else:
        srcAddr = dst_ip
        dstAddr = src_ip
        srcPort = dport
        dstPort = sport
 
    idx = 0
    if(IP in pkt):
        idx = crc16.xmodem(str.encode(str(ip1)+str(ip2)+str(port1)+str(port2)+str(prot)))%size
 
    ip1_out, ip2_out, p1_out, p2_out, prot_out = return_tuple(idx, srcAddr, dstAddr, srcPort, dstPort, prot)
    flow_id = str(ipaddress.ip_address(ip1_out))+"-"+str(ipaddress.ip_address(ip2_out))+"-"+str(p1_out)+"-"+str(p2_out)+"-"+str(prot_out)
    #Check for collision
    id = crc32.aixm(str.encode(str(ip1)+str(ip2)+str(port1)+str(port2)+str(prot)))%size
    coll = collision(idx, id)
    if(not coll):
        duration = flow_duration(idx, pkt.time)
        lt = last_time(idx, pkt.time)
        inactive_duration = pkt.time - lt
        active_duration = pkt.time - active_timestamp(idx, pkt.time)
 
        if(active_duration>=active_timeout or inactive_duration>=idle_timeout or (TCP in pkt and (pkt['TCP'].flags & FIN or pkt['TCP'].flags & RST))):
            reset = True
            _ = active_timestamp(idx, pkt.time, reset)
        
        pc = pkt_count(idx, reset)
        if(pc == 0):
            reset = False
        
        synf = TCP in pkt and (pkt['TCP'].flags & SYN)
        pshf = TCP in pkt and (pkt['TCP'].flags & PSH)
        ackf = TCP in pkt and (pkt['TCP'].flags & ACK)
        syn_count, psh_count, ack_count = flags_count(idx, synf, pshf, ackf, reset)
        cond = IP in pkt
        ihl = 0
        if(cond):
            ihl = pkt[IP].ihl
        tot_len, fwd_len = length_cal(idx, isFwd, cond, ihl, reset)
        cond = (IP in pkt) and (TCP in pkt)
        win = 0
        if(cond):
            win = pkt[IP].window
        fwin = window_cal(idx, isFwd, cond, win)
        act_min, act_mean, fit = times_cal(idx, reset, active_duration, inactive_duration)
        sfs = active_segs(idx, reset, isFwd)
        aps = 0
        if(sfs != 0):
            act_mean = act_mean/sfs
        else:
            act_mean = 0
        
        if(pc!=0):
            aps = tot_len/pc
        else:
            aps = 0
        sfb = 0
        if(pc!=0):
            sfb = (fwd_len/pc)*sfs
        
        if(reset):
            mal_flows[idx] = 0
            y_pred = rf.predict(np.array([duration, fwd_len, fit, aps, syn_count, psh_count, ack_count, sfb, fwin, act_mean, act_min]).reshape(-1,11))[0]
            with open("/home/netx2/flows.txt", "a") as f:
                f.write(flow_id+","+str(y_pred)+"\n")
               

        #We are fine with single packet delay
        else:
            if(dt.predict(np.array([duration, fwd_len, fit, aps, syn_count, psh_count, ack_count, sfb, fwin, act_mean, act_min]).reshape(-1,11))[0]==1):
                mal_flows[idx] = 1
        
    else:
        mal_flow = mal_flows[idx]
        if(mal_flow == 0):
            duration = pkt.time - flow_dur[idx]
            flow_dur[idx] = pkt.time
            inactive_duration = pkt.time - last_ts[idx] 
            last_ts[idx] = pkt.time
            active_duration = pkt.time - active_ts[idx]
            active_ts[idx] = pkt.time
 
            pc = pkt_reg[idx]
            pkt_reg[idx] = 1
 
            synf = TCP in pkt and (pkt['TCP'].flags & SYN)
            pshf = TCP in pkt and (pkt['TCP'].flags & PSH)
            ackf = TCP in pkt and (pkt['TCP'].flags & ACK)
            syn_count, psh_count, ack_count = spcf[idx]
            spcf[idx] = [0,0,0]
            if(synf):
                spcf[idx][0] = 1
            if(pshf):
                spcf[idx][1] = 1
            if(ackf):
                spcf[idx][2] = 1
            cond = IP in pkt
            tot_len, fwd_len =  lengths_reg[idx]
            lengths_reg[idx] = [0,0]
            if(cond):
                lengths_reg[idx][0] = pkt[IP].ihl
                if(isFwd):
                    lengths_reg[idx][1] = pkt[IP].ihl
            cond = (IP in pkt) and (TCP in pkt)
            fwin = fwindow[idx]
            fwindow[idx] = 0
            if(cond):
                fwindow[idx] = pkt[IP].window
            act_min, act_mean, fit  = times_reg[idx]
            times_reg[idx] = [active_duration, active_duration, inactive_duration]
            sfs = act_segs[idx]
            act_segs[idx] = 0
            if(isFwd):
                act_segs[idx] = 1
            aps = 0
            if(sfs != 0):
                act_mean = act_mean/sfs
            else:
                act_mean = 0
            
            if(pc!=0):
                aps = tot_len/pc
            else:
                aps = 0
            sfb = 0
            if(pc!=0):
                sfb = (fwd_len/pc)*sfs
            y_pred = rf.predict(np.array([duration, fwd_len, fit, aps, syn_count, psh_count, ack_count, sfb, fwin, act_mean, act_min]).reshape(-1,11))[0]
            with open("/home/netx2/flows.txt", "a") as f:
                f.write(flow_id+","+str(y_pred)+"\n")
        else:
            duration = flow_duration(idx, pkt.time)
            lt = last_time(idx, pkt.time)
            inactive_duration = pkt.time - lt
            active_duration = pkt.time - active_timestamp(idx, pkt.time)
    
            if(active_duration>=active_timeout or inactive_duration>=idle_timeout or (TCP in pkt and (pkt['TCP'].flags & FIN or pkt['TCP'].flags & RST))):
                reset = True
                _ = active_timestamp(idx, pkt.time, reset)
            
            pc = pkt_count(idx, reset)
            if(pc == 0):
                reset = False
            
            if(reset):
            
                synf = TCP in pkt and (pkt['TCP'].flags & SYN)
                pshf = TCP in pkt and (pkt['TCP'].flags & PSH)
                ackf = TCP in pkt and (pkt['TCP'].flags & ACK)
                syn_count, psh_count, ack_count = flags_count(idx, synf, pshf, ackf, reset)
                cond = IP in pkt
                ihl = 0
                if(cond):
                    ihl = pkt[IP].ihl
                tot_len, fwd_len = length_cal(idx, isFwd, cond, ihl, reset)
                cond = (IP in pkt) and (TCP in pkt)
                win = 0
                if(cond):
                    win = pkt[IP].window
                fwin = window_cal(idx, isFwd, cond, win)
                act_min, act_mean, fit = times_cal(idx, reset, active_duration, inactive_duration)
                sfs = active_segs(idx, reset, isFwd)
                aps = 0
                if(sfs != 0):
                    act_mean = act_mean/sfs
                else:
                    act_mean = 0
                
                if(pc!=0):
                    aps = tot_len/pc
                else:
                    aps = 0
                sfb = 0
                if(pc!=0):
                    sfb = (fwd_len/pc)*sfs
            
                mal_flows[idx] = 0
                y_pred = rf.predict(np.array([duration, fwd_len, fit, aps, syn_count, psh_count, ack_count, sfb, fwin, act_mean, act_min]).reshape(-1,11))[0]
                with open("/home/netx2/flows.txt", "a") as f:
                    f.write(flow_id+","+str(y_pred)+"\n")

        
