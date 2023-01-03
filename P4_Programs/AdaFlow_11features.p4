    /* -*- P4_16 -*- */
    #include <core.p4>
    #if __TARGET_TOFINO__ == 2
    #include<t2na.p4>
    #else
    #include<tna.p4>
    #endif
    // #include "/home/tofino/Open-Tofino/p4-examples/p4_16_programs/common/util.p4"
     
    /* CONSTANTS */
     
    const bit<16> TYPE_IPV4 = 0x800;
    const bit<8>  TYPE_TCP  = 6;
    const bit<8>  TYPE_UDP  = 17;
     
    #define REGISTER_LENGTH 2048
    #define IDLE_TIMEOUT 15000
    #define ACTIVE_TIMEOUT 120000
     
    /*************************************************************************
    *********************** H E A D E R S  ***********************************
    *************************************************************************/
     
    typedef bit<9>  egressSpec_t;
    typedef bit<32> ip4Addr_t;
 
    struct pair{
        bit<8> first;
        bit<8> second;
    }
     
    header timestamp_t {
        bit<32> ts;
    }
     
     
    header ethernet_t {
       bit<48>    dst_addr;
        bit<48>    src_addr;
        bit<16>   etherType;
    }
     
     
    header ipv4_t {
        bit<4>    version;
        bit<4>    ihl;
        bit<8>    tos;
        bit<16>   totalLen;
        bit<16>   identification;
        bit<3>    flags;
        bit<13>   fragOffset;
        bit<8>    ttl;
        bit<8>    protocol;
        bit<16>   hdrChecksum;
        ip4Addr_t srcAddr;
        ip4Addr_t dstAddr;
    }
     
     
    header tcp_t{
        bit<16> srcPort;
        bit<16> dstPort;
        bit<32> seqNo;
        bit<32> ackNo;
        bit<4>  dataOffset;
        bit<4>  res;
        bit<1>  cwr;
        bit<1>  ece;
        bit<1>  urg;
        bit<1>  ack;
        bit<1>  psh;
        bit<1>  rst;
        bit<1>  syn;
        bit<1>  fin;
        bit<16> window;
        bit<16> checksum;
        bit<16> urgentPtr;
     
    }
     
    header udp_t{
        bit<16> srcPort;
        bit<16> dstPort;
        bit<16> length_;
        bit<16> checksum;
        }
     
    struct header_t {
        timestamp_t timestamp;
        ethernet_t   ethernet;
        ipv4_t       ipv4;
        tcp_t        tcp;
        udp_t        udp;
     
    }
     
    header new_header_h {
        bit<32> sip_out;
        bit<32> dip_out;
        bit<16> sp_out;
        bit<16> dp_out;
        bit<8> prot;
        bit<8> pkts;
        bit<8> syn_out;
        bit<8> psh_out;
        bit<8> ack_out;
        bit<16> fwd_len;
        bit<16> flow_len;
        bit<16> fwindow;
        bit<32> flow_dur;
        bit<32> act_min;
        bit<32> flow_inter;
        bit<32> act_mean;
        bit<8> act_segs;
        bit<32> currTime;
    }
     
     
     
    struct metadata_t {
        /* empty */
        ip4Addr_t srcAddr;
        ip4Addr_t dstAddr;
        ip4Addr_t ip1;
        ip4Addr_t ip2;
        bit<16> id;
        bit<16> flowlet_register_index;
        bit<16>  ipcache_index;
        bit<16> srcPort;
        bit<16> dstPort;
        bit<16> port1;
        bit<16> port2;
        bit<32> out_act1;
        bit<32> last_time;
        bit<32> inactive_duration;
        bit<32> active_start;
        bit<32> active_duration;
        bit<32> val;
        bool isForward;
        bit<32> diff1;
        bit<32> diff2;
        bool reset;
        bool mal_flow;
        //Current Feature Values
        new_header_h new_head;
     
    }
     
     
    
 
    struct pair2{
        bit<16> first;
        bit<16> second;
    }
     
     
    struct empty_header_t {}
     
    struct empty_metadata_t {}
     
     
    /*************************************************************************
    *********************** P A R S E R  ***********************************
    *************************************************************************/
     
     
    // ---------------------------------------------------------------------------
    // Ingress parser
    // ---------------------------------------------------------------------------
     
    parser SwitchIngressParser(packet_in packet,
                    out header_t hdr,
                    out metadata_t meta,
                    out ingress_intrinsic_metadata_t ig_intr_md) {
     
        state start{
            packet.extract(ig_intr_md);
            packet.advance(PORT_METADATA_SIZE);
            meta.flowlet_register_index = 0;
            meta.reset = false;
            meta.mal_flow = true;
            transition timestamp;
        }
     
        state timestamp {
            packet.extract(hdr.timestamp);
            transition ethernet;
        }
     
        state ethernet {
     
            packet.extract(hdr.ethernet);
     
            transition select(hdr.ethernet.etherType){
     
                TYPE_IPV4: ipv4;                                   
                default: accept;
            }
     
            
        }
     
        state ipv4 {
            packet.extract(hdr.ipv4);
     
            transition select(hdr.ipv4.protocol){
                TYPE_TCP: tcp;
                TYPE_UDP: udp;
                default: accept;
            }
        }
     
     
        state tcp {
           packet.extract(hdr.tcp);
           transition accept;
        }
        
     
        state udp {
        packet.extract(hdr.udp);
        transition accept;
        }
    }
     
     
     
     
    // ---------------------------------------------------------------------------
    // Ingress Deparser
    // ---------------------------------------------------------------------------
    control SwitchIngressDeparser(
            packet_out pkt,
            inout header_t hdr,
            in metadata_t meta,
            in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
     
       
        apply {
           
            pkt.emit(hdr.ethernet);
            pkt.emit(hdr.ipv4);
            pkt.emit(meta.new_head);
        }
    }
     
     
    /*************************************************************************
    **************  I N G R E S S   P R O C E S S I N G   *******************
    *************************************************************************/
     
    //Currently only ipv4
     
    control SwitchIngress(inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
    {
        Hash<bit<16>>(HashAlgorithm_t.CRC16) sym_hash;
        Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;
        Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_id;
     
        action mark_benign()
        {
            meta.mal_flow = false;
        }
     
                Register<pair, bit<16>>(REGISTER_LENGTH, {8w0,8w0}) flow_cache;
     
                RegisterAction<pair, bit<16>, bool>(flow_cache) flow_cache_register_action0 = {
                    void apply(inout pair flag, out bool isFwd) {
                        if(flag.first == 8w0)
                        {
                            if(flag.second == 8w0)
                            {
                                flag.first = 8w1;
                                isFwd = true;
                            }
                            else
                            {
                                isFwd = false;
                            }
                        }
                        else
                        isFwd = true;
                    }
                };
     
                RegisterAction<pair, bit<16>, bool>(flow_cache) flow_cache_register_action1 = {
                    void apply(inout pair flag, out bool isFwd) {
                        if(flag.second == 8w0)
                        {
                            if(flag.first == 8w0)
                            {
                                flag.second = 8w1;
                                isFwd = true;
                            }
                            else
                            {
                                isFwd = false;
                            }
                        }
                        else
                        isFwd = true;
                    }
                };
     
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) collision_check;
     
                //Check for collisions
                RegisterAction<bit<16>, bit<16>, bool>(collision_check) collision_check_action = {
                    void apply(inout bit<16> key, out bool collision) {
                            if(meta.id != key)
                                collision = true;
                            else
                                collision = false;
                            key = meta.id;
                    }
                };
     
                Register<bit<8>, _>(REGISTER_LENGTH, 0) mal_flows;
     
                RegisterAction<bit<8>, _,bool>(mal_flows) mal_flows_action1 = {
                    void apply(inout bit<8> mali, out bool ou) {
                        if(mali == 1)
                            ou = true;
                        else
                            ou = false;
                    }
                };
     
                RegisterAction<bit<8>, _,bool>(mal_flows) mal_flows_action2 = {
                    void apply(inout bit<8> mali) {
                                mali = 1;
                    }
                };
 
                RegisterAction<bit<8>, _,bool>(mal_flows) mal_flows_action3 = {
                    void apply(inout bit<8> mali) {
                                mali = 0;
                    }
                };
     
                Register<bit<8>, bit<16>>(REGISTER_LENGTH, 0) pkt_count;
     
                //Update packet count
                RegisterAction<bit<8>, bit<16>, bit<8>>(pkt_count) pkt_count_action = {
                    void apply(inout bit<8> n_pkts, out bit<8> curr_pkts) {
                            bit<8> temp = n_pkts;
                            if(meta.reset){
                                n_pkts = 1;
                                
                            }
                            else{
                                n_pkts = n_pkts + 1;
                                temp = n_pkts;
                            }
                            curr_pkts = temp;
                    }
                };
     
                Register<bit<8>, bit<16>>(REGISTER_LENGTH, 0) protocols;
     
                RegisterAction<bit<8>, bit<16>, bit<8>>(protocols) protocols_register_action_ipv4 = {
                    void apply(inout bit<8> proto, out bit<8> protoc) {
                        bit<8> temp = proto;
                        protoc = temp;
                        proto = hdr.ipv4.protocol;
                    }
                };
     
                Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) src_ip;
     
                RegisterAction<bit<32>, bit<16>, bit<32>>(src_ip) src_ip_register_action_ipv4 = {
                    void apply(inout bit<32> sip, out bit<32> sipout) {
                        sipout = sip;
                        sip = meta.srcAddr;
                    }
                };
     
              
                Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) dst_ip;
     
                RegisterAction<bit<32>, bit<16>, bit<32>>(dst_ip) dst_ip_register_action_ipv4 = {
                    void apply(inout bit<32> dip, out bit<32> dipout) {
                        dipout = dip;
                        dip = meta.dstAddr;
                    }
                };
     
                
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) src_port;
     
                RegisterAction<bit<16>, bit<16>, bit<16>>(src_port) src_port_register_action = {
                    void apply(inout bit<16> sport, out bit<16> spout) {
                        spout = sport;
                        sport = meta.srcPort;
                    }
                };
     
     
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) dst_port;
     
                RegisterAction<bit<16>, bit<16>, bit<16>>(dst_port) dst_port_register_action = {
                    void apply(inout bit<16> dport, out bit<16> dpout) {
                        dpout = dport;
                        dport = meta.dstPort;
                    }
                };
     
                 Register<bit<8>, _>(REGISTER_LENGTH, 0) syn_counter;
     
                RegisterAction<bit<8>, _, bit<8>>(syn_counter) syn_counter_register_action = {
                    void apply(inout bit<8> scounter, out bit<8> synout) {
                        synout = scounter;
                        if(meta.reset)
                        scounter = 1;
                        else
                        scounter = scounter + 1;
                        
                    }
                };
     
                Register<bit<8>, _>(REGISTER_LENGTH, 0) psh_counter;
     
                RegisterAction<bit<8>, _, bit<8>>(psh_counter) psh_counter_register_action = {
                    void apply(inout bit<8> pcounter, out bit<8> pshout) {
                        pshout = pcounter;
                        if(meta.reset)
                        pcounter = 1;
                        else
                        pcounter = pcounter + 1;
                        
                    }
                };
               
                Register<bit<8>, _>(REGISTER_LENGTH, 0) ack_counter;
     
                RegisterAction<bit<8>, _, bit<8>>(ack_counter) ack_counter_register_action = {
                    void apply(inout bit<8> acounter, out bit<8> ackout) {
                        ackout = acounter;
                        if(meta.reset)
                        acounter = 1;
                        else
                        acounter = acounter + 1;
                        
                    }
                };
     
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) flow_total_length;
     
                RegisterAction<bit<16>, bit<16>, bit<16>>(flow_total_length) flow_total_length_register_action_ipv4 = {
                    void apply(inout bit<16> ftl, out bit<16> ftlo) {
                        ftlo = ftl;
                        if(meta.reset)
                        ftl = hdr.ipv4.totalLen;
                        else
                        ftl = ftl + hdr.ipv4.totalLen;
                    }
                };
     
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) forward_total_length;
     
                RegisterAction<bit<16>, bit<16>, bit<16>>(forward_total_length) forward_total_length_register_action_ipv4 = {
                    void apply(inout bit<16> fwtl, out bit<16> fwtlo) {
                                fwtlo = fwtl;
                                if(meta.reset)
                                fwtl = hdr.ipv4.totalLen;
                                else
                                fwtl = fwtl + hdr.ipv4.totalLen;
                                
                        }
                    };
     
                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) fw_win_byt;
     
                RegisterAction<bit<16>, bit<16>, bit<16>>(fw_win_byt) fw_win_byt_register_action = {
                    void apply(inout bit<16> fwin, out bit<16> fwino) {
                        fwino = fwin;
                        
                        if (fwin == 0) {
                                fwin = hdr.tcp.window;
                        }	
                        
                    }
                };
     
                //msbs
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) flow_start_time_stamp;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(flow_start_time_stamp) flow_start_time_stamp_register_action = {
            void apply(inout bit<32> fst, out bit<32> flts) {
                if(fst == 0) {
                        @in_hash{fst = hdr.timestamp.ts;}
                }
                flts = hdr.timestamp.ts - fst;	
            }
        };
     
        //msbs of last time stamp
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) last_time_stamp;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(last_time_stamp) last_time_stamp_register_action = {
            void apply(inout bit<32> lts, out bit<32> ltd) {
                bit<32> temp;
                if(lts == 0) {
                        lts = hdr.timestamp.ts;
                        temp = lts;
                        ltd = temp;
                }
                else{
                temp = lts;
                ltd = temp;
                lts = hdr.timestamp.ts;
                }
            }
        };
     
        //msbs of active start time stamp
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) active_start_time_stamp;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(active_start_time_stamp) active_start_time_stamp_register_action = {
            void apply(inout bit<32> ast, out bit<32> alts) {
                bit<32> temp;
                if(ast == 0) {
                        @in_hash{ast = hdr.timestamp.ts;}
                        temp = ast;
                        alts = temp;	
                }
                else if(meta.reset)
                {
                    temp = ast;
                    alts = temp;
                    ast = hdr.timestamp.ts;
     
                }
                else
                {
                    temp = ast;
                    alts = temp;
                }
            }
        };
     
     
        //msbs of flow duration
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) flow_duration;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(flow_duration) flow_duration_register_action = {
            void apply(inout bit<32> fd1, out bit<32> fdo) {
                fdo = fd1;
                @in_hash{fd1 = meta.val;}
            }
        };
     
        //msbs
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) active_min;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(active_min) active_min_register_action = {
            void apply(inout bit<32> am, out bit<32> amo) {
                if(meta.reset){
                if(am == 0)
                {            
                    am = meta.active_duration;
                }
                    else
                    {
                        am = min(am, meta.active_duration);
                    }
                }
                amo = am;
            }
        };
     
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) flow_inter_time;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(flow_inter_time) flow_inter_time_register_action = {
            void apply(inout bit<32> fit, out bit<32> fito) {
                if(meta.reset){
                    if(fit == 0)
                    {
                        fit = meta.inactive_duration;
                    }
                    else 
                    {
                        fit = min(fit, meta.inactive_duration);
                    }
                }
                fito = fit;
                }
        };
     
        // active mean
        Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) active_mean;
     
        RegisterAction<bit<32>, bit<16>, bit<32>>(active_mean) active_mean_register_action = {
            void apply(inout bit<32> am, out bit<32> amo) {
                    if(meta.reset){
                    if(am == 0)
                    {
                        am = meta.active_duration;
                    }
                    else 
                    {
                        am = am + meta.active_duration;
                    }
                    }
                    amo = am;
                }
        };
     
        // Active segments
        Register<bit<8>, _>(REGISTER_LENGTH, 0) active_segs;
     
        RegisterAction<bit<8>, _, bit<8>>(active_segs) active_segs_register_action = {
            void apply(inout bit<8> as, out bit<8> aso) {
                if(meta.reset)
                {
                    as = as + 1;
                }
                aso = as;
            }
        };
     
        table feature_distribution1 {
            key = {
                meta.new_head.pkts : range;
                meta.new_head.syn_out : range;
                meta.new_head.psh_out : range;
                meta.new_head.ack_out : range;
                meta.new_head.act_segs: range;
     
            }
            actions = {
                mark_benign; NoAction;
            }
            size = 1;
            const entries = {
                   (4 ..   10, 2 ..   5,  3 ..   7, 3 ..   7, 3 ..   7): NoAction();
            }
            default_action = mark_benign();
                }
     
         table feature_distribution2 {
            key = {
               
                meta.new_head.flow_len: range;
                meta.new_head.fwindow: range;
                meta.new_head.fwd_len: range;
                meta.new_head.flow_dur[31:16]: range;
                meta.new_head.act_min[31:16]: range;
                meta.new_head.flow_inter[31:16]: range;
                meta.new_head.act_mean[31:16]: range;
     
            }
            actions = {
                mark_benign; NoAction;
            }
            size = 1;
            const entries = {
                   (4 ..   10, 2 ..   5,  3 ..   7, 3 ..   7,  3 ..   7,  3 ..   7,  3 ..   7): NoAction();
            }
            default_action = mark_benign();
                }
     
     
        
        action compute_diff1()
        {
            meta.diff1 = IDLE_TIMEOUT - meta.inactive_duration;
        }
     
        action compute_diff2()
        {
            meta.diff2 = ACTIVE_TIMEOUT - meta.active_duration;
        }
     
        action send(PortId_t port) {
            ig_tm_md.ucast_egress_port = port;
        }
     
     
        action drop()
        {
            ig_dprsr_md.drop_ctl = 1;
        }
     
        action recirculate (bit<7> recirc_port) {
    ig_tm_md.ucast_egress_port [8:7] = ig_intr_md.ingress_port[8:7]; ig_tm_md.ucast_egress_port [6:0] = recirc_port;
    }
     
       
        apply
                {
                        if(hdr.ipv4.isValid())
                        {
                            meta.ip1 = min(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
                            meta.ip2 = max(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
                        }
                        else
                        {
                            meta.ip1 = 0;
                            meta.ip2 = 0;
                        }
     
                        if(hdr.tcp.isValid())
                        {
                            meta.port1 = min(hdr.tcp.srcPort, hdr.tcp.dstPort);
                            meta.port2 = max(hdr.tcp.srcPort, hdr.tcp.dstPort);
                        }
     
                        else if(hdr.udp.isValid())
                        {
                            meta.port1 = min(hdr.udp.srcPort, hdr.udp.dstPort);
                            meta.port2 = max(hdr.udp.srcPort, hdr.udp.dstPort);
                        }
                        else
                        {
                            meta.port1 = 0;
                            meta.port2 = 0;
                        }
     
                        meta.ipcache_index = sym_hash.get({meta.ip1, meta.ip2});
                        if(meta.ip1 == hdr.ipv4.srcAddr)
                            meta.isForward = flow_cache_register_action0.execute(meta.ipcache_index);
                        else
                            meta.isForward = flow_cache_register_action1.execute(meta.ipcache_index);
    		            // // end-of-flow direction	
     
     
                        // find the register index for this flow
                        if (meta.isForward) {
                                meta.srcAddr = hdr.ipv4.srcAddr;
                                meta.dstAddr = hdr.ipv4.dstAddr;
                                if(hdr.tcp.isValid()){
                                meta.srcPort = hdr.tcp.srcPort;
                                meta.dstPort = hdr.tcp.dstPort;
                                }
                                else if(hdr.udp.isValid()){
                                meta.srcPort = hdr.udp.srcPort;
                                meta.dstPort = hdr.udp.dstPort;
                                }
                                else
                                {
                                    meta.srcPort = 0;
                                    meta.dstPort = 0;
                                }
     
                        } else {
                                meta.srcAddr = hdr.ipv4.dstAddr;
                                meta.dstAddr = hdr.ipv4.srcAddr;
                                if(hdr.tcp.isValid()){
                                meta.srcPort = hdr.tcp.dstPort;
                                meta.dstPort = hdr.tcp.srcPort;
                                }
                                else if(hdr.udp.isValid()){
                                meta.srcPort = hdr.udp.dstPort;
                                meta.dstPort = hdr.udp.srcPort;
                                }
                                else
                                {
                                    meta.srcPort = 0;
                                    meta.dstPort = 0;
                                }
                        }
     
                        if(hdr.ipv4.isValid())
                        meta.flowlet_register_index = (bit<16>)hash_1.get({meta.ip1, meta.ip2, meta.port1, meta.port2, hdr.ipv4.protocol});
                        else
                        meta.flowlet_register_index = 0;
     
                        //Recirculation
                        if(ig_tm_md.ucast_egress_port == 68)
                            mal_flows_action2.execute(meta.flowlet_register_index);
                        else
                        {
     
     
                        //msbs
                        // meta.out_act1 = flow_start_time_stamp_register_action.execute(meta.flowlet_register_index);
                        
                        meta.val = flow_start_time_stamp_register_action.execute(meta.flowlet_register_index);
                        
                        meta.last_time = last_time_stamp_register_action.execute(meta.flowlet_register_index);
                        
                        meta.inactive_duration = hdr.timestamp.ts - meta.last_time;
     
                        meta.active_start = active_start_time_stamp_register_action.execute(meta.flowlet_register_index);
     
                        meta.active_duration = meta.last_time - meta.active_start;
     
                        compute_diff1();
                        compute_diff2();
     
                        meta.id = (bit<16>)hash_id.get({meta.ip1, meta.ip2, meta.port1, meta.port2, hdr.ipv4.protocol});
                        
                        bool collision = collision_check_action.execute(meta.flowlet_register_index);
     
                         if(!collision){
                         if(meta.diff1[31:31] == 1 || meta.diff2[31:31] == 1 || (hdr.tcp.isValid() && (hdr.tcp.rst == 1 || hdr.tcp.fin == 1))){
                            meta.reset = true;
                            mal_flows_action3.execute(meta.flowlet_register_index);}
                        
     
                        meta.new_head.pkts = pkt_count_action.execute(meta.flowlet_register_index);
     
                        if(meta.new_head.pkts == 0 )
                            meta.reset = false;
     
                        meta.new_head.prot = protocols_register_action_ipv4.execute(meta.flowlet_register_index);
                        meta.new_head.sip_out = src_ip_register_action_ipv4.execute(meta.flowlet_register_index);
                        meta.new_head.dip_out = dst_ip_register_action_ipv4.execute(meta.flowlet_register_index);
                        
     
                        meta.new_head.sp_out = src_port_register_action.execute(meta.flowlet_register_index);
                        meta.new_head.dp_out = dst_port_register_action.execute(meta.flowlet_register_index);
                        meta.new_head.flow_len = flow_total_length_register_action_ipv4.execute(meta.flowlet_register_index);
     
                        meta.new_head.syn_out = 0;            
                        meta.new_head.psh_out = 0;
                        meta.new_head.ack_out = 0;
                        meta.new_head.fwindow = 0;
                        meta.new_head.fwd_len = 0;
     
                        if(hdr.tcp.isValid())
                        {
                            if(hdr.tcp.syn == 1)
                            {
                                meta.new_head.syn_out = syn_counter_register_action.execute(meta.flowlet_register_index);
                            }
                            if(hdr.tcp.psh == 1)
                            {
                                meta.new_head.psh_out = psh_counter_register_action.execute(meta.flowlet_register_index);
                            }
                            if(hdr.tcp.ack == 1)
                            {
                                meta.new_head.ack_out = ack_counter_register_action.execute(meta.flowlet_register_index);
                            }
                            if(meta.isForward)
                            {
                                meta.new_head.fwindow = fw_win_byt_register_action.execute(meta.flowlet_register_index);
                            }
     
     
                        }
                         if(meta.isForward)
                        {
                            meta.new_head.fwd_len = forward_total_length_register_action_ipv4.execute(meta.flowlet_register_index);
                        }	
     
            meta.new_head.flow_dur = flow_duration_register_action.execute(meta.flowlet_register_index);
            
            meta.new_head.act_min = active_min_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.flow_inter = flow_inter_time_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.act_mean = active_mean_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.act_segs = active_segs_register_action.execute(meta.flowlet_register_index);
     
            feature_distribution1.apply();
            feature_distribution2.apply();
     
            if(meta.mal_flow)
                recirculate(68);
     
                         }
        else
        {
            bool mal = mal_flows_action1.execute(meta.flowlet_register_index);
            if(!mal)
            {
                meta.reset = true;
                meta.new_head.pkts = pkt_count_action.execute(meta.flowlet_register_index);
                meta.new_head.prot = protocols_register_action_ipv4.execute(meta.flowlet_register_index);
                meta.new_head.sip_out = src_ip_register_action_ipv4.execute(meta.flowlet_register_index);
                meta.new_head.dip_out = dst_ip_register_action_ipv4.execute(meta.flowlet_register_index);
                
     
                meta.new_head.sp_out = src_port_register_action.execute(meta.flowlet_register_index);
                meta.new_head.dp_out = dst_port_register_action.execute(meta.flowlet_register_index);
                meta.new_head.flow_len = flow_total_length_register_action_ipv4.execute(meta.flowlet_register_index);
     
                
                meta.new_head.syn_out = syn_counter_register_action.execute(meta.flowlet_register_index);
            
                meta.new_head.psh_out = psh_counter_register_action.execute(meta.flowlet_register_index);
            
                meta.new_head.ack_out = ack_counter_register_action.execute(meta.flowlet_register_index);
            
                meta.new_head.fwindow = fw_win_byt_register_action.execute(meta.flowlet_register_index);
                    
     
     
                        
                         
            meta.new_head.fwd_len = forward_total_length_register_action_ipv4.execute(meta.flowlet_register_index);
     
            meta.new_head.flow_dur = flow_duration_register_action.execute(meta.flowlet_register_index);
            
            meta.new_head.act_min = active_min_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.flow_inter = flow_inter_time_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.act_mean = active_mean_register_action.execute(meta.flowlet_register_index);
     
            meta.new_head.act_segs = active_segs_register_action.execute(meta.flowlet_register_index);
     
            
            }
        }
     
        meta.new_head.currTime = hdr.timestamp.ts;
     
        if(meta.reset)
                send(164);
            else
                drop();
     
     
            }
                }
    }
     
     
                              
     
    /*************************************************************************
    ****************  E G R E S S   P R O C E S S I N G   *******************
    *************************************************************************/
     
    parser EmptyEgressParser(
            packet_in pkt,
            out empty_header_t hdr,
            out empty_metadata_t eg_md,
            out egress_intrinsic_metadata_t eg_intr_md) {
        state start {
            pkt.extract(eg_intr_md);
            transition accept;
        }
    }
     
    control EmptyEgressDeparser(
            packet_out pkt,
            inout empty_header_t hdr,
            in empty_metadata_t eg_md,
            in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
        apply {
            pkt.emit(hdr);
        }
    }
     
    control EmptyEgress(
            inout empty_header_t hdr,
            inout empty_metadata_t eg_md,
            in egress_intrinsic_metadata_t eg_intr_md,
            in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
            inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
            inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        apply {
        }
    }
     
     
    /*************************************************************************
    ***********************  S W I T C H  *******************************
    *************************************************************************/
     
    //switch architecture
    Pipeline(SwitchIngressParser(),
             SwitchIngress(),
             SwitchIngressDeparser(),
             EmptyEgressParser(),
             EmptyEgress(),
             EmptyEgressDeparser()) pipe;
     
    Switch(pipe) main;
     
