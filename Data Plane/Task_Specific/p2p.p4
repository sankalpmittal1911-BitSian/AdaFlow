    /* -*- P4_16 -*- */
    #include <core.p4>
    // #if __TARGET_TOFINO__ == 2
    //#include<t2na.p4>
    // #else
    #include<tna.p4>
    // #endif
    // #include "/home/tofino/Open-Tofino/p4-examples/p4_16_programs/common/util.p4"
         
        /* CONSTANTS */
         
        const bit<16> TYPE_IPV4 = 0x800;
        const bit<8>  TYPE_TCP  = 6;
        const bit<8>  TYPE_UDP  = 17;
         
        #define REGISTER_LENGTH 65536
        #define IDLE_TIMEOUT 15000
        #define ACTIVE_TIMEOUT 120000
        #define RECIRC_PORT 68
        #define EGG_PORT 164
         
        /*************************************************************************
        *********************** H E A D E R S  ***********************************
        *************************************************************************/
         
        typedef bit<9>  egressSpec_t;
        typedef bit<32> ip4Addr_t;
         
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
            bit<8> class;
            bit<32> ipd_min;
        }
         
         
         
        struct metadata_t {
            /* empty */
            // 5-Tuple + Flow ID
            ip4Addr_t srcAddr;
            ip4Addr_t dstAddr;
            bit<16> id;
            bit<16> flowlet_register_index;
            bit<16> srcPort;
            bit<16> dstPort;
            bit<8> proto;
            //Last Time, First Time, BinFeats
            bit<32> last_time;
            bit<32> inactive_duration;
            bit<32> start_time;
            bit<32> active_duration;
            bit<16> pkts;
            bit<32> diff1;
            bit<32> diff2;
            bit<16> flow_size;
            bit<32> ipd_max;
            bit<16> size_min;
            bit<16> size_max;
            bit<16> size_avg;
            bit<8> shift;
            bool reset;
            //Class and Prioritize
            bit<8> type;
            bool prioritize;
            bit<8> class;
            //Packet Features
             bit<16> tcp_window;
             bit<4> tcp_dataoffset;
            bit<16> ip_len;
            bit<16> udp_len;
             bit<8> ip_ttl;
            bit<8> ip_diff;
            //Current Feature Values
            new_header_h new_head;
         
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
                meta.srcAddr = hdr.ipv4.srcAddr;
                meta.dstAddr = hdr.ipv4.dstAddr;
                meta.proto = hdr.ipv4.protocol;
                meta.ip_len = hdr.ipv4.totalLen;
                meta.ip_ttl = hdr.ipv4.ttl;
                meta.ip_diff = hdr.ipv4.tos;
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
            @symmetric("meta.srcAddr", "meta.dstAddr")
            @symmetric("meta.src_port", "meta.dst_port")
     
            Hash<bit<16>>(HashAlgorithm_t.CRC16) sym_hash;
            Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_1;
            Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_id;
         
                    Register<bit<16>, _>(REGISTER_LENGTH, 0) collision_check;
         
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
         
                    Register<bit<8>, _>(REGISTER_LENGTH, 0) prioritize_flows;
         
                    RegisterAction<bit<8>, _,bool>(prioritize_flows) prioritize_flows_action1 = {
                        void apply(inout bit<8> priori, out bool ou) {
                            bit<8> temp = priori;
                            if(temp == 1)
                            ou = true;
                            else
                            ou = false;
                            priori = 0;
                        }
                    };
         
                    RegisterAction<bit<8>, _,bool>(prioritize_flows) prioritize_flows_action2 = {
                        void apply(inout bit<8> priori) {
                                    priori = 1;
                        }
                    };
     
                    RegisterAction<bit<8>, _,bool>(prioritize_flows) prioritize_flows_action3 = {
                        void apply(inout bit<8> priori) {
                                    priori = 0;
                        }
                    };
     
         
         
                    //msbs
            Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) flow_start_time_stamp;
         
            RegisterAction<bit<32>, bit<16>, bit<32>>(flow_start_time_stamp) flow_start_time_stamp_register_action = {
                void apply(inout bit<32> fst, out bit<32> flts) {
                    if(fst == 0) {
                            @in_hash{fst = hdr.timestamp.ts;}
                    }
                    flts = fst;	
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
     
            Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) pkt_count;
     
                //Update packet count
                RegisterAction<bit<16>, bit<16>, bit<16>>(pkt_count) pkt_count_action = {
                    void apply(inout bit<16> n_pkts, out bit<16> curr_pkts) {
                            bit<16> temp = n_pkts;
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


                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) flow_length;
     
                //Update packet count
                RegisterAction<bit<16>, bit<16>, bit<16>>(flow_length) flow_length_action = {
                    void apply(inout bit<16> n_pkts, out bit<16> curr_pkts) {
                            bit<16> temp = n_pkts;
                            if(meta.reset){
                                n_pkts = meta.ip_len;
                                
                            }
                            else{
                                n_pkts = n_pkts + meta.ip_len;
                                temp = n_pkts;
                            }
                            curr_pkts = temp;
                    }
                };

                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) min_flow_length;
     
                //Update packet count
                RegisterAction<bit<16>, bit<16>, bit<16>>(min_flow_length) min_flow_length_action = {
                    void apply(inout bit<16> n_pkts, out bit<16> curr_pkts) {
                            bit<16> temp = n_pkts;
                            if(meta.reset){
                                n_pkts = meta.ip_len;
                                
                            }
                            else{
                                n_pkts = min(n_pkts, meta.ip_len);
                                temp = n_pkts;
                            }
                            curr_pkts = temp;
                    }
                };

                Register<bit<16>, bit<16>>(REGISTER_LENGTH, 0) max_flow_length;
     
                //Update packet count
                RegisterAction<bit<16>, bit<16>, bit<16>>(max_flow_length) max_flow_length_action = {
                    void apply(inout bit<16> n_pkts, out bit<16> curr_pkts) {
                            bit<16> temp = n_pkts;
                            if(meta.reset){
                                n_pkts = meta.ip_len;
                                
                            }
                            else{
                                n_pkts = max(n_pkts, meta.ip_len);
                                temp = n_pkts;
                            }
                            curr_pkts = temp;
                    }
                };

                Register<bit<32>, bit<16>>(REGISTER_LENGTH, 0) ipd_max;
            RegisterAction<bit<32>, bit<16>, bit<32>>(ipd_max) ipd_max_register_action_update = {
                void apply(inout bit<32> ipd, out bit<32> ipd_out) {
                    bit<32> temp = meta.inactive_duration;
                    bit<32> temp2 = ipd;
                    if(meta.reset)
                    {
     
                        ipd = 0;
                    }
                    else{
                    if(temp > ipd)
                        ipd = temp;
     
                }
     
                 ipd_out = temp2;
                }
            };


                action bit_shift(bit<8> shift)
                {
                    meta.shift = shift;
                }

            table shift_bit {
                key = {
                    // meta.flow_size : range;
                    meta.pkts: range;
         
                }
                actions = {
                    bit_shift; NoAction;
                }
                size = 64;
               
                default_action = NoAction();
                    }
     
            
            action mark_flow1(bool priority, bit<8> class)
            {
                meta.prioritize = priority;
                meta.type = class;
            }
     
            action mark_flow2(bit<8> class)
            {
                meta.type = class;
            }
         
            table agg_model {
                key = {
                    meta.size_avg : range;
                    meta.size_max : range;
                    meta.size_min : range;
                    meta.ipd_max[31:16] : range;
         
                }
                actions = {
                    mark_flow1; NoAction;
                }
                size = 256;
               
                default_action = NoAction();
                    }
     
            table pkt_model {
                key = {
                    meta.proto: range;
                    meta.tcp_window: range;
            meta.tcp_dataoffset: range;
            meta.ip_len: range;
            meta.udp_len: range;
            meta.ip_ttl: range;
            meta.ip_diff: range;
                }
                
                actions = {
                    mark_flow2; NoAction;
                }
                size = 256;
               
                default_action = NoAction();
                    }
         
         Register<bit<8>, _>(REGISTER_LENGTH, 0) classify_flows;
         
                    RegisterAction<bit<8>, _,bit<8>>(classify_flows) classify_flows_action = {
                        void apply(inout bit<8> class, out bit<8> ou) {
                            bit<8> temp = class;
                            if(meta.reset)
                            class = 0;
                            else
                            class = meta.type;
                            ou = temp;
                        }
                    };
     
            
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
                            meta.flowlet_register_index = (bit<16>)hash_1.get({meta.srcAddr, meta.dstAddr, meta.srcPort, meta.dstPort, meta.proto});
                            else
                            meta.flowlet_register_index = 0;
                            if(hdr.tcp.isValid())
                            {
                                meta.srcPort = hdr.tcp.srcPort;
               meta.dstPort = hdr.tcp.dstPort;
               meta.tcp_dataoffset = hdr.tcp.dataOffset;
                meta.tcp_window = hdr.tcp.window;
                            }
                            else if(hdr.udp.isValid())
                            {
meta.srcPort = hdr.tcp.srcPort;
            meta.dstPort = hdr.tcp.dstPort;
            meta.udp_len = hdr.udp.length_;
                            }
                            //Recirculation, set the priority of the flow
                            if(ig_tm_md.ucast_egress_port == RECIRC_PORT)
                                prioritize_flows_action2.execute(meta.flowlet_register_index);
                            else
                            {
                            
                            // meta.start_time = flow_start_time_stamp_register_action.execute(meta.flowlet_register_index);
                            
                            meta.last_time = last_time_stamp_register_action.execute(meta.flowlet_register_index);
                            
                            meta.inactive_duration = hdr.timestamp.ts - meta.last_time;
         
                            // meta.active_duration = meta.last_time - meta.start_time;
         
                            compute_diff1();
                            compute_diff2();
         
                            meta.id = (bit<16>)hash_id.get({meta.srcAddr, meta.dstAddr, meta.srcPort, meta.dstPort, meta.proto});
                            
                            //Check if there is collision
                            bool collision = collision_check_action.execute(meta.flowlet_register_index);
         
                             if(!collision){
                             if(meta.diff1[31:31] == 1 || (hdr.tcp.isValid() && (hdr.tcp.rst == 1 || hdr.tcp.fin == 1))){
                                meta.reset = true;
                                //Reset Priority
                                prioritize_flows_action3.execute(meta.flowlet_register_index);}
                            
                            //Get Bin Features
                            meta.pkts = pkt_count_action.execute(meta.flowlet_register_index);
                            meta.flow_size = flow_length_action.execute(meta.flowlet_register_index);
                            meta.size_min = min_flow_length_action.execute(meta.flowlet_register_index);
                            meta.size_max = max_flow_length_action.execute(meta.flowlet_register_index);
                            meta.ipd_max = ipd_max_register_action_update.execute(meta.flowlet_register_index);
                            shift_bit.apply();

                            if(meta.shift == 2)
                            meta.size_avg = meta.flow_size >> 2;
                            else if(meta.shift == 3)
                            meta.size_avg = meta.flow_size >> 3;
                            else if(meta.shift == 6)
                            meta.size_avg = meta.flow_size >> 6;
                            else if(meta.shift == 9)
                            meta.size_avg = meta.flow_size >> 9;
                            else if(meta.shift ==  12)
                            meta.size_avg = meta.flow_size >> 12;
         
                agg_model.apply();
                meta.class = classify_flows_action.execute(meta.flowlet_register_index);
                if(meta.prioritize)
                    recirculate(RECIRC_PORT);
         
                             }
            else
            {
                bool prior = prioritize_flows_action1.execute(meta.flowlet_register_index);
                if(!prior)
                {
                    meta.reset = true;
                    meta.pkts = pkt_count_action.execute(meta.flowlet_register_index);
                            meta.flow_size = flow_length_action.execute(meta.flowlet_register_index);
                            meta.size_min = min_flow_length_action.execute(meta.flowlet_register_index);
                            meta.size_max = max_flow_length_action.execute(meta.flowlet_register_index);
                            meta.ipd_max = ipd_max_register_action_update.execute(meta.flowlet_register_index);
                            // shift_bit.apply();
                            // bit<16> x = (bit<16>)meta.shift;
                            // meta.size_avg = meta.flow_size << x;
                    meta.class = classify_flows_action.execute(meta.flowlet_register_index);
         
                
                }
                else
                {
                    //Classify using Packet Model
                    pkt_model.apply();
                    meta.class = classify_flows_action.execute(meta.flowlet_register_index);
     
                }
            }
         
            meta.new_head.sip_out = meta.srcAddr;
            meta.new_head.dip_out = meta.dstAddr;
            meta.new_head.sp_out = meta.srcPort;
            meta.new_head.dp_out = meta.dstPort;
            meta.new_head.prot = meta.proto;
            // meta.new_head.ipd_min = meta.ipd_min;
            meta.new_head.class = meta.class;
         
            if(meta.reset)
                    send(EGG_PORT);
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
         
