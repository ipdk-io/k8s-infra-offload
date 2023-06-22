
#include <core.p4>
#include <pna.p4>
#include <idpf.p4>
#include "fxp_ptypes.p4"
#include "protocols.p4"
#include "parsed_hdrs.p4"
#include "proto_ids.p4"
#include "metadata.p4"

#define BUILD_DOMAIN 0
@intel_config("domain_id", BUILD_DOMAIN)
#include "fxp_parser_hints.p4"
#include "k8s_policy_hints.p4"

minipkg_config() minicfg;

#include "parser.p4"

#define RxPkt(istd) (istd.direction == PNA_Direction_t.NET_TO_HOST)
#define TxPkt(istd) (istd.direction == PNA_Direction_t.HOST_TO_NET)

#define pass_1st(istd) (istd.pass == 0)
#define pass_2nd(istd) (istd.pass == 1)

control PreControlImpl(
        in    parsed_headers_t hdr,
        inout user_metadata_t meta,
        in    pna_pre_input_metadata_t  istd,
        inout pna_pre_output_metadata_t ostd)
{
        apply { }
}

#define ALLOW_ALL    0              // When no ACL is enabled
#define DENY_ALL     1              // When ACL is enabled, but no rules configured
#define MATCH_RULE   2              // When ACL is enabled, and either only protocol+RC, 
                                    //    or protocol+RC+IPSet are configured
#define MATCH_IPSET  3              // When only IPSet is configured

const bit<6> ref_range_check_tcp_dport     = 11;
const bit<6> ref_range_check_udp_dport     = 12;
const bit<6> ref_range_check_sctp_dport    = 13;
const bit<6> ref_range_check_udplite_dport = 14;

const bit<8> dir_rx = 0;
const bit<8> dir_tx = 1;

control MainControlImpl(inout parsed_headers_t hdrs,
               inout user_metadata_t user_meta,
               inout vendor_meta_t meta,
               out user_rx_host_metadata_t user_rx_host_meta,
               in user_tx_host_metadata_t user_tx_host_meta,
               in pna_main_input_metadata_t istd,
               inout pna_main_output_metadata_t ostd) {

    action allow () {
        NoAction();   
    }

    action deny () {
        drop_packet();
    }

    action drop () {
        drop_packet();
    }

    action recirc_action () {
        recirculate();
    }

    /* 
     * =============
     * SEM
     * ==============
     */

    action set_dest_mac_vport(PortId_t p, bit<24> ptr) {
        send_to_port(p);
        meta.common.mod_action = (ActionRef_t) POD_GATEWAY_MAC_MOD;
        meta.common.mod_blob_ptr = ptr;
    }

    table ipv4_to_port_table_tx {
        key = {
            hdrs.ipv4[meta.common.depth].dst_ip : exact;
        }
        actions = {
            set_dest_mac_vport;
            drop;
        }
        // Don't know the default port right now
        const default_action = drop();
    }

    action set_dest_vport(PortId_t p) {
        send_to_port(p);
    }

    table ipv4_to_port_table_rx {
        key = {
            hdrs.ipv4[meta.common.depth].dst_ip : exact;
        }
        actions = {
            set_dest_vport;
            drop;
        }
        // Don't know the default port right now
        const default_action = drop();
    }

    table arp_to_port_table {
        key = {
            hdrs.arp.tpa : exact;
        }
        actions = {
            set_dest_vport;
            drop;
        }
        const default_action = drop();
    }

    // When ACL is not enabled for the pod - miss action
    action set_status_allow_all() {
        user_meta.gmeta.acl_status = ALLOW_ALL;
        recirculate();
    }

    // Use this action when ACL is enabled for the pod, but no rules are configured.
    // Also call this action when ACL is enabled and all rules are   
    // configured with protocol. If the second SEM table (acl_destip_proto_table/
    // acl_srcip_proto_table) has a match, then user_meta.gmeta.acl_status will be
    // overwritten with value LOOKUP_RULES. If the second SEM table does not
    // have a match, user_meta.gmeta.acl_status will be DENY_ALL, which is what we
    // expect, since the packet didn't match any configured protocols.
    action set_status_deny_all() {
        user_meta.gmeta.acl_status = DENY_ALL;
        recirculate();
    }

    // When ACL is enabled, and one or more rules are configured with ipset
    action set_status_match_ipset_only_ingress(bit<8> ipset_idx) {
        user_meta.gmeta.acl_status = MATCH_IPSET;
        user_meta.gmeta.tcam_key[7:0] = dir_rx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        recirculate();
    }

    // When ACL is enabled, and one or more rules are configured with ipset
    action set_status_match_ipset_only_egress(bit<8> ipset_idx) {
        user_meta.gmeta.acl_status = MATCH_IPSET;
        user_meta.gmeta.tcam_key[7:0] = dir_tx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        recirculate();
    }

    // SEM table 1, RX
    table acl_pod_ip_table_ingress {
        key = {
            hdrs.ipv4[meta.common.depth].dst_ip : exact;
        }	
        actions = {
            set_status_match_ipset_only_ingress;
            set_status_deny_all;
            set_status_allow_all;
            recirc_action;
        }
        const default_action = recirc_action();
    }

    // SEM table 1, TX
    table acl_pod_ip_table_egress {
        key = {
            hdrs.ipv4[meta.common.depth].src_ip : exact;
        }	
        actions = {
            set_status_match_ipset_only_egress;
            set_status_deny_all;
            set_status_allow_all;
            recirc_action;
        }
        const default_action = recirc_action();
    }
    
    // When range check and ipset check are configured in a rule
    action set_range_check_ref_tcp_ingress(bit<13> rng_idx, bit<8> ipset_idx) {
        // Expecting this action to override user_meta.gmeta.acl_status (originally
        // set by acl_destip_table/acl_srcip_table action). Action
        // by second SEM table should take precedence over first table.
        meta.common.range_check_ref = ref_range_check_tcp_dport;
        meta.common.range_idx = rng_idx;
        user_meta.gmeta.acl_status = MATCH_RULE;
        user_meta.gmeta.tcam_key[7:0] = dir_rx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        //recirculate();
    }

    action set_range_check_ref_udp_ingress(bit<13> rng_idx, bit<8> ipset_idx) {
        // Expecting this action to override user_meta.gmeta.acl_status (originally
        // set by acl_destip_table/acl_srcip_table action). Action
        // by second SEM table should take precedence over first table.
        meta.common.range_check_ref = ref_range_check_udp_dport;
        meta.common.range_idx = rng_idx;
        user_meta.gmeta.acl_status = MATCH_RULE;
        user_meta.gmeta.tcam_key[7:0] = dir_rx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        //recirculate();
    }

    action set_range_check_ref_tcp_egress(bit<13> rng_idx, bit<8> ipset_idx) {
        // Expecting this action to override user_meta.gmeta.acl_status (originally
        // set by acl_destip_table/acl_srcip_table action). Action
        // by second SEM table should take precedence over first table.
        meta.common.range_check_ref = ref_range_check_tcp_dport;
        meta.common.range_idx = rng_idx;
        user_meta.gmeta.acl_status = MATCH_RULE;
        user_meta.gmeta.tcam_key[7:0] = dir_tx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        //recirculate();
    }

    action set_range_check_ref_udp_egress(bit<13> rng_idx, bit<8> ipset_idx) {
        // Expecting this action to override user_meta.gmeta.acl_status (originally
        // set by acl_destip_table/acl_srcip_table action). Action
        // by second SEM table should take precedence over first table.
        meta.common.range_check_ref = ref_range_check_udp_dport;
        meta.common.range_idx = rng_idx;
        user_meta.gmeta.acl_status = MATCH_RULE;
        user_meta.gmeta.tcam_key[7:0] = dir_tx;
        user_meta.gmeta.tcam_key[15:8] = ipset_idx;
        //recirculate();
    }

    //SEM table 2, looked up in RX 
    table acl_pod_ip_proto_table_ingress {
        key = {
            hdrs.ipv4[meta.common.depth].dst_ip : exact;
            hdrs.ipv4[meta.common.depth].protocol : exact;
        }	
        actions = {
            set_range_check_ref_tcp_ingress;
            set_range_check_ref_udp_ingress;
            NoAction;
        }
        const default_action = NoAction;
    }


    // SEM table 2, looked up in TX 
    table acl_pod_ip_proto_table_egress {
        key = {
            hdrs.ipv4[meta.common.depth].src_ip : exact;
            hdrs.ipv4[meta.common.depth].protocol : exact;
        }
        actions = {
            set_range_check_ref_tcp_egress;
            set_range_check_ref_udp_egress;
            NoAction;
        }	
        const default_action = NoAction;
    }

    /* 
     * =============
     * RC
     * ==============
     */

    action do_range_check_tcp (
        bit<16> min0, bit<16> max0,
        bit<16> min1, bit<16> max1,
        bit<16> min2, bit<16> max2,
        bit<16> min3, bit<16> max3,
        bit<16> min4, bit<16> max4,
        bit<16> min5, bit<16> max5,
        bit<16> min6, bit<16> max6,
        bit<16> min7, bit<16> max7) {
        /* 
         * The ports the container can receive on and the ports it can send to,
         * are both dst_port
         */
        meta.fxp_internal.range_check_result[0:0] = (bit<1>)((min0 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max0));
        meta.fxp_internal.range_check_result[1:1] = (bit<1>)((min1 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max1));
        meta.fxp_internal.range_check_result[2:2] = (bit<1>)((min2 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max2));
        meta.fxp_internal.range_check_result[3:3] = (bit<1>)((min3 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max3));
        meta.fxp_internal.range_check_result[4:4] = (bit<1>)((min4 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max4));
        meta.fxp_internal.range_check_result[5:5] = (bit<1>)((min5 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max5));
        meta.fxp_internal.range_check_result[6:6] = (bit<1>)((min6 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max6));
        meta.fxp_internal.range_check_result[7:7] = (bit<1>)((min7 <= hdrs.tcp.dport) && (hdrs.tcp.dport <= max7));
    }

    action do_range_check_udp (
        bit<16> min0, bit<16> max0,
        bit<16> min1, bit<16> max1,
        bit<16> min2, bit<16> max2,
        bit<16> min3, bit<16> max3,
        bit<16> min4, bit<16> max4,
        bit<16> min5, bit<16> max5,
        bit<16> min6, bit<16> max6,
        bit<16> min7, bit<16> max7) {
        /* 
         * The ports the container can receive on and the ports it can send to,
         * are both dst_port
         */
        meta.fxp_internal.range_check_result[0:0] = (bit<1>)((min0 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max0));
        meta.fxp_internal.range_check_result[1:1] = (bit<1>)((min1 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max1));
        meta.fxp_internal.range_check_result[2:2] = (bit<1>)((min2 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max2));
        meta.fxp_internal.range_check_result[3:3] = (bit<1>)((min3 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max3));
        meta.fxp_internal.range_check_result[4:4] = (bit<1>)((min4 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max4));
        meta.fxp_internal.range_check_result[5:5] = (bit<1>)((min5 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max5));
        meta.fxp_internal.range_check_result[6:6] = (bit<1>)((min6 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max6));
        meta.fxp_internal.range_check_result[7:7] = (bit<1>)((min7 <= hdrs.udp[0].dport) && (hdrs.udp[0].dport <= max7));
    }

    // action do_range_check_udplite (
    // 	bit<16> min0, bit<16> max0,
    //     bit<16> min1, bit<16> max1,
    //     bit<16> min2, bit<16> max2,
    //     bit<16> min3, bit<16> max3,
    //     bit<16> min4, bit<16> max4,
    //     bit<16> min5, bit<16> max5,
    //     bit<16> min6, bit<16> max6,
    //     bit<16> min7, bit<16> max7) {
    // 	/* 
    // 	 * The ports the container can receive on and the ports it can send to,
    // 	 * are both dst_port
    // 	 */
    //     meta.fxp_internal.range_check_result[0:0] = (bit<1>)((min0 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max0));
    // 	meta.fxp_internal.range_check_result[1:1] = (bit<1>)((min1 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max1));
    //     meta.fxp_internal.range_check_result[2:2] = (bit<1>)((min2 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max2));
    //     meta.fxp_internal.range_check_result[3:3] = (bit<1>)((min3 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max3));
    // 	meta.fxp_internal.range_check_result[4:4] = (bit<1>)((min4 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max4));
    //     meta.fxp_internal.range_check_result[5:5] = (bit<1>)((min5 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max5));
    //     meta.fxp_internal.range_check_result[6:6] = (bit<1>)((min6 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max6));
    // 	meta.fxp_internal.range_check_result[7:7] = (bit<1>)((min7 <= hdrs.udplite.dport) && (hdrs.udplite.dport <= max7));
    // }

    // action do_range_check_sctp (
    // 	bit<16> min0, bit<16> max0,
    //     bit<16> min1, bit<16> max1,
    //     bit<16> min2, bit<16> max2,
    //     bit<16> min3, bit<16> max3,
    //     bit<16> min4, bit<16> max4,
    //     bit<16> min5, bit<16> max5,
    //     bit<16> min6, bit<16> max6,
    //     bit<16> min7, bit<16> max7) {
    // 	/* 
    // 	 * The ports the container can receive on and the ports it can send to,
    // 	 * are both dst_port
    // 	 */
    //     meta.fxp_internal.range_check_result[0:0] = (bit<1>)((min0 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max0));
    // 	meta.fxp_internal.range_check_result[1:1] = (bit<1>)((min1 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max1));
    //     meta.fxp_internal.range_check_result[2:2] = (bit<1>)((min2 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max2));
    //     meta.fxp_internal.range_check_result[3:3] = (bit<1>)((min3 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max3));
    // 	meta.fxp_internal.range_check_result[4:4] = (bit<1>)((min4 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max4));
    //     meta.fxp_internal.range_check_result[5:5] = (bit<1>)((min5 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max5));
    //     meta.fxp_internal.range_check_result[6:6] = (bit<1>)((min6 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max6));
    // 	meta.fxp_internal.range_check_result[7:7] = (bit<1>)((min7 <= hdrs.sctp.dport) && (hdrs.sctp.dport <= max7));
    // }


    // TODO: Add actions for other protocols

    // RC table, looked up in TX/RX - TCP
    table tcp_dport_rc_table {
        key = {
            meta.common.range_idx : exact;
        }
        actions = {
            do_range_check_tcp;
        }	
    }

    // RC table, looked up in TX/RX - UDP
    table udp_dport_rc_table {
        key = {
            meta.common.range_idx : exact;
        }
        actions = {
            do_range_check_udp;
        }	
    }

    // // RC table, looked up in TX/RX - UDP-Lite
    // table udplite_dport_rc_table {
    // 	key = {
    // 		meta.common.range_idx : exact;
    // 	}
    // 	actions = {
    // 		do_range_check_udplite;
    // 		NoAction;
    //     }	
    // 	const default_action = NoAction();
    // }

    // // RC table, looked up in TX/RX - SCTP
    // table sctp_dport_rc_table {
    // 	key = {
    // 		meta.common.range_idx : exact;
    // 	}
    // 	actions = {
    // 		do_range_check_sctp;
    // 		NoAction;
    //     }	
    // 	const default_action = NoAction();
    // }

    /* 
     * =============
     * LPM
     * ==============
     */

    @intel_lut_type("lpm_table")
    TernaryMatchLookupTable<bit<32>, bit<32>, _>(
        size = 2, // 1 const entries + default entry
        // const_entries = {
        //     {{lpm_lut_key_rx}, {(bit<32>) 1}},
        //     {{lpm_lut_key_tx}, {(bit<32>) 2}},
        // },
        // In this program we dont expect for any packet 
        // to miss this tcam lookup, but in general we
        // prefer to have a default root always
        default_value = 0
       ) acl_lpm_root_lut_ingress;

    @intel_lut_type("lpm_table")
    TernaryMatchLookupTable<bit<32>, bit<32>, _>(
        size = 2, // 1 const entries + default entry
        // const_entries = {
        //     {{lpm_lut_key_rx}, {(bit<32>) 1}},
        //     {{lpm_lut_key_tx}, {(bit<32>) 2}},
        // },
        // In this program we dont expect for any packet 
        // to miss this tcam lookup, but in general we
        // prefer to have a default root always
        default_value = 0
       ) acl_lpm_root_lut_egress;

    action set_ipset_match_result (bit<8> ipset_bitmap) {
        user_meta.gmeta.ipset_check_result = ipset_bitmap;
    }

    bit<32> ipset_table_lpm_root_egress;
    bit<32> ipset_table_lpm_root_ingress;

    // LPM Table RX
    table acl_ipset_match_table_ingress {
        key = {
            ipset_table_lpm_root_ingress : ternary;
            hdrs.ipv4[meta.common.depth].src_ip : lpm;
        }
        actions = {
            set_ipset_match_result;
        }
    }
   
    // LPM Table TX
    table acl_ipset_match_table_egress {
        key = {
            ipset_table_lpm_root_egress : ternary;
            hdrs.ipv4[meta.common.depth].dst_ip : lpm;
        }
        actions = {
            set_ipset_match_result;
        }
    }

    /* 
     * =============
     * WCM
     * ==============
     */

    // WCM Table - TX/RX - Pass 2
    table check_acl_result {
        key = {
            // ALLOW_ALL,    xxxxxxxx, xxxxxxxx : allow
            // DENY_ALL,     xxxxxxxx, xxxxxxxx : deny

            // LOOKUP_RULES, 1xxxxxxx, 1xxxxxxx : allow
            // LOOKUP_RULES, x1xxxxxx, x1xxxxxx : allow
            // LOOKUP_RULES, xx1xxxxx, xx1xxxxx : allow
            // LOOKUP_RULES, xxx1xxxx, xxx1xxxx : allow
            // LOOKUP_RULES, xxxx1xxx, xxxx1xxx : allow
            // LOOKUP_RULES, xxxxx1xx, xxxxx1xx : allow
            // LOOKUP_RULES, xxxxxx1x, xxxxxx1x : allow
            // LOOKUP_RULES, xxxxxxx1, xxxxxxx1 : allow
            // LOOKUP_RULES, xxxxxxxx, xxxxxxxx : deny      - Lower precedence

            // LOOKUP_IPSET, xxxxxxxx, 00000000 : deny      - Higher precedence
            // LOOKUP_IPSET, xxxxxxxx, xxxxxxxx : allow     - Lower precedence
            user_meta.gmeta.acl_status : exact;
            meta.fxp_internal.range_check_result : ternary;
            user_meta.gmeta.ipset_check_result : ternary;
        }
        actions = {
            allow;
            deny;
        }
        // // const entries
        // const entries = {
        //     (ALLOW_ALL,_,_): allow;
        //     (DENY_ALL,_,_): deny;
        //     (LOOKUP_RULES, 0x80 &&& 0x80, 0x80 &&& 0x80) : allow;
        //     (LOOKUP_RULES, 0x40 &&& 0x40, 0x40 &&& 0x40) : allow;
        //     (LOOKUP_RULES, 0x20 &&& 0x20, 0x20 &&& 0x20) : allow;
        //     (LOOKUP_RULES, 0x10 &&& 0x10, 0x10 &&& 0x10) : allow;
        //     (LOOKUP_RULES, 0x8 &&& 0x8, 0x8 &&& 0x8) : allow;
        //     (LOOKUP_RULES, 0x4 &&& 0x4, 0x4 &&& 0x4) : allow;
        //     (LOOKUP_RULES, 0x2 &&& 0x2, 0x2 &&& 0x2) : allow;
        //     (LOOKUP_RULES, 0x1 &&& 0x1, 0x1 &&& 0x1) : allow;
        //     (LOOKUP_RULES,_,_) : deny;  // Lower precedence
        //     (LOOKUP_IPSET,_,0x0 &&& 0xFF): deny;  // Higher precedence
        //     (LOOKUP_IPSET,_,_): allow; // Lower precedence
        // }
        // const default_action = allow;
    }

    /* 
     * =============
     * MOD
     * ==============
     */

    action update_src_dst_mac(bit<48> new_dmac) {
        hdrs.mac[meta.common.depth].sa = hdrs.mac[meta.common.depth].da;
        hdrs.mac[meta.common.depth].da = new_dmac;
    }

    table pod_gateway_mac_mod_table {
        key = { meta.common.mod_blob_ptr : exact; }
        actions = { update_src_dst_mac; }
        size = 1024;
    }

    // Simple ACL ingress and egress rules
    apply {
        /* SEM - 1st pass */

        // ARP Request: Unicast the packet since the port corresponding to
        // to that tpa is known
        // Target Protocol Address in ARP Request is known via CNI Add.
        // This table also handles ARP Replies
        if (hdrs.arp.isValid() && meta.common.depth==0) {
            arp_to_port_table.apply();
        }

        else if (RxPkt(istd) && pass_1st(istd) && hdrs.ipv4[0].isValid()) {
            // When both tables are taking the same action (e.g. set user_meta.gmeta.acl_status),
            // assumption is that the actions of second table take precedence 
            acl_pod_ip_table_ingress.apply();
            acl_pod_ip_proto_table_ingress.apply();     // pod to which the traffic is terminating, target of policy
        }

        else if (TxPkt(istd) && pass_1st(istd) && hdrs.ipv4[0].isValid()) {
            acl_pod_ip_table_egress.apply();
            acl_pod_ip_proto_table_egress.apply();     // pod from which the traffic is originating
        }
        
        /* Range Check - 1st pass */
        
        switch (meta.common.range_check_ref) {
            ref_range_check_tcp_dport: { tcp_dport_rc_table.apply(); }
            ref_range_check_udp_dport: { udp_dport_rc_table.apply(); }
            //ref_range_check_udplite_dport: { udplite_dport_rc_table.apply(); }
            //ref_range_check_sctp_dport: { sctp_dport_rc_table.apply(); }
        }
        
        /* LPM - 1st pass */

        if (RxPkt(istd) && pass_1st(istd) && hdrs.ipv4[0].isValid() && user_meta.gmeta.acl_status[1:1]==1
                && meta.common.depth==0 && meta.common.vsig == 2) { 
            ipset_table_lpm_root_ingress = acl_lpm_root_lut_ingress.lookup(user_meta.gmeta.tcam_key);
            acl_ipset_match_table_ingress.apply();
        }
        else if (TxPkt(istd) && pass_1st(istd) && hdrs.ipv4[0].isValid() && user_meta.gmeta.acl_status[1:1]==1
                && meta.common.depth==0 && meta.common.vsig == 2) {
            ipset_table_lpm_root_egress = acl_lpm_root_lut_egress.lookup(user_meta.gmeta.tcam_key);
            acl_ipset_match_table_egress.apply();
        }

        /* SEM - 2nd pass */

        if (TxPkt(istd) && pass_2nd(istd) && hdrs.ipv4[0].isValid() && meta.common.depth==0) {
            /*
            * Simple L3 forwarding with mac update - TX direction
            */
            ipv4_to_port_table_tx.apply();
        }
        else if (RxPkt(istd) && pass_2nd(istd) && hdrs.ipv4[0].isValid() && meta.common.depth==0) {
            /*
            * Simple L3 forwarding - RX direction
            * Avoid MAC update in RX as it is already done in TX
            */
            ipv4_to_port_table_rx.apply();
        }

        /* WCM - 2nd pass */
        
        if (pass_2nd(istd) && hdrs.ipv4[0].isValid() && meta.common.depth==0 && meta.common.vsig == 2) {
            check_acl_result.apply();
        }

        /* MOD - 2nd pass */
        switch(meta.common.mod_action) {
            POD_GATEWAY_MAC_MOD : { pod_gateway_mac_mod_table.apply(); }
        }
    }
}

control MainDeparserImpl(
    packet_out pkt,
    in	  parsed_headers_t  main_hdr,
    in	  user_metadata_t main_user_meta,
    in	  pna_main_output_metadata_t ostd) {

    apply{} 
}

PNA_NIC(main_parser = Parser(),
        main_control = MainControlImpl(),
        main_deparser = MainDeparserImpl()) main;
