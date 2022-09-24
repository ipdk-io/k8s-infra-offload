/**********************************************************
* Copyright(c) 2018 - 2021 Intel Corporation
*
* For licensing information, see the file ▒~@~XLICENSE▒~@~Y in the root folder
***********************************************************/

/* -*- P4_16 -*- */

#include <core.p4>
#include <pna.p4>

/**************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IP_PROTO_TCP   = 0x06;

typedef bit<8> ActCommit_t;
typedef bit<16> ActionRef_t;
typedef bit<24> ModDataPtr_t;
typedef bit<8> Atr_t;

const ActionRef_t WRITE_SRC_IP = (ActionRef_t) 1;
const ActionRef_t WRITE_DEST_IP = (ActionRef_t) 2;
const ActionRef_t NO_MODIFY =  (ActionRef_t) 0;

const ExpireTimeProfileId_t EXPIRE_TIME_CT = (ExpireTimeProfileId_t) 2;

const PortId_t DEFAULT_HOST_PORT = (PortId_t) 0;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header ethernet_t {
    bit<48> dst_mac;
    bit<48> src_mac;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> ether_type;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    bit<48> sha;
    bit<32> spa;
    bit<48> tha;
    bit<32> tpa;
}

header ipv4_t {
    bit<8> version_ihl;
    bit<8> dscp_ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> header_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit <8> data_offset_res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct hash_data_t {
    bit<32> h_addr;
    bit<16> h_port;
}

struct headers_t {
    ethernet_t ethernet;
    vlan_tag_h vlan_tag;
    ipv4_t ipv4;
    tcp_t tcp;
    arp_t arp;
}

struct clb_pinned_flows_hit_params_t {
    PortId_t p;
    ModDataPtr_t ptr;
};

struct main_metadata_t {
   PortId_t dst_port;
   bit<8> clb_hash;
   ActionRef_t mod_action;
   ModDataPtr_t mod_blob_ptr;
   ActCommit_t act_commit;
   PNA_Direction_t direction;
}

#define ARP_REQUEST     1
#define AS_NUM_MEMBERS  128
#define AS_OP_BITS      10

#define IS_IPV4_TCP (hdr.ipv4.isValid() && hdr.tcp.isValid())

extern void recirculate();

bool RxPkt (in main_metadata_t meta) {
    return (meta.direction == PNA_Direction_t.NET_TO_HOST);
}

bool TxPkt (in main_metadata_t meta) {
    return (meta.direction == PNA_Direction_t.HOST_TO_NET);
}

bool TCP_SYN_flag_set(in bit<8> flags) {
    return (flags[1:1] == 1);
}

control  pre_control(
    in    headers_t  hdr,
    inout main_metadata_t meta,
    in    pna_pre_input_metadata_t  istd,
    inout pna_pre_output_metadata_t ostd)
{
    apply {
    }
}

parser packet_parser(
    packet_in pkt,
    out   headers_t       hdr,
    inout main_metadata_t main_meta,
    in    pna_main_parser_input_metadata_t istd)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_TPID:  parse_vlan_tag;
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP:   parse_arp;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_ARP:   parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP:   parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
}

control k8s_dp_control(
    inout headers_t  hdr,
    inout main_metadata_t meta,
    in    pna_main_input_metadata_t  istd,
    inout pna_main_output_metadata_t ostd)
{
    bool do_clb_pinned_flows_add_on_miss = false;
    bool add_succeeded = false;
    InternetChecksum() ck;
    InternetChecksum() ck1;
    ExpireTimeProfileId_t new_expire_time_profile_id;

    action update_src_ip_mac(bit<48> new_smac, bit<32> new_ip) {
        ck.clear();
        ck1.clear();
        ck.subtract(hdr.ipv4.header_checksum);
        ck1.subtract(hdr.tcp.checksum);
        hdr.ipv4.header_checksum = ck.get();
        ck.subtract(hdr.ipv4.src_addr);
        ck1.subtract(hdr.ipv4.src_addr);

        hdr.ethernet.src_mac = new_smac;
        hdr.ipv4.src_addr = new_ip;

        ck.add(hdr.ipv4.src_addr);
        ck1.add(hdr.ipv4.src_addr);
        hdr.ipv4.header_checksum = ck.get();
        hdr.tcp.checksum = ck1.get();
    }

    /* SNAT table for Pod IP -> Service IP translation. Along with IP address,
     * the IP checksum and SMAC is also updated. */
    table write_source_ip_table {
        key = { meta.mod_blob_ptr : exact; }
        actions = { update_src_ip_mac; }
        size = 2048;
    }

    action set_source_ip (bit<24> ptr) {
        meta.mod_action = (ActionRef_t) WRITE_SRC_IP;
        meta.mod_blob_ptr = (ModDataPtr_t) ptr;
    }

    /* Table to enable SNAT for pod IP address */
    table rx_src_ip  {
        key = {
            hdr.ipv4.src_addr : exact;
        }
        actions = {
            set_source_ip;
            NoAction;
        }
        const default_action = NoAction();
    }

    action set_dest_vport(PortId_t p) {
        send_to_port(p);
    }

    action my_drop() {
        drop_packet();
    }

    /* The Target IP based forwarding table. Used only for ARP Request
     * broadcast packets */
    table ipv4_to_port_table {
        key = {
            hdr.arp.tpa : lpm;
        }

        actions = {
            set_dest_vport;
        }

        const default_action = set_dest_vport(DEFAULT_HOST_PORT);
    }

    /* The DMAC based forwarding table. Used for all traffic except ARP
     * request broadcasts */
    table mac_to_port_table {
        key = {
            hdr.ethernet.dst_mac : exact;
        }

        actions = {
            set_dest_vport;
        }

        const default_action = set_dest_vport(DEFAULT_HOST_PORT);
    }

    action update_dst_ip_mac(bit<48> new_dmac, bit<32> new_ip) {
        ck.clear();
        ck1.clear();
        ck.subtract(hdr.ipv4.header_checksum);
        ck1.subtract(hdr.tcp.checksum);
        ck.subtract(hdr.ipv4.dst_addr);
        ck1.subtract(hdr.ipv4.dst_addr);

        hdr.ipv4.dst_addr = new_ip;
        hdr.ethernet.dst_mac = new_dmac;

        ck.add(hdr.ipv4.dst_addr);
        ck1.add(hdr.ipv4.dst_addr);
        hdr.ipv4.header_checksum = ck.get();
        hdr.tcp.checksum = ck1.get();
    }

    /* DNAT table for Service IP -> Pod IP translation. Along with IP address,
     * the IP checksum and DMAC is also updated. */
    table write_dest_ip_table {
        key = { meta.mod_blob_ptr : exact; }
        actions = { update_dst_ip_mac; }
        size = 1024;
    }

    action pinned_flows_hit(PortId_t p,
                            ModDataPtr_t ptr) {
        meta.dst_port = p;
        meta.mod_action = WRITE_DEST_IP;
        meta.mod_blob_ptr = ptr;
    }

    action pinned_flows_miss() {
        if (do_clb_pinned_flows_add_on_miss) {
            new_expire_time_profile_id = EXPIRE_TIME_CT;
            add_succeeded =
                add_entry(action_name = "pinned_flows_hit",
                    action_params = (clb_pinned_flows_hit_params_t) {
                        p = meta.dst_port,
                        ptr = meta.mod_blob_ptr
                    },
                    expire_time_profile_id = new_expire_time_profile_id);
        }
    }

    /* The table which dynamically learns action, if not already present.
     * If present, the learnt action is applied */
    table pinned_flows {
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            hdr.ipv4.protocol : exact;
            hdr.tcp.src_port : exact;
            hdr.tcp.dst_port : exact;
        }
        actions = {
            @tableonly   pinned_flows_hit;
            @defaultonly pinned_flows_miss;
        }
        add_on_miss = true;
        const default_action = pinned_flows_miss;
    }

    action set_default_lb_dest (PortId_t p, bit<24> ptr) {
        meta.dst_port = p; // Not used
        meta.mod_action = (ActionRef_t) WRITE_DEST_IP;
        meta.mod_blob_ptr = ptr;
    }

    /* The table for load balancing of initial TCP SYN packet. The action
     * from this table is learnt by the next pinned_flows table and then,
     * applied to all subsequent TCP packets belonging to that flow */
    ActionSelector(PNA_HashAlgorithm_t.TARGET_DEFAULT,
                   AS_NUM_MEMBERS, AS_OP_BITS) as_sl3;
    table tx_balance {
        key = {
            hdr.ipv4.dst_addr : exact;
            hdr.tcp.dst_port : exact;
            hdr.ipv4.src_addr : selector;
            hdr.tcp.src_port : selector;
        }
        actions = {
            set_default_lb_dest;
            NoAction;
        }
        pna_implementation = as_sl3;
        const default_action = NoAction();
    }

    /* Host is the client node running Kube-Proxy.
     * The service node is in remote network */
    action set_direction_by_port (bit<8> direction)
    {
        if (direction == 0)
            meta.direction = PNA_Direction_t.NET_TO_HOST;
        else
            meta.direction = PNA_Direction_t.HOST_TO_NET;
    }

    table direction_table {
        key = {
            istd.input_port : exact;
        }
        actions = {
            set_direction_by_port;
            NoAction;
        }
        const default_action = NoAction();
    }

    apply {
        meta.mod_action = 0;
        meta.mod_blob_ptr = 0;
        direction_table.apply();

        /* If this is Kube-Proxy Rx in client node, then enable SNAT. */
        if (RxPkt(meta) && IS_IPV4_TCP)
        {
            rx_src_ip.apply();
        }
        else if (IS_IPV4_TCP) /* else perform load-balancing and enable DNAT */
        {
            if (TCP_SYN_flag_set(hdr.tcp.flags))
            {
                tx_balance.apply();
                do_clb_pinned_flows_add_on_miss = true;
                pinned_flows.apply();
            }
            else
            {
                do_clb_pinned_flows_add_on_miss = false;
                pinned_flows.apply();
            }
        }

        /* Perform the SNAT or DNAT if enabled by above TCP processing */
        switch (meta.mod_action) {
            WRITE_SRC_IP: {
                write_source_ip_table.apply();
            }

            WRITE_DEST_IP: {
                write_dest_ip_table.apply();
            }

            default: {
            }
        }

        /* The brodcast ARP Request pkts are forwarded based upon target IP
         * address. Rest all are forwarded based upon DMAC */
        if (hdr.arp.isValid() && hdr.arp.oper == ARP_REQUEST) {
            ipv4_to_port_table.apply();
        } else if (hdr.ethernet.isValid()) {
            mac_to_port_table.apply();
        }
    }
}

control packet_deparser(
    packet_out pkt,
    in    headers_t hdr,                // from main control
    in    main_metadata_t user_meta,    // from main control
    in    pna_main_output_metadata_t ost)
{
    apply {
        pkt.emit(hdr);
    }
}

// BEGIN:Package_Instantiation_Example

PNA_NIC(
    packet_parser(),
    pre_control(),
    k8s_dp_control(),
    packet_deparser()
    ) main;
