#include <core.p4>
#include <pna.p4>
#include <idpf.p4>
#include "protocols.p4"
#include "parsed_hdrs.p4"
#include "metadata.p4"
#include "proto_ids.p4"
#include "fxp_ptypes.p4"

@intel_config("domain_id", 0)
#include "fxp_parser_hints.p4"
#include "k8s_dp_hints.p4"

minipkg_config() minicfg;

#include "parser.p4"

#define IS_IPV4 (hdrs.ipv4[0].isValid())
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

control k8s_dp_control(inout parsed_headers_t hdrs,
               inout user_metadata_t user_meta,
               inout vendor_meta_t meta,
               out user_rx_host_metadata_t user_rx_host_meta,
               in user_tx_host_metadata_t user_tx_host_meta,
               in pna_main_input_metadata_t istd,
               inout pna_main_output_metadata_t ostd)

{

    action drop() {
        drop_packet();
    }

    action send(PortId_t port){
        send_to_port(port);
    }

    table comms_channel_table {
        key = {
            meta.common.vsi : exact;
            user_meta.cmeta.flex16 : exact;
        }

        actions = {
            send;
            drop;
        }
    }

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

    action update_src_dst_mac(bit<48> new_dmac) {
        hdrs.mac[meta.common.depth].sa = hdrs.mac[meta.common.depth].da;
        hdrs.mac[meta.common.depth].da = new_dmac;
    }

    table pod_gateway_mac_mod_table {
        key = { meta.common.mod_blob_ptr : exact; }
        actions = { update_src_dst_mac; }
        size = 1024;
    }

    apply {
        if (meta.common.vsig == 1) {
            /*
            * ACC-IMC connectivity channel
            * Using vsi as a match bidirection table
            * on prof-id=1, vsig=1
            */
            comms_channel_table.apply();
        } 
        // ARP Request: Unicast the packet since the port corresponding to
        // to that tpa is known
        // Target Protocol Address in ARP Request is known via CNI Add.
        // This table also handles ARP Replies
        else if (hdrs.arp.isValid() && meta.common.depth==0) {
            arp_to_port_table.apply();
        }

        /*
         * Simple L3 forwarding with mac update - TX direction
         */
        else if (TxPkt(istd) && IS_IPV4 && meta.common.depth==0) {
            /*
             * Forward either to local vport or externally.
             */
            ipv4_to_port_table_tx.apply();
        }

        /*
         * Simple L3 forwarding - RX direction
         * Avoid MAC update in RX as it is already done in TX
         */
        else if (RxPkt(istd) && IS_IPV4 && meta.common.depth==0) {
            /*
             * Forward either to local vport
             */
            ipv4_to_port_table_rx.apply();
        }

        switch(meta.common.mod_action) {
            POD_GATEWAY_MAC_MOD : { pod_gateway_mac_mod_table.apply(); }
        }
    }
}

control MainDeparserImpl(
      packet_out pkt,
      in    parsed_headers_t  main_hdr,
      in    user_metadata_t main_user_meta,
      in    pna_main_output_metadata_t ostd) {
    apply{}
}

PNA_NIC(main_parser = Parser(),
        main_control = k8s_dp_control(),
        main_deparser = MainDeparserImpl()) main;
