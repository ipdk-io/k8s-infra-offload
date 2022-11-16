/**********************************************************
* Copyright(c) 2018 - 2021 Intel Corporation
*
* For licensing information, see the file ▒~@~XLICENSE▒~@~Y in the root folder
***********************************************************/

/* -*- P4_16 -*- */

#include <core.p4>
#include <pna.p4>

/**************************************************************************
 ************* C O N S T A N T S   A N D   T Y P E S  *******************
**************************************************************************/

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IP_PROTO_TCP   = 0x06;
const bit<8> IP_PROTO_UDP = 0x11;

typedef bit<16> ActionRef_t;
typedef bit<24> ModDataPtr_t;

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

header udp_t {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> length;
	bit<16> checksum;
}

struct headers_t {
	ethernet_t ethernet;
	vlan_tag_h vlan_tag;
	ipv4_t ipv4;
	tcp_t tcp;
	udp_t udp;
	arp_t arp;
}

struct clb_pinned_flows_hit_params_t {
	ModDataPtr_t ptr;
};

struct clb_pinned_flows_reverse_hit_params_t {
	ModDataPtr_t ptr;
};

struct main_metadata_t {
	bit<16> dst_port;
	bit<16> src_port;
	bit<32> src_ip;
	bit<32> dst_ip;
	bit<8> clb_hash;
	ActionRef_t mod_action;
	ModDataPtr_t mod_blob_ptr_dnat;
	ModDataPtr_t mod_blob_ptr_snat;
}

#define ARP_REQUEST	 1
#define AS_NUM_MEMBERS  128
#define AS_OP_BITS	  10

#define IS_IPV4_TCP (hdr.ipv4.protocol == IP_PROTO_TCP)
#define IS_IPV4_UDP (hdr.ipv4.protocol == IP_PROTO_UDP)

bool tcp_syn_flag_set(in bit<8> flags) {
	bool flag = (flags == 0x02);
	return flag;
}

void save_to_meta_tcp (inout headers_t hdr, inout main_metadata_t meta) {
	meta.src_ip = hdr.ipv4.src_addr;
	meta.dst_ip = hdr.ipv4.dst_addr;
	meta.src_port = hdr.tcp.src_port;
	meta.dst_port = hdr.tcp.dst_port;
}

void save_to_meta_udp (inout headers_t hdr, inout main_metadata_t meta) {
	meta.src_ip = hdr.ipv4.src_addr;
	meta.dst_ip = hdr.ipv4.dst_addr;
	meta.src_port = hdr.udp.src_port;
	meta.dst_port = hdr.udp.dst_port;
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
	out       headers_t hdr,
	inout     main_metadata_t main_meta,
	in	  pna_main_parser_input_metadata_t istd)
{
	state start {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ETHERTYPE_TPID:  parse_vlan_tag;
			ETHERTYPE_IPV4:  parse_ipv4;
			ETHERTYPE_ARP :  parse_arp;
			default       :  accept;
		}
	}

	state parse_vlan_tag {
		pkt.extract(hdr.vlan_tag);
		transition select(hdr.vlan_tag.ether_type) {
			ETHERTYPE_IPV4:  parse_ipv4;
			ETHERTYPE_ARP :  parse_arp;
			default       :  accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTO_TCP:   parse_tcp;
			IP_PROTO_UDP:   parse_udp;
			default     :   accept;
		}
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
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
	bool create_reverse_ct = false;
	bool add_succeeded = false;
	InternetChecksum() ck;
	InternetChecksum() ck1;
	ExpireTimeProfileId_t new_expire_time_profile_id;

	action update_src_ip_mac(bit<48> new_smac, bit<32> new_ip, bit<16> new_port) {
		ck.clear();
		ck1.clear();
		ck.subtract(hdr.ipv4.header_checksum);
		hdr.ipv4.header_checksum = ck.get();
		ck.subtract(hdr.ipv4.src_addr);
		if (IS_IPV4_TCP) { 
			ck1.subtract(hdr.tcp.checksum);
			ck1.subtract(hdr.ipv4.src_addr);
			ck1.subtract(hdr.tcp.src_port);
			hdr.tcp.src_port = new_port;
		} else {
			if (IS_IPV4_UDP) {
				ck1.subtract(hdr.udp.checksum);
				ck1.subtract(hdr.ipv4.src_addr);
				ck1.subtract(hdr.udp.src_port);
				hdr.udp.src_port = new_port;
			}
		}

		hdr.ethernet.src_mac = new_smac;
		hdr.ipv4.src_addr = new_ip;

		ck.add(hdr.ipv4.src_addr);
		hdr.ipv4.header_checksum = ck.get();
		if (IS_IPV4_TCP) {
			ck1.add(hdr.ipv4.src_addr);
			ck1.add(hdr.tcp.src_port);
			hdr.tcp.checksum = ck1.get();
		} else {
			if (IS_IPV4_UDP) {
				ck1.add(hdr.ipv4.src_addr);
				ck1.add(hdr.udp.src_port);
				hdr.udp.checksum = ck1.get();
			}
		}
	}

	/* SNAT table for Pod IP -> Service IP translation. Along with IP address,
	 * the IP checksum and SMAC is also updated. */
	table write_source_ip_table {
		key = { meta.mod_blob_ptr_snat : exact; }
		actions = { update_src_ip_mac; }
		size = 2048;
	}

	action set_dest_mac_vport(PortId_t p, bit<48> new_dmac) {
		/* Replace DMAC if supplied and if needed */
		if ((new_dmac != (bit<48>) 0) && (new_dmac != hdr.ethernet.dst_mac)) {
			hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
			hdr.ethernet.dst_mac = new_dmac;
		}
		send_to_port(p);
    }

	action set_dest_vport(PortId_t p) {
		send_to_port(p);
	}

	action my_drop() {
		drop_packet();
	}

	/* The Target IP based forwarding table. Used only for ARP Request
	 * broadcast packets */
	table arpt_to_port_table {
		key = {
			hdr.arp.tpa : exact;
		}

		actions = {
			set_dest_vport;
		}

		const default_action = set_dest_vport(DEFAULT_HOST_PORT);
	}

	/* The destination IP based forwarding table. Used for all IP packets */
	table ipv4_to_port_table {
		key = {
			hdr.ipv4.dst_addr : exact;
		}

		actions = {
			set_dest_mac_vport;
		}

		const default_action = set_dest_mac_vport(DEFAULT_HOST_PORT, 0);
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

	action update_dst_ip_mac(bit<48> new_dmac, bit<32> new_ip, bit<16> new_port) {
		ck.clear();
		ck1.clear();
		ck.subtract(hdr.ipv4.header_checksum);
		ck.subtract(hdr.ipv4.dst_addr);
		if (IS_IPV4_TCP) {
			ck1.subtract(hdr.tcp.checksum);
			ck1.subtract(hdr.ipv4.dst_addr);
			ck1.subtract(hdr.tcp.dst_port);
			hdr.tcp.dst_port = new_port;
		} else {
			if (IS_IPV4_UDP) {
				ck1.subtract(hdr.udp.checksum);
				ck1.subtract(hdr.ipv4.dst_addr);
				ck1.subtract(hdr.udp.dst_port);
				hdr.udp.dst_port = new_port;
			}
		}

		hdr.ipv4.dst_addr = new_ip;
		hdr.ethernet.dst_mac = new_dmac;

		ck.add(hdr.ipv4.dst_addr);
		hdr.ipv4.header_checksum = ck.get();
		if (IS_IPV4_TCP) {
			ck1.add(hdr.ipv4.dst_addr);
			ck1.add(hdr.tcp.dst_port);
			hdr.tcp.checksum = ck1.get();
		} else {
			if (IS_IPV4_UDP) {
				ck1.add(hdr.ipv4.dst_addr);
				ck1.add(hdr.udp.dst_port);
				hdr.udp.checksum = ck1.get();
			}
		}
	}

	/* DNAT table for Service IP -> Pod IP translation. Along with IP address,
	 * the IP checksum and DMAC is also updated. */
	table write_dest_ip_table {
		key = { meta.mod_blob_ptr_dnat : exact; }
		actions = { update_dst_ip_mac; }
		size = 1024;
	}

	action pinned_flows_hit (ModDataPtr_t ptr) {
		meta.mod_action = WRITE_DEST_IP;
		meta.mod_blob_ptr_dnat = ptr;
	}

	action pinned_flows_miss() {
		if (do_clb_pinned_flows_add_on_miss && meta.mod_blob_ptr_dnat != 0) {            
			new_expire_time_profile_id = EXPIRE_TIME_CT;
			add_succeeded =
				add_entry(action_name = "pinned_flows_hit",
				action_params = (clb_pinned_flows_hit_params_t) {
					ptr = meta.mod_blob_ptr_dnat
				},
				expire_time_profile_id = new_expire_time_profile_id);
		}
	}

	/* The table which dynamically learns action, if not already present.
	 * If present, the learnt action is applied */
	table pinned_flows {
		key = {
			meta.src_ip : exact;
			meta.dst_ip : exact;
			hdr.ipv4.protocol : exact;
			meta.src_port : exact;
			meta.dst_port : exact;
		}
		actions = {
			@tableonly   pinned_flows_hit;
			@defaultonly pinned_flows_miss;
		}
		add_on_miss = true;
		const default_action = pinned_flows_miss;
	}

	action pinned_flows_reverse_hit (ModDataPtr_t ptr) {
		meta.mod_action = WRITE_SRC_IP;
		meta.mod_blob_ptr_snat = ptr;
	}

	action pinned_flows_reverse_miss() {
		if (create_reverse_ct && meta.mod_blob_ptr_snat != 0) {
			new_expire_time_profile_id = EXPIRE_TIME_CT;
			add_succeeded =
				add_entry(action_name = "pinned_flows_reverse_hit",
				action_params = (clb_pinned_flows_reverse_hit_params_t) {
					ptr = meta.mod_blob_ptr_snat
				},
				expire_time_profile_id = new_expire_time_profile_id);
		}
	}

	table pinned_flows_reverse {
		key = {
			meta.src_ip : exact;
			meta.dst_ip : exact;
			hdr.ipv4.protocol : exact;
			meta.src_port : exact;
			meta.dst_port : exact;
		}
		actions = {
			@tableonly pinned_flows_reverse_hit;
			@defaultonly pinned_flows_reverse_miss;
		}
		add_on_miss = true;
		const default_action = pinned_flows_reverse_miss;
	}

	action set_default_lb_dest (bit<24> ptr) {
		meta.mod_action = (ActionRef_t) WRITE_DEST_IP;
		meta.mod_blob_ptr_dnat = ptr;
	}

	/* The table for load balancing of initial TCP SYN packet. The action
	 * from this table is learnt by the next pinned_flows table and then,
	 * applied to all subsequent TCP packets belonging to that flow */
	ActionSelector(PNA_HashAlgorithm_t.TARGET_DEFAULT,
		           AS_NUM_MEMBERS, AS_OP_BITS) as_sl3_tcp;
	ActionSelector(PNA_HashAlgorithm_t.TARGET_DEFAULT,
		           AS_NUM_MEMBERS, AS_OP_BITS) as_sl3_udp;

	table tx_balance_tcp {
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
		pna_implementation = as_sl3_tcp;
		const default_action = NoAction();
	}

	table tx_balance_udp {
		key = {
	        hdr.ipv4.dst_addr : exact;
	        hdr.udp.dst_port : exact;
	        hdr.ipv4.src_addr : selector;
	        hdr.udp.src_port : selector;
		}
		actions = {
	        set_default_lb_dest;
	        NoAction;
		}
		pna_implementation = as_sl3_udp;
		const default_action = NoAction();
	}

	action set_key_for_reverse_ct (bit <24> ptr) {
		meta.src_ip = hdr.ipv4.dst_addr;
		meta.dst_ip = hdr.ipv4.src_addr;
		if (IS_IPV4_TCP) {
			meta.src_port = hdr.tcp.dst_port;
			meta.dst_port = hdr.tcp.src_port;
		} else {
			if (IS_IPV4_UDP) {
				meta.src_port = hdr.udp.dst_port;
				meta.dst_port = hdr.udp.src_port;
			}
		}
		meta.mod_blob_ptr_snat = ptr;
	}

	table set_meta_tcp {
		key = {
			hdr.ipv4.dst_addr : exact;
			hdr.tcp.dst_port : exact;
		}
		actions = {
			set_key_for_reverse_ct;
			NoAction;
		}
		const default_action = NoAction();
	}

	table set_meta_udp {
		key = {
			hdr.ipv4.dst_addr : exact;
		    hdr.udp.dst_port : exact;
		}
		actions = {
		    set_key_for_reverse_ct;
			NoAction;
		}
		const default_action = NoAction();
	}
	

	apply {
		meta.mod_action = 0;
		meta.mod_blob_ptr_dnat = 0;
		meta.mod_blob_ptr_snat = 0;
		meta.src_ip = 0;
		meta.dst_ip = 0;
		meta.src_port = 0;
		meta.dst_port = 0;
		do_clb_pinned_flows_add_on_miss = false;
		create_reverse_ct = false;

		if (IS_IPV4_TCP) {
			if (tcp_syn_flag_set(hdr.tcp.flags)) {
				if (tx_balance_tcp.apply().hit) {
					do_clb_pinned_flows_add_on_miss = true;
					create_reverse_ct = true;
					save_to_meta_tcp(hdr, meta);
					pinned_flows.apply();
				}
			} else {
				save_to_meta_tcp(hdr, meta);
				if (pinned_flows_reverse.apply().miss) {
					pinned_flows.apply();
				}
			}
		} else {
			if (IS_IPV4_UDP) {
				if (tx_balance_udp.apply().hit) {
					create_reverse_ct = true;
					do_clb_pinned_flows_add_on_miss = true;
					save_to_meta_udp(hdr, meta);
					pinned_flows.apply();
				} else {
					save_to_meta_udp(hdr, meta);
					pinned_flows_reverse.apply();
				}
			}
		}	

		/* Perform the SNAT or DNAT if enabled by above TCP processing */
		switch (meta.mod_action) {
			WRITE_SRC_IP: {
				write_source_ip_table.apply();
			}

			WRITE_DEST_IP: {
				write_dest_ip_table.apply();
				if (create_reverse_ct) {
					if (IS_IPV4_TCP) {
						set_meta_tcp.apply();
					} else {
						if (IS_IPV4_UDP) {
							set_meta_udp.apply();
						}
					}
					pinned_flows_reverse.apply();		
				}
			}

		    default: {
		    }
		}

		/* The brodcast ARP Request pkts are forwarded based upon target IP
		* address. All IP packets are forwarded based upon DIP and all
		* non-IP packets are forwarded based upon DMAC */
		if (hdr.arp.isValid() && hdr.arp.oper == ARP_REQUEST) {
			arpt_to_port_table.apply();
		} else if (hdr.ipv4.isValid()) {
			ipv4_to_port_table.apply();
		} else {
			mac_to_port_table.apply();
		}
	}
}

control packet_deparser(
	packet_out pkt,
	in	   headers_t hdr,                // from main control
	in	   main_metadata_t user_meta,    // from main control
	in	   pna_main_output_metadata_t ostd)
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
