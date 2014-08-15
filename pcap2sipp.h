/*
 * pcap2sipp     - tool for generating the sipp scenario, injection file and RTP packets 
 * that are needed to run a sipp test that simulates the behavior from a given pcap trace
 * Copyright (c) 2012 Catalina Oancea
 *
 * * * BEGIN LICENCE * * *
 *
 * This file is part of pcap2sipp
 *
 * pcap2sipp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * pcap2sipp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pcap2sipp.  If not, see <http://www.gnu.org/licenses/>.
 *
 * * * END LICENCE * * *
 *
 */

#ifndef PCAP2SIPP_H_
#define PCAP2SIPP_H_

#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include "nodes.h"
#include <net/ethernet.h>
#include <libnet/libnet-macros.h>

#define LINE_LEN 16
#define REQUEST  1
#define REPLY    0
#define INITIATOR  1
#define REPLIER    0
#define SIP_IDENTIFYER "sip"
#define ETHERNET_LEN 14
#define LINUX_COOKED_LEN 16

/* Ethernet header */
typedef struct ethernet_header
{
	u_char ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_char ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
}ethernet_header;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service
	u_short tlen;           // Total length
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/* SIP text */
typedef struct sip_contents{
	char *callid;
	char *method;
	int *type;
	char *text;
}sip_contents;

static struct option long_options[] =
{
		{"file",     required_argument,       0, 'f'},
		{"option",  required_argument,       0, 'o'},
		{"call_id",  required_argument, 0, 'c'},
		{"ip",  required_argument, 0, 'i'},  //IP of DUT
		{"port",  required_argument, 0, 'p'},  //port if DUT
		{"remote_ip",    required_argument, 0, 'a'},
		{"local_ip",    required_argument, 0, 'b'},
		{"local_port",    required_argument, 0, 'j'},
		{"remote_port",    required_argument, 0, 'd'},
		{"remote_nr",    required_argument, 0, 'r'},
		{"remote_name",    required_argument, 0, 'e'},
		{"local_nr",    required_argument, 0, 'l'},
		{"local_name",    required_argument, 0, 'g'},
		{"local_password", required_argument, 0, 's'},
		{0, 0, 0, 0}
};

void packet_handler_callids(u_char *, const struct pcap_pkthdr *, const u_char *);
void packet_handler_ips(u_char *, const struct pcap_pkthdr *, const u_char *);
void packet_handler_simulate(u_char *, const struct pcap_pkthdr *, const u_char *);

char *sim_callid;
int port;
char *ovalue;
char *fvalue;
char *local_ip;
char *remote_ip;
char *remote_nr;
char *remote_name;
char *local_nr;
char *local_name;
int local_port;
int remote_port;
char *local_password;
char *sim_ip;
int sdp_port=0;
int last_sdp=0;
int sdp_start_time=0;
int sdp_end_time=0;
int sdp_millisecs=0;
int datalink;
ip_node *ip_addresses;
string_node *callids;
FILE *scenario_file;
char *prefix = "/home/";
int datalink_length;
int i_am_initiator=0;
char* peer_tag_param="[peer_tag_param]";
char* call_number="[call_number]";
char *injection_file_path="/tmp/sipp_injection.csv";
char *scenario_file_path="/tmp/sipp_scenario.xml";
char *rtp_file_path="/tmp/rtp.pcap";
int this_is_first_request=1;
char* last_reply;

#endif /* PCAP2SIPP_H_ */
