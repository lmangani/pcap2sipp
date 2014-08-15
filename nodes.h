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

#ifndef NODES_H_
#define NODES_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct ip_node{
	ip_address addr;
	struct ip_node *next;
} ip_node;

typedef struct string_node{
	char *contents;
	struct string_node *next;
} string_node;

int add_ipnodes(ip_node **, ip_address);
int print_ipnodes(ip_node *);
int in_ipnodelist(ip_node *, ip_address);

int add_stringnodes(string_node **, char*);
int print_stringnodes(string_node *);
int in_stringlist(string_node *, char*);

#endif /* NODES_H_ */
