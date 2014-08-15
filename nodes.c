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

#include "nodes.h"
#include <stdlib.h>

int add_ipnodes(ip_node **node, ip_address address){
	ip_node *newnode=*node;
	if (newnode==NULL) {
		newnode=malloc(sizeof(ip_node));
		*node=newnode;
	}
	else{
		if (newnode->next!=NULL)
			while (newnode->next!=NULL){
				newnode=newnode->next;
			}
		newnode->next=malloc(sizeof(ip_node));
		newnode = newnode->next;
	}
	newnode->addr.byte1=address.byte1;
	newnode->addr.byte2=address.byte2;
	newnode->addr.byte3=address.byte3;
	newnode->addr.byte4=address.byte4;
	newnode->next=NULL;
	return 0;
}

int print_ipnodes(ip_node *node){
	ip_node *newnode=node;
	while (newnode!=NULL){
		printf("%d.%d.%d.%d \n",
			newnode->addr.byte1,
			newnode->addr.byte2,
			newnode->addr.byte3,
			newnode->addr.byte4);
		newnode=newnode->next;
	}
	return 0;
}

int in_ipnodelist(ip_node *node, ip_address address){
	ip_node *newnode=node;
	while (newnode!=NULL){
		if ((newnode->addr.byte1==address.byte1)
				&& (newnode->addr.byte2==address.byte2)
				&& (newnode->addr.byte3==address.byte3)
				&& (newnode->addr.byte4==address.byte4))
			return 1;
		newnode=newnode->next;
	}
	return 0;
}


int add_stringnodes(string_node **node, char *address){
	string_node *newnode=*node;
	if (newnode==NULL) {
		newnode=malloc(sizeof(string_node));
		*node=newnode;
	}
	else{
		if (newnode->next!=NULL)
			while (newnode->next!=NULL){
				newnode=newnode->next;
			}
		newnode->next=malloc(sizeof(string_node));
		newnode = newnode->next;
	}
	newnode->contents=malloc(sizeof(char)*strlen(address));

	strcpy(newnode->contents,address);

	newnode->next=NULL;
	return 0;
}

int print_stringnodes(string_node *node){
	string_node *newnode=node;
	while (newnode!=NULL){
		printf("%s \n",
			newnode->contents);
		newnode=newnode->next;
	}
	return 0;
}

int in_stringlist(string_node *node, char* address){
	string_node *newnode=node;
	while (newnode!=NULL){
		if ((strcmp(newnode->contents,address))==0)
			return 1;
		newnode=newnode->next;
	}
	return 0;
}
