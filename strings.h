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

#ifndef STRINGS_H_
#define STRINGS_H_

/* find and replace types */
#define IP_STRING 0
#define NAME_STRING 1
#define NUMBER_STRING 2
#define PORT_STRING 3
#define ANY_STRING 4

char* replace(const char* ,const char* ,const char*, int);
char* replace_after(const char *, const char *, const char *, const char *,int);

#endif /* STRINGS_H_ */
