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

#include "strings.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

/*
 * Find and replace function. Also accepts a type parameter, which changes the behavior
 * for replacing IP addresses, ports, caller ID numbers or names
 * param src source string
 * param from string to replace
 * param to string with which to replace
 * param type of string to replace. Possible values: IP_STRING, NAME_STRING, NUMBER_STRING, PORT_STRING, ANY_STRING
 * return the resulting string
 */
char *replace(const char *src, const char *from, const char *to, int type) {
	size_t size = strlen(src) + 1;
	size_t fromlen = strlen(from);
	size_t tolen = strlen(to);
	int badmatch = 0;
	char *dst;
	char *value = malloc(size);

	if (value==NULL) {
		fprintf (stderr, "Cannot allocate memory\n");
		return NULL;
	}

	dst = value;

	if ( value != NULL ) {
		for ( ;; ) {
			const char *match = strstr(src, from);
			if ( match != NULL ) {
				badmatch = 0;

				if (type == IP_STRING){
					/* An IP_STRING must not be preceded or followed by digits in order to be replaced */
					if (src < match){
						char c=*(match-1);
						if (c>='0' && (int)c<='9') badmatch = 1;
					}
					if (((src + strlen(src)) > (match + strlen(from))) && (badmatch == 0)) {
						char c=*(match+strlen(from));
						if (c>='0' && c<='9') badmatch = 1;
					}
				} else if (type == PORT_STRING){
					/* A PORT_STRING must be preceded by ':' and not followed by digits in order to be replaced */
					if (src < match){
						char c=*(match-1);
						if (c!=':') badmatch = 1;
					}
					if (((src + strlen(src)) > (match + strlen(from))) && (badmatch == 0)) {
						char c=*(match+strlen(from));
						if (c>='0' && c<='9') badmatch = 1;
					}
				} else if (type == NAME_STRING){
					/* A NAME_STRING must be preceded by '"','<' or ' ' and followed by '"','>' or ' ' in order to be replaced */
					if (src < match){
						char c=*(match-1);
						if (c!='"' && c!='<' && c!=' ') badmatch = 1;
					}
					if (((src + strlen(src)) > (match + strlen(from))) && (badmatch == 0)) {
						char c=*(match+strlen(from));
						if (c!='"' && c!='>' && c!=' ') badmatch = 1;
					}
				}  else if (type == NUMBER_STRING){
					/* A NUMBER_STRING must be preceded by '"','<' or ':' and followed by '"' or '@' in order to be replaced */
					if (src < match){
						char c=*(match-1);
						if (c!='"' && c!='<' && c!=':') badmatch = 1;
					}
					if (((src + strlen(src)) > (match + strlen(from))) && (badmatch == 0)) {
						char c=*(match+strlen(from));
						if (c!='"' && c!='@') badmatch = 1;
					}
				}

				if (badmatch == 1){ /* Match was found, but did not comply to our type replace criteria. Continue searching */
					size_t count = match - src;

					memmove(dst, src, count);
					src += count;
					dst += count;

					memmove(dst, from, fromlen);
					src += fromlen;
					dst += fromlen;

					continue;
				}

				size_t count = match - src;
				char *temp;
				size += tolen - fromlen;

				temp = realloc(value, size);

				if ( temp == NULL ) {
					fprintf (stderr, "Cannot re-allocate memory\n");
					free(value);
					return NULL;
				}

				dst = temp + (dst - value);
				value = temp;
				memmove(dst, src, count);
				src += count;
				dst += count;

				memmove(dst, to, tolen);
				src += fromlen;
				dst += tolen;
			}

			else {/* No match found. Stop searching and return the initial string */
				strcpy(dst, src);
				break;
			}
		}
	}

	return value;
}

/*
 * Find and replace everything starting with a given string until a given string.
 * param src source string
 * param from string to start with
 * param to string to end with
 * param to string with which to replace
 * param or_end chooses whether to accept end of line if parameter to is not matched. Possible values: 0 for no, 1 for yes
 * return the resulting string
 */
char *replace_after(const char *src, const char *from, const char *until, const char *to, int or_end) {
	size_t size = strlen(src) + 1;
	size_t tolen = strlen(to);
	char *dst;
	char *value = malloc(size);

	if (value==NULL) {
		fprintf (stderr, "Cannot allocate memory\n");
		return NULL;
	}

	dst = value;

	if ( value != NULL ) {
		for ( ;; ) {
			const char *match1 = strstr(src, from);
			if ( match1 != NULL ) {
				char* match2=strstr(match1+strlen(from), until);
				if (match2 == NULL) {
					if (or_end == 1) match2=(char *)src+strlen(src)-1;
					else {
						strcpy(dst, src);
						break;
					}
				}


				size_t count = match1 - src;
				size_t diff = match2 - match1;
				char *temp;
				size += (tolen - diff);

				temp = realloc(value, size);

				if ( temp == NULL ) {
					fprintf (stderr, "Cannot re-allocate memory\n");
					free(value);
					return NULL;
				}

				dst = temp + (dst - value);
				value = temp;

				memmove(dst, src, count);
				src += count;
				dst += count;

				memmove(dst, to, tolen);
				src += diff;
				dst += tolen;

			}

			else { /* No match found. Stop searching and return the initial string */
				strcpy(dst, src);
				break;
			}
		}
	}

	return value;
}
