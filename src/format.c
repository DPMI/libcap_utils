/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "format/format.h"
#include "caputils/caputils.h"
#include "caputils/marker.h"
#include <time.h>

static int min(int a, int b){ return a<b?a:b; }

static void print_timestamp(FILE* fp, struct format* state, const struct cap_header* cp){
	const int format_date  = state->flags & FORMAT_DATE_BIT;
	const int format_local = state->flags & FORMAT_LOCAL_BIT;
	const int relative     = state->flags & FORMAT_REL_TIMESTAMP;

	if( !format_date ) {
		timepico t = cp->ts;
		int sign = 0; /* quick-and-dirty solution */

		if ( relative ){
			/* need to test if timestamp is less than reference in case multiple
			 * locations is present in trace in which case dt may be negative. */
			if ( timecmp(&t, &state->ref) >= 0 ){
				t = timepico_sub(t, state->ref);
				sign = 0;
			} else {
				t = timepico_sub(state->ref, t);
				sign = 1;
			}
		}

		fprintf(fp, "%s%u.%012"PRIu64, sign ? "-" : "", t.tv_sec, t.tv_psec);
		return;
	}

	static char buffer[32];
	time_t time = (time_t)cp->ts.tv_sec;
	struct tm* tm = format_local ? localtime(&time) : gmtime(&time);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(fp, "%s.%012"PRIu64, buffer, cp->ts.tv_psec);
	strftime(buffer, sizeof(buffer), "%z", tm);
	fprintf(fp, " %s", buffer);
}

static void print_linklayer(FILE* fp, const struct cap_header* cp, unsigned int flags){
	fputc(':', fp);

	/* Test for libcap_utils marker packet */
	struct marker mark;
	int marker_port;
	if ( (marker_port=is_marker(cp, &mark, 0)) != 0 ){
		fprintf(stdout, "Marker [e=%d, r=%d, k=%d, s=%d, port=%d]",
		        mark.exp_id, mark.run_id, mark.key_id, mark.seq_num, marker_port);
		return;
	}

	print_eth(fp, cp, cp->ethhdr, flags);
}

static void print_pkt(FILE* fp, struct format* state, const struct cap_header* cp){
	print_timestamp(fp, state, cp);
	fprintf(fp, ":LINK(%4d):CAPLEN(%4d)", cp->len, cp->caplen);

	if ( state->flags >= FORMAT_LAYER_LINK ){
		print_linklayer(fp, cp, state->flags);
	}
	fputc('\n', fp);

	if ( state->flags & FORMAT_HEXDUMP ){
		hexdump(fp, cp->payload, min(cp->caplen, cp->len));
	}
}

void format_setup(struct format* state, unsigned int flags){
	state->pktcount = 0;
	state->first = 1;
	state->flags = flags;

	/* by default show all */
	if ( state->flags >> FORMAT_LAYER_BIT == 0){
		state->flags |= FORMAT_LAYER_APPLICATION;
	}
}

void format_pkg(FILE* fp, struct format* state, const struct cap_header* cp){
	fprintf(fp, "[%4"PRIu64"]:%.8s:%.8s:", ++state->pktcount, cp->nic, cp->mampid);
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
	print_pkt(fp, state, cp);
}

void format_ignore(FILE* fp, struct format* state, const struct cap_header* cp){
	state->pktcount++;
	if ( state->first ){
		state->ref = cp->ts;
		state->first = 0;
	}
}

int limited_caplen(const struct cap_header* cp, const void* ptr, size_t bytes){
	const size_t used = (const char*)ptr - cp->payload;
	const size_t left = cp->caplen - used;
	return left < bytes;
}
