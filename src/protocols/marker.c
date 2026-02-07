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

// CALCULATION PROTOCOL USED in DV1619 labs.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "src/format/format.h"
#include "caputils/marker.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/time.h>



static const char* marker_flags(const struct marker marker){
	static char buf[12];
	static char flag[8] = {'T', 0, };
	if ( marker.flags == (0) ){
		return "(not set)";
	}

	char* dst = buf;
	*dst++ = '[';
	for ( int i = 0; i < 8; i++ ){
		if ( marker.flags & (1<<i) ){
			*dst++ = flag[i];
		}
	}
	*dst++ = ']';
	return buf;
}

static void marker_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
  
  const struct cap_header* cp = header->cp;

  //  fprintf(fp," CP \n");
  struct marker h = *(const struct marker*)ptr;

//  const char* cur = ptr + sizeof(struct marker); /* Not used, commented */
  const char* end = header->cp->payload + header->cp->caplen;
  const ptrdiff_t markerSize = end - ptr;
  fprintf(fp,"Marker size = %ld \n",markerSize);    

  if ( cp->caplen < cp->len ){
    fprintf(fp, "%s[Packet size limited during capture %d / %d ]", prefix,cp->caplen,cp->len);
    return;
  }

  fprintf(fp, "magic     = %d \n",ntohl(h.magic));
  fprintf(fp, "version   = %d \n",h.version);
  fprintf(fp, "flags     = %s [%02x] \n",marker_flags(h), h.flags);
  fprintf(fp, "reserved  = %d \n",ntohs(h.reserved));
  fprintf(fp, "expid     = %d \n",ntohl(h.exp_id));
  fprintf(fp, "runid     = %d \n",ntohl(h.run_id));
  fprintf(fp, "keyid     = %d \n",ntohl(h.key_id));
  fprintf(fp, "seqnr     = %d \n",ntohl(h.seq_num));
  fprintf(fp, "timestamp = %d \n",ntohl(h.timestamp));
  
}

static void marker_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){

  
  struct marker h = *(const struct marker*)ptr;
  
  const struct cap_header* cp = header->cp;
  const size_t offset         = ptr - cp->payload;     /* how many bytes into the packet are we? */
  const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
  const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */
  
  fputs("MARKER ", fp);
  //  fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
  //  fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));

  /* The size isnt enough. */  
  if (full_size >= sizeof(struct marker)){
    //    fprintf(fp, "FLAGS/EXPID/RUNID/KEYID/SEQNR %d/%d/%d/%d ",ntohl(h.exp_id),ntohl(h.run_id),ntohl(h.key_id),ntohl(h.counter));
    fprintf(fp, "%s[0x%02x]:%d:%d:%d:%d ",marker_flags(h),h.flags,ntohl(h.exp_id),ntohl(h.run_id),ntohl(h.key_id),ntohl(h.seq_num));
    /*    
    fprintf(fp, "\n");
    fprintf(fp, "magic     = %x \n",ntohl(h.magic));
    fprintf(fp, "version   = %d \n",h.version);
    fprintf(fp, "flags     = %d \n",h.flags);
    fprintf(fp, "reserved  = %d \n",ntohs(h.reserved));
    fprintf(fp, "expid     = %d \n",ntohl(h.exp_id));
    fprintf(fp, "runid     = %d \n",ntohl(h.run_id));
    fprintf(fp, "keyid     = %d \n",ntohl(h.key_id));
    fprintf(fp, "seqnr     = %d \n",ntohl(h.seq_num));
    fprintf(fp, "timestamp = %d \n",be64toh(h.timestamp));
    */
    
  } else {
    fprintf(fp,"Unknown ");
    fprintf(fp,"\nfsize = %ld , captured_size = %ld, offset = %ld \n",full_size, captured_size,offset);
    fprintf(fp,"\nsize(Protocol) = %ld \n",sizeof(struct marker));
    
  }
  
 
  
}

struct caputils_protocol protocol_marker = {
	.name = "MARKERProtocol",
	.size = sizeof(struct marker),
	.next_payload = NULL,
	.format = marker_format,
	.dump = marker_dump,
};
