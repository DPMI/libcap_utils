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
#include <stdio.h>
//#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/time.h>

struct tg_Protocol {
  u_int32_t exp_id;// Experiment ID
  u_int32_t run_id;// Run ID
  u_int32_t key_id;// Key ID
  u_int32_t counter;// Packet Counter
  u_int64_t starttime;// Start of packet transmission time, comes with packet.counter+1
  u_int64_t stoptime;// Stopt of packet transmission time,  comes with packet.counter+1
  struct timeval depttime; // Departure time. 
  u_int64_t recvstarttime; // Receive start and stop time, recorded at receiver.
  u_int64_t recvstoptime; // Receive start and stop time, recorded at receiver.
  struct timeval recvtime;// Receive time
  // After this comes the payload. 
};



static void tg_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
  
  const struct cap_header* cp = header->cp;

  //  fprintf(fp," CP \n");
  struct tg_Protocol h = *(const struct tg_Protocol*)ptr;
//  const char* cur = ptr + sizeof(struct tg_Protocol);
  const char* end = header->cp->payload + header->cp->caplen;
  const ptrdiff_t tgSize = end - ptr;
  fprintf(fp,"TG size = %ld \n",tgSize);    

  if ( cp->caplen < cp->len ){
    fprintf(fp, "%s[Packet size limited during capture %d / %d ]", prefix,cp->caplen,cp->len);
    return;
  }

  fprintf(fp, "expid     = %d \n",ntohl(h.exp_id));
  fprintf(fp, "runid     = %d \n",ntohl(h.run_id));
  fprintf(fp, "keyid     = %d \n",ntohl(h.key_id));
  fprintf(fp, "counter   = %d \n",ntohl(h.counter));
  
}

static void tg_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){

  
  struct tg_Protocol h = *(const struct tg_Protocol*)ptr;
  
  const struct cap_header* cp = header->cp;
  const size_t offset         = ptr - cp->payload;     /* how many bytes into the packet are we? */
  const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
  const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */
  
  fputs("TG ", fp);
  //  fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
  //  fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));

  /* The size isnt enough. */  
  if (full_size >= sizeof(struct tg_Protocol)){
    //    fprintf(fp, "EXPID/RUNID/KEYID/COUNTER %d/%d/%d/%d ",ntohl(h.exp_id),ntohl(h.run_id),ntohl(h.key_id),ntohl(h.counter));
    fprintf(fp, "%d:%d:%d:%d ",ntohl(h.exp_id),ntohl(h.run_id),ntohl(h.key_id),ntohl(h.counter));   
  } else {
    fprintf(fp,"Unknown ");
    fprintf(fp,"\nfsize = %ld , captured_size = %ld, offset = %ld \n",full_size, captured_size,offset);
    fprintf(fp,"\nsize(Protocol) = %ld \n",sizeof(struct tg_Protocol));
    
  }
  
 
  
}

struct caputils_protocol protocol_tg = {
	.name = "TGProtocol",
	.size = sizeof(struct tg_Protocol),
	.next_payload = NULL,
	.format = tg_format,
	.dump = tg_dump,
};
