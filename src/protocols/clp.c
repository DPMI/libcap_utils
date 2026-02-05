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

#include "src/format/format.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

//static const unsigned int MAX_LABEL_REFERENCES = 32;    /* how many label references (depth) is allowed */

//static int min(int a, int b){ return a<b?a:b; }

static void clp_dump(FILE* fp, const struct header_chunk* header, const char* payload, const char* prefix, int flags){
  
  const struct cap_header* cp = header->cp;

  //  fprintf(fp," CLP \n");
//  const char* cur = payload; /* Not used */
  const char* end = header->cp->payload + header->cp->caplen;
  const ptrdiff_t cpSize = end - payload;
  fprintf(fp,"CLP size = %ld \n",cpSize);    

  if ( cp->caplen < cp->len ){
    fprintf(fp, "%s[Packet size limited during capture %d / %d ]", prefix,cp->caplen,cp->len);
    return;
  }

  
  /*
  fprintf(fp, "type     = %d \n",ntohs(h.type));
  fprintf(fp, "version  = %d.%d \n",ntohs(h.major_version),ntohs(h.minor_version));
  fprintf(fp, "id       = %d \n",ntohl(h.type));
  fprintf(fp, "arith    = %d \n",ntohl(h.arith));
  fprintf(fp, "inVal1   = %d \n",ntohl(h.inValue1));
  fprintf(fp, "inVal2   = %d \n",ntohl(h.inValue2));
  fprintf(fp, "inResult = %d \n",ntohl(h.inResult));
  fprintf(fp, "flVal1   = %d \n",h.flValue1);
  fprintf(fp, "flVal2   = %d \n",h.flValue2);
  fprintf(fp, "flResult = %d \n",h.flResult);  
  */
}

static void clp_format(FILE* fp, const struct header_chunk* header, const char* payload, unsigned int flags){

  /* The next four lines are probably from a more complicated protocol.*/
//  const struct cap_header* cp = header->cp;
//  const size_t offset         = payload - cp->payload;     /* how many bytes into the packet are we? */
 // const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
 // const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */
  
  fputs("CLP (prot) ", fp);
  //  fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
  //  fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));
  fprintf(fp,"\nASCII=[");
  for(int k=0;k<strlen(payload);k++){
    fprintf(fp,"%2c ",payload[k]);
  }
  fprintf(fp,"]\nHEX=[");
  for(int k=0;k<strlen(payload);k++){
    fprintf(fp,"%02x ",payload[k]);
  }
  fprintf(fp,"]\n");
  
  
}

/*
// Removed, used in old solution. 
static size_t clp_message_size(const struct header_chunk* header, const char* ptr){
  return strlen(ptr);
}

*/

struct caputils_protocol protocol_clp = {
	.name = "CalcProtocol",
//	.size = clp_message_size, // OLD approach. 
	.size = 0,
	.next_payload = NULL,
	.format = clp_format,
	.dump = clp_dump,
};
