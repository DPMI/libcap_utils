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
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

static const unsigned int MAX_LABEL_REFERENCES = 32;    /* how many label references (depth) is allowed */

static int min(int a, int b){ return a<b?a:b; }

struct cp_Protocol {
  uint16_t type;  // What message is this, 1 = server to client, 2 client to server, 3... reserved , conversion needed (for practice)
  uint16_t major_version; // 1, conversion needed (for practice)
  uint16_t minor_version; // 0, conversion needed (for practice)
  uint32_t id; // Server side identification with operation. Client must return the same ID as it got from Server., conversion needed (for practice)
  uint32_t arith; // What operation to perform, see mapping below. 
  int32_t inValue1; // integer value 1, conversion needed (for practice)
  int32_t inValue2; // integer value 2, conversion needed (for practice)
  int32_t inResult; // integer result, conversion needed (for practice)
  double flValue1;  // float value 1,NO NEED TO do host to Network or Network to Host conversion here, we are using equivalent platforms        
  double flValue2;  // float value 2,NO NEED TO do host to Network or Network to Host conversion here, we are using equivalent platforms
  double flResult;  // float result,NO NEED TO do host to Network or Network to Host conversion here, we are using equivalent platforms
};

struct cp_Message {
  uint16_t type;    // See below, conversion needed (for practice)
  uint32_t message; // See below, conversion needed (for practice)
  
  // Protocol, UDP = 17, TCP = 6, other values are reserved. 
  uint16_t protocol; // conversion needed (for practice)
  uint16_t major_version; // 1, conversion needed (for practice)
  uint16_t minor_version; // 0 , conversion needed (for practice)

};

static void cp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
  
  const struct cap_header* cp = header->cp;

  //  fprintf(fp," CP \n");
  struct cp_Protocol h = *(const struct cp_Protocol*)ptr;
  const char* cur = ptr + sizeof(struct cp_Protocol);
  const char* end = header->cp->payload + header->cp->caplen;
  const cpSize = end - ptr;
  fprintf(fp,"CP size = %d \n",cpSize);    

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

static void cp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){

  
  struct cp_Protocol h = *(const struct cp_Protocol*)ptr;
  struct cp_Message k = *(const struct cp_Message*)ptr;
  
  const struct cap_header* cp = header->cp;
  const size_t offset         = ptr - cp->payload;     /* how many bytes into the packet are we? */
  const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
  const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */
  
  fputs("CP ", fp);
  //  fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
  //  fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));

  if ( (full_size == sizeof(struct cp_Message)) || (full_size == (sizeof(struct cp_Message)+2) )  ){ // The last is needed if someone padds... 
    fprintf(fp, "Message %d.%d ",ntohs(k.major_version),ntohs(k.minor_version));
    fprintf(fp, "type = %d ",ntohs(k.type));
    switch (ntohl(k.message)) {
    case 0:
      fprintf(fp," N/A ");
      break;
    case 1:
      fprintf(fp," OK ");
      break;
    case 2:
      fprintf(fp," Not OK ");
      break;
    default:
      fprintf(fp," unknown %d ",ntohl(k.message));
      break;
    }
    switch( ntohs(k.protocol)){
    case 17:
      fprintf(fp, " UDP *correct* ");
      break;
    case 6:
      fprintf(fp, " TCP *bad* ");
      break;
    default:
      fprintf(fp, " wrong protocol %d ", ntohs(k.protocol));
      break;
    }
	
    
  } else if (full_size == sizeof(struct cp_Protocol)){
    fprintf(fp, "Protocol %d.%d id=%d ",ntohs(h.major_version),ntohs(h.minor_version),ntohl(h.id));
    switch(ntohs(h.type)){
    case 1:
      fprintf(fp, "S->C ");
      break;
    case 2:
      fprintf(fp, "C->S ");
      break;      
    default:
      fprintf(fp, "type (%d) ",ntohs(h.type));
      break;
    }

    switch(ntohl(h.arith)){
    case 1:
      fprintf(fp, "%d add %d = %d ", ntohl(h.inValue1), ntohl(h.inValue2), ntohl(h.inResult));
      break;
    case 2:
      fprintf(fp, "%d sub %d = %d ", ntohl(h.inValue1), ntohl(h.inValue2), ntohl(h.inResult));
      break;      
    case 3:
      fprintf(fp, "%d mul %d = %d ", ntohl(h.inValue1), ntohl(h.inValue2), ntohl(h.inResult));
      break;
    case 4:
      fprintf(fp, "%d div %d = %d ", ntohl(h.inValue1), ntohl(h.inValue2), ntohl(h.inResult));
      break;      
    case 5:
      fprintf(fp, "%g fadd %g = %g ", h.flValue1, h.flValue2,h.flResult);
      break;
    case 6:
      fprintf(fp, "%g fsub %g = %g ", h.flValue1, h.flValue2,h.flResult);
      break;      
    case 7:
      fprintf(fp, "%g fmul %g = %g ", h.flValue1, h.flValue2,h.flResult);
      break;
    case 8:
      fprintf(fp, "%g fdiv %g = %g ", h.flValue1, h.flValue2,h.flResult);
      break;      
    default:
      fprintf(fp, "arith (%d) ",ntohl(h.arith));
      break;
    }
    
  } else {
    fprintf(fp,"Unknown ");
    fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
    fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));
    
  }
  
  

  
}

struct caputils_protocol protocol_cp = {
	.name = "CalcProtocol",
	.size = sizeof(struct cp_Message),
	.next_payload = NULL,
	.format = cp_format,
	.dump = cp_dump,
};
