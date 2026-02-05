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

#include "format.h"
#include <string.h>


//static int min(int a, int b){ return a<b?a:b; }

void print_clp(FILE* fp, const struct cap_header* cp, const char* payload, size_t size, unsigned int flags){

   fputs("CLP (format) ", fp);
  //  fprintf(fp,"\nfsize = %d , captured_size = %d, offset = %d \n",full_size, captured_size,offset);
  //  fprintf(fp,"\nsize(Message) = %d , size(Protocol) = %d \n",sizeof(struct cp_Message), sizeof(struct cp_Protocol));
  fprintf(fp,"\nASCII=[");
  for(int k=0;k<size;k++){
    if (payload[k] < 30 ){
      fprintf(fp,"\\%d ",payload[k]);
    } else {
//      fprintf(fp,"%03c ",payload[k]);  /* Old code, update below */
      fprintf(fp,"%03u ",payload[k] & 0xFF );

    } 
  }
  fprintf(fp,"]\n");
  
  fprintf(fp,"  HEX=[");
  for(int k=0;k<size;k++){
    fprintf(fp,"%03x ",payload[k]);
  }
  fprintf(fp,"]\n");
  
  
}
