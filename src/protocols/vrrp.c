/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2015 (see AUTHORS)
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

struct vrrpv3 {
  uint8_t version_type;
  uint8_t virtual_router_id;
  uint8_t priority;
  uint8_t count_ipvx_addresses;

  uint16_t reserved_and_max_adv_int;
  uint16_t checksum;
};



/*
  version = (version_type >> 4 ) & 0x0f
  type = (version_type ) & 0x0f
  reserved = (reserved_and_max_adv_int >> 12) & 0x0F
  max_adv_int = (reserved_and_max_adv_int ) & 0x0FFF

*/

struct vrrpv2 {
  uint8_t version_type;
  uint8_t virtual_router_id;
  uint8_t priority;
  uint8_t count_ipvx_addresses;
  
  uint8_t auth;
  uint8_t adv_int;
  uint16_t checksum;
};

enum {
  VRRP_TYPE_MIN = 0,
  VRRP_TYPE_ADVERTISEMENT = 1,
  VRRP_TYPE_MAX,
};

enum {
  VRRP_AUTH_NON = 0,
  VRRP_AUTH_RESERVED1 = 1,
  VRRP_AUTH_RESERVED2 = 2,  
  VRRP_AUTH_MAX,
};


static const char* vrrp_type_table[VRRP_TYPE_MAX] = {
  NULL,
  "Advertisement",
};

static const char* vrrp_auth_table[VRRP_AUTH_MAX] = {
  "No Authentication",
  "Simple Text Password",
  "IP Authentication Header",  
};

static const char* vrrp_type_name(int type){
	if ( type > VRRP_TYPE_MIN || type < VRRP_TYPE_MAX ){
		return vrrp_type_table[type];
	} else {
		return "Unknown";
	}
}

static const char* vrrp_auth_type(int type){
	if ( type >= VRRP_AUTH_NON || type < VRRP_AUTH_MAX ){
		return vrrp_auth_table[type];
	} else {
		return "Unknown";
	}
}


static enum caputils_protocol_type vrrp_next(struct header_chunk* header, const char* ptr, const char** out){
	return PROTOCOL_DONE;
}

static void vrrp_format(FILE* fp, const struct header_chunk* header, const char* ptr, unsigned int flags){
	fputs(": VRRP", fp);

	if ( limited_caplen(header->cp, ptr, offsetof(struct vrrpv3, virtual_router_id)) ){
		fputs(" [Packet size limited during capture]", fp);
		return;
	}

	const struct vrrpv3* vrrp = (const struct vrrpv3*)ptr;
	const struct vrrpv2* vrrpv2 = (const struct vrrpv2*)ptr;

	
	// Count=%d 
	// Max.adv=%d, 

	int vrrp_version = (vrrp->version_type>>4)& 0x0F;
	/*
	fprintf(fp, " v%d %s(%d) VRID=%d Prio=%d Count=%d  %s--> %s", vrrp_version , vrrp_type_name(vrrp->version_type&0x0F), (vrrp->version_type&0x0F), (vrrp->virtual_router_id),(vrrp->priority),vrrp->count_ipvx_addresses, 
		header->last_net.net_src, header->last_net.net_dst);
	*/

	fprintf(fp, " v%d %s(%d) VRID=%d Prio=%d Count=%d  ", (vrrp->version_type>>4)& 0x0F , vrrp_type_name(vrrp->version_type&0x0F), (vrrp->version_type&0x0F), (vrrp->virtual_router_id),(vrrp->priority),vrrp->count_ipvx_addresses);
	
	switch(vrrp_version) {
	case 2:
	  fprintf(fp, "Auth=%d, Adv_int=%d ", vrrpv2->auth, vrrpv2->adv_int);
	  break;
	  
	case 3:
	  fprintf(fp, "Max Adv_int=%d ", (vrrp->reserved_and_max_adv_int ) & 0x0FFF );
	  break;
	  
	default:
	  fprintf(fp, " (version not supported  )");
	  break;
	  
	} 

	fprintf(fp, " %s --> %s", header->last_net.net_src, header->last_net.net_dst);
}

static void vrrp_dump(FILE* fp, const struct header_chunk* header, const char* ptr, const char* prefix, int flags){
  if ( limited_caplen(header->cp, ptr,  offsetof(struct vrrpv3, virtual_router_id)) ){
    fprintf(fp, "%s[Packet size limited during capture]", prefix);
    return;
  }
  
  const struct vrrpv3* vrrp = (const struct vrrpv3*)ptr;
  const struct vrrpv2* vrrpv2 = (const struct vrrpv2*)ptr;
  int vrrp_version = (vrrp->version_type>>4)& 0x0F;

  const struct cap_header* cp = header->cp;
  const size_t offset         = ptr - cp->payload;     /* how many bytes into the packet are we? */
  const size_t full_size      = cp->len    - offset;   /* how many bytes was the packet? */
  const size_t captured_size  = cp->caplen - offset;   /* how many bytes is left to read? */
  

  

  fprintf(fp, "%sSize (Padding ?)     %d\n", prefix, full_size); 
  
  fprintf(fp, "%sversion:             %d\n", prefix, (vrrp->version_type>>4)&0x0F);
  fprintf(fp, "%stype:                %s (%d)\n", prefix, vrrp_type_name(vrrp->version_type&0x0F), (vrrp->version_type)&0x0F);
  fprintf(fp, "%sVRID:                %d\n", prefix, vrrp->virtual_router_id);
  fprintf(fp, "%spriority:            %d\n", prefix, vrrp->priority);
  fprintf(fp, "%scount:               %d\n", prefix, vrrp->count_ipvx_addresses);
  
  switch(vrrp_version) {
  case 2:
    fprintf(fp, "%sAuth:                %s(%d)\n", prefix,vrrp_auth_type(vrrpv2->auth),vrrpv2->auth);;
    fprintf(fp, "%sAdv.Int:             %d\n", prefix,vrrpv2->adv_int);
    
    break;
    
  case 3:
    fprintf(fp, "%sMax Adv_int:         %d\n", prefix,(vrrp->reserved_and_max_adv_int ) & 0x0FFF );
    break;
    
  default:
    fprintf(fp, "%s(version not supported)\n",prefix);
    break;
    
  } 	
  fprintf(fp, "%schecksum:            0x%02x\n", prefix, ntohs(vrrp->checksum));


  
  char *IPAddress_Data = ptr + sizeof(struct vrrpv3);
  char *Auth_data = ptr + sizeof(struct vrrpv3) + vrrp->count_ipvx_addresses*sizeof(struct in_addr);


  const size_t AuthOff = Auth_data - IPAddress_Data;
  char ip_string[INET_ADDRSTRLEN];
  char *result;
  
  for(int IPindex=0;IPindex<vrrp->count_ipvx_addresses; IPindex++){
    struct in_addr *anAddress=(struct in_addr*)IPAddress_Data;
    result = inet_ntop(AF_INET, anAddress, ip_string, INET_ADDRSTRLEN);
    if (result == NULL ) {
      perror("ntop failed");
      return 1;
    }
    fprintf(fp,"%sAddress [%d]          %s\n", prefix,IPindex, ip_string);
  }

  char authBuffer[9];
  int index=0;


  while (Auth_data+(index+1)*8 < (ptr+full_size) ){
    memcpy(authBuffer, Auth_data+index*8,8);
    authBuffer[8]='\0';
    fprintf(fp,"%sAuthString [%d]       \"%s\"\n",prefix, index,authBuffer);
    index++;
    if (index>10){
      break;
    }
  }
  
	
	
}

struct caputils_protocol protocol_vrrp = {
	.name = "VRRP",
	.size = 0,
	.next_payload = vrrp_next,
	.format = vrrp_format,
	.dump = vrrp_dump,
};
