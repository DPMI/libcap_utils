/***************************************************************************
                          eth_aton.c  -  description
                             -------------------
    begin                : Mon Feb 3 2003
    copyright            : (C) 2005 by Patrik Arlos
    email                : Patrik.Arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "caputils_int.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/udp.h>

int eth_aton(struct ether_addr* dst, const char* addr){
  assert(dst);
  assert(addr);

  struct ether_addr* tmp = ether_aton(addr);

  if ( !tmp ){
    return 0;
  }

  memcpy(dst, tmp, sizeof(struct ether_addr));
  return 1;
}

const char* hexdump_address_r(const struct ether_addr* address, char buf[IFHWADDRLEN*3]){
  /* this is basically the same as ether_ntoa but it pads with zeroes which ether_ntoa doesn't */
  int i;

  for ( i = 0; i < IFHWADDRLEN - 1; i++ ) {
    sprintf (buf + 3*i, "%2.2X:", address->ether_addr_octet[i]);
  }
  sprintf (buf + 15, "%2.2X", address->ether_addr_octet[i]);

  return buf;
}

const char* hexdump_address(const struct ether_addr* address){
  static char buf[IFHWADDRLEN*3];
  return hexdump_address_r(address, buf);
}

const char* caputils_version(caputils_version_t* version){
#define str(x) #x
	if ( version ){
		version->major = VERSION_MAJOR;
		version->minor = VERSION_MAJOR;
		version->micro = atoi(str(VERSION_MICRO)); /* hack because micro may include suffix like _git */
		version->features = 0;
	}
#undef str
	return VERSION;
}

int is_marker(struct cap_header* cp, struct marker* ptr, int port){
	/* match ip packet */
	const struct ip* ip = find_ip_header(cp->ethhdr);
	if ( !ip ){ return 0; }

	/* match udp packet */
	uint16_t src, dst;
	const struct udphdr* udp = find_udp_header(cp->payload, cp->ethhdr, ip, &src, &dst);
	if ( !(udp && src == MARKERPORT && (dst == port || port == 0)) ){ return 0; }

	/* match magic */
	struct marker* marker = (struct marker*)((char*)udp + sizeof(struct udphdr));
	if ( ntohl(marker->magic) != MARKER_MAGIC ){ return 0; }

	/* assume it is a marker */
	if ( ptr ){
		ptr->magic = ntohl(marker->magic);
		ptr->version = marker->version;
		ptr->flags = marker->flags;
		ptr->reserved = ntohs(marker->reserved);
		ptr->exp_id = ntohl(marker->exp_id);
		ptr->run_id = ntohl(marker->run_id);
		ptr->key_id = ntohl(marker->key_id);
		ptr->seq_num = ntohl(marker->seq_num);
		ptr->timestamp = be64toh(marker->timestamp);
	}

	return 1;
}
