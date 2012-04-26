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
	if ( version ){
		version->major = VERSION_MAJOR;
		version->minor = VERSION_MINOR;
		version->micro = VERSION_MICRO;
		version->features = 0;
	}
	return VERSION;
}
