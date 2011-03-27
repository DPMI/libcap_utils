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
