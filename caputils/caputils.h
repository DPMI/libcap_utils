/***************************************************************************
                          cap_utils.h  -  description
                             -------------------
    begin                : Fri Jan 31 2003
    copyright            : (C) 2003 by Anders Ekberg, 
    			 : (C) 2005 by Patrik Arlos,
                         : (C) 2011 by David Sveningsson
    email                : anders.ekberg@bth.se
    			 : Patrik.Arlos@bth.se
                         : david.sveningsson@bth.se

 ***************************************************************************/
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef CAP_UTILS
#define CAP_UTILS

#include <stdint.h>
#include <stdio.h>
#include <net/ethernet.h>

#define buffLen 10000                   // Buffer size

/* Protocol definitions */
enum protocol_t {
  PROTOCOL_LOCAL_FILE = 0,
  PROTOCOL_ETHERNET_MULTICAST,
  PROTOCOL_UDP_MULTICAST,
  PROTOCOL_TCP_UNICAST,
};

struct ether_vlan_header{
  uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  uint16_t vlan_proto;             /* vlan is present if feild begins with 0x8100 */
  uint16_t vlan_tci;               /* vlan is present if feild begins with 0x8100 */
  uint16_t h_proto;                /* Ethernet payload protocol */
};

/* forward declare */
struct stream;
struct filter;

#include <caputils/file.h>
#include <caputils/picotime.h>
#include <caputils/filter.h>
#include <caputils/stream.h>
#include <caputils/capture.h>
#include <caputils/utils.h>
#include <caputils/version.h>

#endif /* CAP_UTILS */
