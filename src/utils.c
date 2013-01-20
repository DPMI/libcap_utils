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
#include "vcs.h"
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
	return VERSION
#ifdef VCS_REV
		"[" VCS_REV "/" VCS_BRANCH "]"
#endif
		;
}

/* generated from linux/if_ether.h at 2011-06-20 */
static struct ethertype ethertype[] = {
	{"LOOP",      0x0060},          /* Ethernet Loopback packet     */
	{"STP",       0x0026},          /* Spanning-Tree Protocol       */
	{"CDPVTP",    0x016e},
	{"PUP",       0x0200},          /* Xerox PUP packet             */
	{"PUPAT",     0x0201},          /* Xerox PUP Addr Trans packet  */
	{"SPRITE",    0x0500},          /* Sprite */
	{"IPv4",      0x0800},          /* Internet Protocol packet     */
	{"IP",        0x0800},          /* Internet Protocol packet     */
	{"X25",       0x0805},          /* CCITT X.25                   */
	{"ARP",       0x0806},          /* Address Resolution packet    */
	{"BPQ",       0x08FF},          /* G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] */
	{"IEEEPUP",   0x0a00},          /* Xerox IEEE802.3 PUP packet */
	{"IEEEPUPAT", 0x0a01},          /* Xerox IEEE802.3 PUP Addr Trans packet */
	{"DEC",       0x6000},          /* DEC Assigned proto           */
	{"DNA_DL",    0x6001},          /* DEC DNA Dump/Load            */
	{"DNA_RC",    0x6002},          /* DEC DNA Remote Console       */
	{"DNA_RT",    0x6003},          /* DEC DNA Routing              */
	{"LAT",       0x6004},          /* DEC LAT                      */
	{"DIAG",      0x6005},          /* DEC Diagnostics              */
	{"CUST",      0x6006},          /* DEC Customer use             */
	{"SCA",       0x6007},          /* DEC Systems Comms Arch       */
	{"TEB",       0x6558},          /* Trans Ether Bridging         */
	{"MP",        0x8010},          /* Measurement Frame (DPMI)     */
	{"RARP",      0x8035},          /* Reverse Addr Res packet      */
	{"ATALK",     0x809B},          /* Appletalk DDP                */
	{"AARP",      0x80F3},          /* Appletalk AARP               */
	{"VLAN",      0x8100},          /* 802.1Q VLAN Extended Header  */
	{"8021Q",     0x8100},          /* 802.1Q VLAN Extended Header  */
	{"IPX",       0x8137},          /* IPX over DIX                 */
	{"IPv6",      0x86DD},          /* IPv6 over bluebook           */
	{"PAUSE",     0x8808},          /* IEEE Pause frames. See 802.3 31B */
	{"SLOW",      0x8809},          /* Slow Protocol. See 802.3ad 43B */
	{"WCCP",      0x883E},          /* Web-cache coordination protocol
	                                 * defined in draft-wilson-wrec-wccp-v2-00.txt */
	{"PPP_DISC",  0x8863},          /* PPPoE discovery messages     */
	{"PPP_SES",   0x8864},          /* PPPoE session messages       */
	{"MPLS_UC",   0x8847},          /* MPLS Unicast traffic         */
	{"MPLS_MC",   0x8848},          /* MPLS Multicast traffic       */
	{"ATMMPOA",   0x884c},          /* MultiProtocol Over ATM       */
	{"LINK_CTL",  0x886c},          /* HPNA, wlan link local tunnel */
	{"ATMFATE",   0x8884},          /* Frame-based ATM Transport
	                                 * over Ethernet                */
	{"PAE",       0x888E},          /* Port Access Entity (IEEE 802.1X) */
	{"AOE",       0x88A2},          /* ATA over Ethernet            */
	{"TIPC",      0x88CA},          /* TIPC                         */
	{"1588",      0x88F7},          /* IEEE 1588 Timesync */
	{"FCOE",      0x8906},          /* Fibre Channel over Ethernet  */
	{"FIP",       0x8914},          /* FCoE Initialization Protocol */
	{"LOOPBACK",  0x9000},          /* used to test interfaces */
	{"EDSA",      0xDADA},          /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
	{0, 0},                         /* SENTINEL */
};

const struct ethertype* ethertype_by_name(const char* name){
	struct ethertype* cur = ethertype;
	while ( cur->name ){
		if ( strcasecmp(name, cur->name) == 0 ){
			return cur;
		}
		cur++;
	}
	return NULL;
}

const struct ethertype* ethertype_by_number(int number){
	struct ethertype* cur = ethertype;
	while ( cur->name ){
		if ( number == cur->value ){
			return cur;
		}
		cur++;
	}
	return NULL;
}
