/***************************************************************************
                          filter.c  -  description
                             -------------------
    begin        : Mnn Aug 1 2004
    copyright    : (c) 2005 by Patrik Arlos <patrik.arlos@bth.se>
                   (c) 2011 by David Sveningsson <david.sveningsson@bth.se>

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

#include "caputils/filter.h"
#include "caputils_int.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#define FILTER __attribute__ ((pure))

/**
 * Match ethernet address.
 */
static int matchEth(const struct ether_addr* desired, const struct ether_addr* mask, const uint8_t net[ETH_ALEN]){
  for ( int i=0; i < ETH_ALEN; i++ ){
    uint8_t t = (net[i] & mask->ether_addr_octet[i]);
    if( t != desired->ether_addr_octet[i] ){
       return 0;
    }
  }

  return 1;
}

static const struct ether_vlan_header* find_ether_vlan_header(const struct ethhdr* ether, uint16_t* h_proto){
  if( *h_proto == 0x8100 ){
    const struct ether_vlan_header* vlan = (const struct ether_vlan_header*)ether;
    *h_proto = ntohs(vlan->h_proto);
    return vlan;
  }
  return NULL;
}

const struct ip* find_ip_header(const struct ethhdr* ether){
  const void* ptr = ether;
  if( ntohs(ether->h_proto) != 0x8100 ){
    if ( ntohs(ether->h_proto) == ETHERTYPE_IP ){
      return (const struct ip*)(ptr + sizeof(struct ethhdr));
    }
  } else { /* have VLAN tag */
    const struct ether_vlan_header* vlan = (const struct ether_vlan_header*)ether;
    if( ntohs(vlan->h_proto) == ETHERTYPE_IP ){
      return (const struct ip*)(ptr + sizeof(struct ether_vlan_header));
    }
  }
  return NULL;
}

static const void* find_ipproto_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip){
  const size_t vlan_offset = ntohs(ether->h_proto) == 0x8100 ? 4 : 0; /* vlan tag is 4 octets */
  return pkt + sizeof(struct ethhdr) + vlan_offset + 4*(ip->ip_hl);
}

const struct tcphdr* find_tcp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest){
  if ( !( ip && ip->ip_p == IPPROTO_TCP) ){
    return NULL;
  }

  const struct tcphdr* tcp = (const struct tcphdr*)find_ipproto_header(pkt, ether, ip);
  *src = ntohs(tcp->source);
  *dest = ntohs(tcp->dest);
  return tcp;
}

const struct udphdr* find_udp_header(const void* pkt, const struct ethhdr* ether, const struct ip* ip, uint16_t* src, uint16_t* dest){
  if ( !( ip && ip->ip_p == IPPROTO_UDP) ){
    return NULL;
  }
  const struct udphdr* udp = (const struct udphdr*)find_ipproto_header(pkt, ether, ip);
  *src = ntohs(udp->source);
  *dest = ntohs(udp->dest);
  return udp;
}

/**
 * Filter tests.
 * Filters return non-zero if the match and zero if rejected.
 */

static int FILTER filter_iface(const struct filter* filter, const char* iface){
	return  (filter->index & FILTER_CI) && (strstr(iface, filter->iface) != NULL);
}

static int FILTER filter_vlan_tci(const struct filter* filter, const struct ether_vlan_header* vlan){
	return (filter->index & FILTER_VLAN) && vlan && (ntohs(vlan->vlan_tci) & filter->vlan_tci_mask) == filter->vlan_tci;
}

static int FILTER filter_h_proto(const struct filter* filter, uint16_t h_proto){
	return (filter->index & FILTER_ETH_TYPE) && ((h_proto & filter->eth_type_mask) == filter->eth_type);
}

static int FILTER filter_eth_src(const struct filter* filter, const struct ethhdr* ether){
	return (filter->index & FILTER_ETH_SRC) && matchEth(&filter->eth_src, &filter->eth_src_mask, ether->h_source);
}

static int FILTER filter_eth_dst(const struct filter* filter, const struct ethhdr* ether){
	return (filter->index & FILTER_ETH_DST) && matchEth(&filter->eth_dst, &filter->eth_dst_mask, ether->h_dest);
}

static int FILTER filter_ip_proto(const struct filter* filter, const struct ip* ip){
	return (filter->index & FILTER_IP_PROTO) && (ip && filter->ip_proto == ip->ip_p);
}

static int FILTER filter_ip_src(const struct filter* filter, const struct ip* ip){
	return (filter->index & FILTER_IP_SRC) && (ip && (ip->ip_src.s_addr & filter->ip_src_mask.s_addr) == filter->ip_src.s_addr);
}

static int FILTER filter_ip_dst(const struct filter* filter, const struct ip* ip){
	return (filter->index & FILTER_IP_DST) && (ip && (ip->ip_dst.s_addr & filter->ip_dst_mask.s_addr) == filter->ip_dst.s_addr);
}

static int FILTER filter_src_port(const struct filter* filter, uint16_t port){
	return (filter->index & FILTER_SRC_PORT) && (filter->src_port == port);
}

static int FILTER filter_dst_port(const struct filter* filter, uint16_t port){
	return (filter->index & FILTER_DST_PORT) && (filter->dst_port == port);
}

static int FILTER filter_port(const struct filter* filter, uint16_t src, uint16_t dst){
	return (filter->index & FILTER_PORT) && (filter->port == src || filter->port == dst);
}

static int FILTER filter_mampid(const struct filter* filter, char mampid[]){
	return (filter->index & FILTER_MAMPID) && (strncmp(filter->mampid, mampid, 8) == 0);
}

static int FILTER filter_start_time(const struct filter* filter, const timepico* time){
	return (filter->index & FILTER_START_TIME) && (timecmp(&filter->starttime, time) <= 0);
}

static int FILTER filter_end_time(const struct filter* filter, const timepico* time){
	return (filter->index & FILTER_END_TIME) && (timecmp(&filter->endtime, time) >= 0);
}

int filter_match(const struct filter* filter, const void* pkt, struct cap_header* head){
  assert(filter);
  assert(pkt);
  assert(head);

  /* fast path */
  if ( filter->index == 0 ){
    return 1;
  }

  const struct ethhdr* ether = (const struct ethhdr*)pkt;
  uint16_t h_proto = ntohs(ether->h_proto); /* may be overwritten by find_ether_vlan_header */
  uint16_t src_port = 0; /* set by find_{tcp,udp}_header */
  uint16_t dst_port = 0; /* set by find_{tcp,udp}_header */

  const struct ether_vlan_header* vlan = find_ether_vlan_header(ether, &h_proto);
  const struct ip* ip = find_ip_header(ether);
  find_tcp_header(pkt, ether, ip, &src_port, &dst_port);
  find_udp_header(pkt, ether, ip, &src_port, &dst_port);

  int match = 0;

  /* base tests */
  match |= filter_dst_port(filter, dst_port)       << OFFSET_DST_PORT;    /* Transport dest port */
  match |= filter_src_port(filter, src_port)       << OFFSET_SRC_PORT;    /* Transport source port */
  match |= filter_ip_dst(filter, ip)               << OFFSET_IP_DST;      /* IP destination address */
  match |= filter_ip_src(filter, ip)               << OFFSET_IP_SRC;      /* IP source address */
  match |= filter_ip_proto(filter, ip)             << OFFSET_IP_PROTO;    /* IP protocol */
  match |= filter_eth_dst(filter, ether)           << OFFSET_ETH_DST;     /* Ethernet destination */
  match |= filter_eth_src(filter, ether)           << OFFSET_ETH_SRC;     /* Ethernet source */
  match |= filter_h_proto(filter, h_proto)         << OFFSET_ETH_TYPE;    /* Ethernet type */
  match |= filter_vlan_tci(filter, vlan)           << OFFSET_VLAN;        /* VLAN TCI (Tag Control Information) */
  match |= filter_iface(filter, head->nic)         << OFFSET_IFACE;       /* Capture Interface (iface) */

  /* 0.7 extensions */
  match |= filter_mampid(filter, head->mampid)     << OFFSET_MAMPID;      /* MAMPid */
  match |= filter_end_time(filter, &head->ts)      << OFFSET_END_TIME;    /* End time vs packet timestamp */
  match |= filter_start_time(filter, &head->ts)    << OFFSET_START_TIME;  /* Start time vs packet timestamp */
  match |= filter_port(filter, src_port, dst_port) << OFFSET_PORT;        /* Transport source or dest port */

  //printf("match=%d index=%d and=%d or=%d\n", match, filter->index, match == filter->index, match > 0);

  switch ( filter->mode ){
  case FILTER_AND: return match == filter->index;
  case FILTER_OR:  return match > 0;
  default: fprintf(stderr, "invalid filter mode\n"); abort();
  }
}

static const char* inet_ntoa_r(const struct in_addr in, char* buf){
  const char* tmp = inet_ntoa(in);
  strcpy(buf, tmp);
  return buf;
}

void filter_print(const struct filter* filter, FILE* fp, int verbose){
  static char buf[100];

  fprintf(fp, "FILTER {%02d}\n", filter->filter_id);
  fprintf(fp, "\t%-14s: %s\n", stream_addr_type(&filter->dest) == STREAM_ADDR_CAPFILE ? "DESTFILE" : "DESTADDRESS", stream_addr_ntoa(&filter->dest));
  fprintf(fp, "\tCAPLEN        : %d\n", filter->caplen);
  fprintf(fp, "\tindex         : %d\n", filter->index);
  fprintf(fp, "\tmode          : %s (%d)\n", filter->mode == FILTER_AND ? "AND" : "OR", filter->mode);

  if ( verbose || filter->index & FILTER_MAMPID ){
    fprintf(fp, "\tMAMPid        : %s\n", filter->mampid);
  } else if ( verbose ){
    fprintf(fp, "\tMAMPid        : NULL\n");
  }

  if ( verbose || filter->index&512 ){
    fprintf(fp, "\tCI_ID         : %s\n", filter->iface);
  } else if ( verbose ) {
    fprintf(fp, "\tCI_ID         : NULL\n");
  }

  if ( filter->index&256 ){
    fprintf(fp, "\tVLAN_TCI      : %d MASK (%d)", filter->vlan_tci, filter->vlan_tci_mask);
  } else if ( verbose ) {
    fprintf(fp, "\tVLAN_TCI      : NULL\n");
  }

  if ( filter->index&128 ){
    fprintf(fp, "\tETH_TYPE      : %d (MASK: 0x%04X)\n", filter->eth_type, filter->eth_type_mask);
  } else if ( verbose ) {
    fprintf(fp, "\tETH_TYPE      : NULL\n");
  }

  if ( filter->index&64 ){
    fprintf(fp, "\tETH_SRC       : %s (MASK: %s)\n", hexdump_address_r(&filter->eth_src, &buf[0]), hexdump_address_r(&filter->eth_src_mask, &buf[19]));
  } else if ( verbose ) {
    fprintf(fp, "\tETH_SRC       : NULL\n");
  }

  if ( filter->index&32 ){
    fprintf(fp, "\tETH_DST       : %s (MASK: %s)\n", hexdump_address_r(&filter->eth_dst, &buf[0]), hexdump_address_r(&filter->eth_dst_mask, &buf[19]));
  } else if ( verbose ) {
    fprintf(fp, "\tETH_DST       : NULL\n");
  }

  if ( filter->index&16 ){
    fprintf(fp, "\tIP_PROTO      : %d\n", filter->ip_proto);
  } else if ( verbose ) {
    fprintf(fp, "\tIP_PROTO      : NULL\n");
  }

  if ( filter->index&8 ){
    fprintf(fp, "\tIP_SRC        : %s (MASK: %s)\n", inet_ntoa_r(filter->ip_src, &buf[0]), inet_ntoa_r(filter->ip_src_mask, &buf[50]));
  } else if ( verbose ) {
    fprintf(fp, "\tIP_SRC        : NULL\n");
  }

  if ( filter->index&4 ){
    fprintf(fp, "\tIP_DST        : %s (MASK: %s)\n", inet_ntoa_r(filter->ip_dst, &buf[0]), inet_ntoa_r(filter->ip_dst_mask, &buf[50]));
  } else if ( verbose ) {
    fprintf(fp, "\tIP_DST        : NULL\n");
  }

  if ( filter->index & FILTER_PORT ){
    fprintf(fp, "\tPORT (s or d) : %d (MASK: 0x%04X)\n", filter->port, filter->port_mask);
  } else if ( verbose ) {
    fprintf(fp, "\tPORT (s or d) : NULL\n");
  }

  if ( filter->index&2 ){
    fprintf(fp, "\tPORT_SRC      : %d (MASK: 0x%04X)\n", filter->src_port, filter->src_port_mask);
  } else if ( verbose ) {
    fprintf(fp, "\tPORT_SRC      : NULL\n");
  }

  if ( filter->index&1  ){
    fprintf(fp, "\tPORT_DST      : %d (MASK: 0x%04X)\n", filter->dst_port, filter->dst_port_mask);
  } else if ( verbose ) {
    fprintf(fp, "\tPORT_DST      : NULL\n");
  }
}

void filter_pack(struct filter* src, struct filter_packed* dst){
  dst->filter_id	= htonl(src->filter_id);
  dst->index		= htonl(src->index);
  dst->vlan_tci		= htons(src->vlan_tci);
  dst->eth_type		= htons(src->eth_type);
  dst->ip_proto		= src->ip_proto;
  dst->src_port		= htons(src->src_port);
  dst->dst_port		= htons(src->dst_port);
  dst->port       = htons(src->port);
  dst->vlan_tci_mask	= htons(src->vlan_tci_mask);
  dst->eth_type_mask	= htons(src->eth_type_mask);
  dst->src_port_mask	= htons(src->src_port_mask);
  dst->dst_port_mask	= htons(src->dst_port_mask);
  dst->port_mask      = htons(src->port_mask);
  dst->consumer	      = htonl(src->consumer);
  dst->caplen         = htonl(src->caplen);
  dst->mode           = src->mode;

  /* ip source and dest */
  dst->ip_src = src->ip_src;
  dst->ip_dst = src->ip_dst;
  dst->ip_src_mask = src->ip_src_mask;
  dst->ip_dst_mask = src->ip_dst_mask;
  memcpy(dst->_ip_src, inet_ntoa(src->ip_src), 16);
  memcpy(dst->_ip_dst, inet_ntoa(src->ip_dst), 16);
  memcpy(dst->_ip_src_mask, inet_ntoa(src->ip_src_mask), 16);
  memcpy(dst->_ip_dst_mask, inet_ntoa(src->ip_dst_mask), 16);

  memcpy(dst->iface, src->iface, 8);
  memcpy(&dst->eth_src, &src->eth_src, sizeof(struct ether_addr));
  memcpy(&dst->eth_dst, &src->eth_dst, sizeof(struct ether_addr));
  memcpy(&dst->eth_src_mask, &src->eth_src_mask, sizeof(struct ether_addr));
  memcpy(&dst->eth_dst_mask, &src->eth_dst_mask, sizeof(struct ether_addr));

  /* address (safe to copy, already in network order) */
  memcpy(&dst->dest, &src->dest, sizeof(stream_addr_t));

  /* filter version */
  dst->version = htonl(0x02);
}

void filter_unpack(struct filter_packed* src, struct filter* dst){
  dst->filter_id	= ntohl(src->filter_id);
  dst->index		= ntohl(src->index);
  dst->vlan_tci		= ntohs(src->vlan_tci);
  dst->eth_type		= ntohs(src->eth_type);
  dst->ip_proto		= src->ip_proto;
  dst->src_port		= ntohs(src->src_port);
  dst->dst_port		= ntohs(src->dst_port);
  dst->vlan_tci_mask	= ntohs(src->vlan_tci_mask);
  dst->eth_type_mask	= ntohs(src->eth_type_mask);
  dst->src_port_mask	= ntohs(src->src_port_mask);
  dst->dst_port_mask	= ntohs(src->dst_port_mask);
  dst->consumer		= ntohl(src->consumer);
  dst->caplen		= ntohl(src->caplen);

  const int version = ntohl(src->version);

  if ( version == 0 ){
	  /* legacy filters are converted from ascii */
	  inet_aton((const char*)src->_ip_src, &dst->ip_src);
	  inet_aton((const char*)src->_ip_dst, &dst->ip_dst);
	  inet_aton((const char*)src->_ip_src_mask, &dst->ip_src_mask);
	  inet_aton((const char*)src->_ip_dst_mask, &dst->ip_dst_mask);
  } else {
	  dst->ip_src = src->ip_src;
	  dst->ip_dst = src->ip_dst;
	  dst->ip_src_mask = src->ip_src_mask;
	  dst->ip_dst_mask = src->ip_dst_mask;
  }

  /* Check if mode was supplied */
  if ( version >= 2 ){
	  dst->mode = src->mode;
  } else {
	  dst->mode = FILTER_AND;
  }

  memcpy(dst->iface, src->iface, 8);
  memcpy(&dst->eth_src, &src->eth_src, sizeof(struct ether_addr));
  memcpy(&dst->eth_dst, &src->eth_dst, sizeof(struct ether_addr));
  memcpy(&dst->eth_src_mask, &src->eth_src_mask, sizeof(struct ether_addr));
  memcpy(&dst->eth_dst_mask, &src->eth_dst_mask, sizeof(struct ether_addr));

  /* address (safe to copy, supposed to be in network order) */
  memcpy(&dst->dest, &src->dest, sizeof(stream_addr_t));

  /* filter version */
  dst->version = htonl(0x02);
}
