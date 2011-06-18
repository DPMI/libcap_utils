/***************************************************************************
                          createfilter.c  -  description
                             -------------------
    begin                : Wed 5 2003
    copyright            : (C) 2003 by Anders Ekberg, Patrik Arlos
    email                : anders.ekberg@bth.se, Patrik.Arlos@bth.se
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 This function takes arguments from a option string in the original program
 call and creates a filter to be used in all programs based on cap_utils.
 ***************************************************************************/
#include "caputils/caputils.h"
#include "caputils/picotime.h"
#include "caputils_int.h"

#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>

void filter_from_argv_usage(){
  printf("Libcap_filter version %d.%d\n",VERSION_MAJOR, VERSION_MINOR);
  printf("Filter Options\n");
  printf("  -A, --starttime=DATETIME\n");
  printf("                  Filter on all packets after starttime\n");
  printf("      --begin     Alias for --starttime\n");
  printf("      --endtime   filter on all packets before endtime in ISO-8601 format\n");
  printf("                  ISO 8601 YYYY-MM-DD hh:mm:ss.x, x can be upto 12 digits,\n");	  
  printf("	--mpid	    filter on mpid\n");
  printf("	--if	    filter on networkinterface on MP\n");
  printf("	--eth.vlan  filter on vlan				     value/[mask]\n");
  printf("	--eth.type  filter on carrier protocol (ip, arp,rarp)	     value/[mask]\n");
  printf("	--eth.src   filter on ethernet source			     value/[mask]\n");
  printf("	--eth.dst   filter on ethernet destination		     value/[mask]\n");
  printf("	--ip.proto  filter on ip protocol (tcp, udp, icmp,)	     value/[mask]\n");
  printf("	--ip.src    filter on source ip address, dotted decimal	     value/[mask]\n");
  printf("	--ip.dst    filter on destination ip address, dotted decimal value/[mask]\n");
  printf("	--tp.sport  filter on source portnumber			     value/[mask]\n");
  printf("	--tp.dport  filter on destination portnumber		     value/[mask]\n");
  printf("\n");
  printf("Datetime format\n");
  printf("in ISO-8601 format");
}

struct filter* createfilter(int argc, char** argv){
  static struct option options[]= {
    {"starttime", 1, 0, 4096},
    {"begin",     1, 0, 4096},
    {"endtime",   1, 0, 2048},
    {"end",       1, 0, 2048},
    {"mpid",      1, 0, 1024},
    {"if",        1, 0,  512},
    {"eth.vlan",  1, 0,  256},
    {"eth.type",  1, 0,  128},
    {"eth.src",   1, 0,   64},
    {"eth.dst",   1, 0,   32},
    {"ip.proto",  1, 0,   16},
    {"ip.src",    1, 0,    8},
    {"ip.dst",    1, 0,    4},
    {"tp.sport",  1, 0,    2},
    {"tp.dport",  1, 0,    1},
  };

  struct filter* filter = (struct filter*)malloc(sizeof(struct filter));
  memset(filter, 0, sizeof(struct filter));

  int index;
  int op;
  while ( (op=getopt_long(argc, argv, "", options, &index)) != -1 ){
    const enum FilterBitmask bitmask = (enum FilterBitmask)bitmask;

    switch (bitmask){
    case FILTER_START_TIME:
      if ( timepico_from_string(&filter->starttime, optarg) != 0 ){
	fprintf(stderr, "Invalid dated passed to --%s: %s. Ignoring.", options[index].name, optarg);
	continue;
      }
      break;

    case FILTER_END_TIME:
      if ( timepico_from_string(&filter->endtime, optarg) != 0 ){
	fprintf(stderr, "Invalid dated passed to --%s: %s. Ignoring.", options[index].name, optarg);
	continue;
      }
      break;

    case FILTER_MAMPID:
      strncpy(filter->mampid, optarg, 8);
      break;

    case FILTER_IFACE:
      strncpy(filter->iface, optarg, 8);
      break;

    case FILTER_VLAN:
      filter->vlan_tci_mask = 0xFFFF;
      if ( sscanf(optarg, "%hd/%hd", &filter->vlan_tci, &filter->vlan_tci_mask) == 0 ){
	fprintf(stderr, "Invalid VLAN TCI: %s. Ignoring\n", optarg);
	continue;
      }
      break;

    case FILTER_ETH_TYPE:
      {
	char type[64];
	filter->eth_type_mask = 0xFFFF;
	sscanf(optarg, "%64s/%hd", type, &filter->eth_type_mask);

	if      ( strcmp(type, "ip"  ) == 0 ) filter->eth_type = ETH_P_IP;
	else if ( strcmp(type, "arp" ) == 0 ) filter->eth_type = ETH_P_ARP;
	else if ( strcmp(type, "rarp") == 0 ) filter->eth_type = ETH_P_RARP;
	else if ( isdigit(type[0])          ) filter->eth_type = atoi(type);
	else {
	  fprintf(stderr, "Invalid ethernet protocol: %s. Ignoring.\n", type);
	  continue;
	}
      }
      break;

    case FILTER_ETH_SRC:
      {
	char addr[18], mask[18] = "FF:FF:FF:FF:FF:FF";
	sscanf(optarg, "%18s/%18s", addr, mask);
	if ( !eth_aton(&filter->eth_src, addr) ){
	  fprintf(stderr, "Invalid ethernet address passed to --eth.src: %s. Ignoring\n", addr);
	  continue;
	}
	if ( !eth_aton(&filter->eth_src_mask, mask) ){
	  fprintf(stderr, "Invalid ethernet mask passed to --eth.src: %s. Ignoring\n", mask);
	  continue;
	}
      }
      break;

    case FILTER_ETH_DST:
      {
	char addr[18], mask[18] = "FF:FF:FF:FF:FF:FF";
	sscanf(optarg, "%18s/%18s", addr, mask);
	if ( !eth_aton(&filter->eth_dst, addr) ){
	  fprintf(stderr, "Invalid ethernet address passed to --eth.dst: %s. Ignoring\n", addr);
	  continue;
	}
	if ( !eth_aton(&filter->eth_dst_mask, mask) ){
	  fprintf(stderr, "Invalid ethernet mask passed to --eth.dst: %s. Ignoring\n", mask);
	  continue;
	}
      }
      break;

    case FILTER_IP_PROTO:
      {
	struct protoent* proto = getprotobyname(optarg);
	if ( proto ){
	  filter->ip_proto = proto->p_proto;
	} else if ( isdigit(optarg[0]) ) {
	  filter->ip_proto = atoi(optarg);
	} else {
	  fprintf(stderr, "Invalid IP protocol: %s. Ignoring\n", optarg);
	  continue;
	}
      }
      break;

    case FILTER_IP_SRC:
      {
	char addr[25], mask[25] = "255.255.255.255";
	sscanf(optarg, "%24s/%24s", addr, mask);
	strcpy((char*)filter->_ip_src, addr);
	strcpy((char*)filter->_ip_src_mask, mask);
	if ( inet_aton(addr, &filter->ip_src) != 0 ){
	  fprintf(stderr, "Invalid IP address passed to --ip.src: %s. Ignoring\n", addr);
	  continue;
	}
	if ( inet_aton(mask, &filter->ip_src_mask) != 0 ){
	  fprintf(stderr, "Invalid IP mask passed to --ip.src: %s. Ignoring\n", mask);
	  continue;
	}
      }
      break;

    case FILTER_IP_DST:
      {
	char addr[25], mask[25] = "255.255.255.255";
	sscanf(optarg, "%24s/%24s", addr, mask);
	strcpy((char*)filter->_ip_dst, addr);
	strcpy((char*)filter->_ip_dst_mask, mask);
	if ( inet_aton(addr, &filter->ip_dst) != 0 ){
	  fprintf(stderr, "Invalid IP address passed to --ip.dst: %s. Ignoring\n", addr);
	  continue;
	}
	if ( inet_aton(mask, &filter->ip_dst_mask) != 0 ){
	  fprintf(stderr, "Invalid IP mask passed to --ip.dst: %s. Ignoring\n", mask);
	  continue;
	}
      }
      break;

    case FILTER_SRC_PORT:
      {
	filter->src_port_mask = 0xFFFF;
	char name[64];
	sscanf(optarg, "%64s/%hd", name, &filter->src_port_mask);

	struct servent* service = getservbyname(name, NULL);
	if ( service ){
	  filter->src_port = service->s_port;
	} else if ( isdigit(optarg[0]) ) {
	  filter->src_port = atoi(optarg);
	} else {
	  fprintf(stderr, "Invalid port number passed to tp.sport: %s. Ignoring\n", name);
	  continue;
	}
      }

    case FILTER_DST_PORT:
      {
	filter->dst_port_mask = 0xFFFF;
	char name[64];
	sscanf(optarg, "%64s/%hd", name, &filter->dst_port_mask);

	struct servent* service = getservbyname(name, NULL);
	if ( service ){
	  filter->dst_port = service->s_port;
	} else if ( isdigit(optarg[0]) ) {
	  filter->dst_port = atoi(optarg);
	} else {
	  fprintf(stderr, "Invalid port number passed to tp.dport: %s. Ignoring\n", name);
	  continue;
	}
      }

    }

    filter->index |= bitmask;
  }
  
  return filter;
}

int closefilter(struct filter* filter){
  free(filter);
  return 0;
}
