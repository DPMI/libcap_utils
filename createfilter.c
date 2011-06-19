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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "caputils/picotime.h"
#include "caputils_int.h"

#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>

static struct option options[]= {
  {"starttime", 1, 0, 4096},
  {"begin",     1, 0, 4096},
  {"endtime",   1, 0, 2048},
  {"end",       1, 0, 2048},
  {"mampid",    1, 0, 1024},
  {"mpid",      1, 0, 1024},
  {"iface",     1, 0,  512},
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
  {0, 0, 0, 0}
};

/* Remove the consumed arguments from argv by shifting the others until all
 * consumed ones are at the and, and decrement argc. */
static void split_argv(int* src_argc, char** src_argv, int* dst_argc, char** dst_argv){
  /* always copy program_name */
  dst_argv[(*dst_argc)++] = src_argv[0];

  char** ptr = &src_argv[1];
  int i = 1;
  do {
    const char* arg = *ptr;

    /* check if it is consumed */
    struct option* cur = options;
    while ( cur->name ){
      if ( strcmp(cur->name, &arg[2]) != 0 ){
	cur++;
	continue;
      }

      /* got a match, proceed with copy and shift argument */
      size_t n = 2;

      /* ensure valid argument follows */
      if ( (i+1) == *src_argc || ptr[1][0] == '-' ){
	fprintf(stderr, "%s: option '--%s' requires an argument\n", src_argv[0], cur->name);
	n = 1;
      }

      /* copy arguments to dst_argv */
      dst_argv[(*dst_argc)++] = ptr[0];
      if ( n == 2 ) dst_argv[(*dst_argc)++] = ptr[1];

      /* shift arguments in src_argv */
      void* dst = ptr;
      void* src = ptr+n;
      size_t bytes = (&src_argv[*src_argc] - (ptr+n)) * sizeof(char*);
      memmove(dst, src, bytes);
      
      *src_argc -= n;
      break;
    }
    
    /* no match */
    if ( !cur->name ){
      i++;
      ptr++;
    }
  } while ( i < *src_argc );
}

/**
 * Parse a string as IP address and mask. Mask does not have to correspond to valid netmask.
 * CIDR-notation works.
 */
static int parse_inet_addr(const char* src, struct in_addr* addr, struct in_addr* mask, const char* flag){
  static char* mask_default = "255.255.255.255";
  const char* buf_addr = src;
  const char* buf_mask = mask_default;
 
  /* test if mask was passed */
  char* separator = strchr(src, '/');
  if ( separator ){
    separator[0] = 0;
    buf_mask = separator+1;
  }

  if ( inet_aton(buf_addr, addr) == 0 ){
    fprintf(stderr, "Invalid IP address passed to --%s: %s. Ignoring\n", flag, buf_addr);
    return 0;
  }

  /* first try CIDR */
  uint32_t bits;
  if ( strchr(buf_mask, '.') == NULL && (bits=atoi(buf_mask)) <= 32 ){
    mask->s_addr = 0;
    while ( bits-- ){
      mask->s_addr = (mask->s_addr >> 1) | (1<<31);
    }
    mask->s_addr = htonl(mask->s_addr);
  } else { /* regular address */
    if ( inet_aton(buf_mask, mask) == 0 ){
      fprintf(stderr, "Invalid mask passed to --%s: %s. Ignoring\n", flag, buf_mask);
      return 0;
    }
  }

  return 1;
}

static int parse_port(const char* src, uint16_t* port, uint16_t* mask, const char* flag){
  *mask = 0xFFFF;

  /* test if mask was passed */
  char* separator = strchr(src, '/');
  if ( separator ){
    separator[0] = 0;
    *mask = atoi(separator+1);
  }

  struct servent* service = getservbyname(src, NULL);
  if ( service ){
    *port = ntohs(service->s_port);
  } else if ( isdigit(optarg[0]) ) {
    *port = atoi(optarg);
  } else {
    fprintf(stderr, "Invalid port number passed to %s: %s. Ignoring\n", flag, src);
    return 0;
  }

  return 1;
}

void filter_from_argv_usage(){
  printf("libcap_filter-" VERSION " options\n");
  printf("      --starttime=DATETIME    Discard all packages before starttime described by\n");
  printf("                              the unix timestamp. See capfilter(1) for\n");
  printf("                              additional accepted formats.\n");
  printf("      --endtime=DATETIME      Discard all packets after endtime.\n");
  printf("      --begin                 Alias for --starttime\n");
  printf("      --end                   Alias for --endtime\n");
  printf("      --mampid=STRING         Filter on MAMPid\n");
  printf("      --mpid=STRING           Alias for --mampid\n");
  printf("      --iface=STRING          Filter on networkinterface on MP\n");
  printf("      --if=STRING             Alias for --iface\n");
  printf("      --eth.vlan=TCI[/MASK]   Filter on VLAN TCI and mask\n");
  printf("      --eth.type=STRING[/MASK]Filter on carrier protocol (ip, arp,rarp)\n");
  printf("      --eth.src=ADDR[/MASK]   Filter on ethernet source\n");
  printf("      --eth.dst=ADDR[/MASK]   Filter on ethernet destination\n");
  printf("      --ip.proto=STRING       Filter on ip protocol (tcp, udp, icmp,)\n");
  printf("      --ip.src=ADDR[/MASK]    Filter on source ip address, dotted decimal\n");
  printf("      --ip.dst=ADDR[/MASK]    Filter on destination ip address, dotted decimal\n");
  printf("      --tp.sport=PORT[/MASK]  Filter on source portnumber\n");
  printf("      --tp.dport=PORT[/MASK]  Filter on destination portnumber\n");
}

int filter_from_argv(int* argcptr, char** argv, struct filter* filter){
  if ( !(argcptr && filter) ){
    return EINVAL;
  }
  
  int argc = *argcptr;

  /* reset filter */
  memset(filter, 0, sizeof(struct filter));

  /* fast path */
  if ( argc == 0 ){
    return 0;
  }

  if ( !argv ){ /* argv is required when argc > 0 */
    return EINVAL;
  }

  int filter_argc = 0;
  char* filter_argv[argc];

  /* take all valid arguments and put into filter_argv */
  split_argv(&argc, argv, &filter_argc, filter_argv);

  /* save getopt settings */
  extern int opterr;
  extern int optind;
  int opterr_save = opterr;
  int optind_save = optind;
  opterr = 1;

  int index;
  int op;
  while ( (op=getopt_long(filter_argc, filter_argv, "", options, &index)) != -1 ){
    const enum FilterBitmask bitmask = (enum FilterBitmask)op;

    switch (op){
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
      if ( !parse_inet_addr(optarg, &filter->ip_src, &filter->ip_src_mask, "ip.src") ){
	continue;
      }
      /* copy to text for legacy code */
      strcpy((char*)filter->_ip_src, inet_ntoa(filter->ip_src));
      strcpy((char*)filter->_ip_src_mask, inet_ntoa(filter->ip_src_mask));
      break;

    case FILTER_IP_DST:
      if ( !parse_inet_addr(optarg, &filter->ip_dst, &filter->ip_dst_mask, "ip.dst") ){
	continue;
      }
      /* copy to text for legacy code */
      strcpy((char*)filter->_ip_dst, inet_ntoa(filter->ip_dst));
      strcpy((char*)filter->_ip_dst_mask, inet_ntoa(filter->ip_dst_mask));
      break;

    case FILTER_SRC_PORT:
      if ( !parse_port(optarg, &filter->src_port, &filter->src_port_mask, "tp.sport") ){
	continue;
      }
      break;

    case FILTER_DST_PORT:
      if ( !parse_port(optarg, &filter->dst_port, &filter->dst_port_mask, "tp.dport") ){
	continue;
      }
      break;
    }

    /* update index bitmask */
    filter->index |= bitmask;
  }

  /* restore getopt */
  opterr = opterr_save;
  optind = optind_save;

  /* save argc */
  *argcptr = argc;
  return 0;
}

int filter_close(struct filter* filter){
  return 0;
}
