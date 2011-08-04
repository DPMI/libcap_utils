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

/* uint32_t MSB */
#define PARAM_BIT (~((uint32_t)-1 >> 1))

/**
 * Parameters are added with the MSB high so they can be distinguished from the
 * regular filter. */
enum Parameters {
  PARAM_CAPLEN = 1,
};

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
  {"caplen",    1, 0,    PARAM_CAPLEN | PARAM_BIT},
  {0, 0, 0, 0}
};

/* Remove the consumed arguments from argv by shifting the others until all
 * consumed ones are at the and, and decrement argc. */
static void split_argv(int* src_argc, char** src_argv, int* dst_argc, char** dst_argv){
  /* always copy program_name */
  dst_argv[(*dst_argc)++] = src_argv[0];

  /* no arguments passed */
  if ( *src_argc == 1 ){
    return;
  }

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
  static const char* mask_default = "255.255.255.255";
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

static int parse_eth_type(const char* src, uint16_t* type, uint16_t* mask, const char* flag){
  /* generated from linux/if_ether.h at 2011-06-20 */
  static struct ethproto_t {const char* name; uint16_t value;} lut[] = {
    {"LOOP",      0x0060},          /* Ethernet Loopback packet     */
    {"PUP",       0x0200},          /* Xerox PUP packet             */
    {"PUPAT",     0x0201},          /* Xerox PUP Addr Trans packet  */
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
    {"RARP",      0x8035},          /* Reverse Addr Res packet      */
    {"ATALK",     0x809B},          /* Appletalk DDP                */
    {"AARP",      0x80F3},          /* Appletalk AARP               */
    {"8021Q",     0x8100},          /* 802.1Q VLAN Extended Header  */
    {"IPX",       0x8137},          /* IPX over DIX                 */
    {"IPV6",      0x86DD},          /* IPv6 over bluebook           */
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
    {"EDSA",      0xDADA},          /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
    {0, 0},                         /* SENTINEL */
  };

  *mask = 0xFFFF;

  /* test if mask was passed */
  char* separator = strchr(src, '/');
  if ( separator ){
    separator[0] = 0;
    *mask = atoi(separator+1);
  }

  /* search for protocol name */
  struct ethproto_t* cur = lut;
  while ( cur->name ){
    if ( strcasecmp(src, cur->name) == 0 ){
      *type = cur->value;
      return 1;
    }
    cur++;
  }

  /* try to match a number */
  if ( sscanf(src, "%hd", type) == 0 ){
    fprintf(stderr, "Invalid ethernet protocol given to --%s: %s. Ignoring.\n", flag, src);
    return 0;
  }

  return 1;
}

static int parse_eth_addr(const char* src, struct ether_addr* addr, struct ether_addr* mask, const char* flag){
  static const char* mask_default = "FF:FF:FF:FF:FF:FF";
  const char* buf_addr = src;
  const char* buf_mask = mask_default;
 
  /* test if mask was passed */
  char* separator = strchr(src, '/');
  if ( separator ){
    separator[0] = 0;
    buf_mask = separator+1;
  }

  if ( !eth_aton(addr, buf_addr) ){
    fprintf(stderr, "Invalid ethernet address passed to --%s: %s. Ignoring\n", flag, buf_addr);
    return 0;
  }
  if ( !eth_aton(mask, buf_mask) ){
    fprintf(stderr, "Invalid ethernet mask passed to --%s: %s. Ignoring\n", flag, buf_mask);
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
  printf("      --caplen=BYTES          Store BYTES of the captured packet. [default=ALL]\n");
}

int filter_from_argv(int* argcptr, char** argv, struct filter* filter){
  if ( !(argcptr && filter) ){
    return EINVAL;
  }
  
  int argc = *argcptr;

  /* reset filter */
  memset(filter, 0, sizeof(struct filter));
  filter->caplen = -1; /* capture everything (-1 overflows to a very large int) */

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
  int opterr_save = opterr;
  int optind_save = optind;
  opterr = 1;

  int index;
  int op;
  while ( (op=getopt_long(filter_argc, filter_argv, "", options, &index)) != -1 ){
    if ( op & PARAM_BIT ){
      switch ((enum Parameters)(op ^ PARAM_BIT)){
      case PARAM_CAPLEN:
	filter->caplen = atoi(optarg);
	printf("caplen: %d\n", filter->caplen);
      }

      continue;
    }

    const enum FilterBitmask bitmask = (enum FilterBitmask)op;

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
      if ( !parse_eth_type(optarg, &filter->eth_type, &filter->eth_type_mask, "eth.type") ){
	continue;
      }
      break;

    case FILTER_ETH_SRC:
      if ( !parse_eth_addr(optarg, &filter->eth_src, &filter->eth_src_mask, "eth.src") ){
	continue;
      }
      break;

    case FILTER_ETH_DST:
      if ( !parse_eth_addr(optarg, &filter->eth_dst, &filter->eth_dst_mask, "eth.dst") ){
	continue;
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
