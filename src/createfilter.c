/**
 * libcap_utils - DPMI capture utilities
 * Copyright (C) 2003-2013 (see AUTHORS)
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

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

/* uint32_t MSB */
#define PARAM_BIT (~((uint32_t)-1 >> 1))

/**
 * Parameters are added with the MSB high so they can be distinguished from the
 * regular filter. */
enum Parameters {
	PARAM_CAPLEN = 1,
	PARAM_MODE,
	PARAM_BPF,
};

static struct option options[]= {
	{"tp.port",   1, 0, FILTER_PORT},
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
	{"filter-mode", required_argument, 0, PARAM_MODE | PARAM_BIT},

	/* local-only filters */
	{"frame-max-dt", required_argument, 0, FILTER_FRAME_MAX_DT},

	{"bpf",       required_argument, 0, PARAM_BPF | PARAM_BIT},
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
		if ( strlen(arg) < 3 ){ /* not enough chars */
			i++;
			ptr++;
			continue;
		}

		/* find = to determine how many chars to compare */
		size_t maxlen = 0;
		const char* tmp = arg;
		while ( maxlen++, *++tmp ) if ( *tmp == '=' ) break;

		/* check if it is consumed */
		struct option* cur = options;
		for ( cur = options; cur->name; cur++ ){
			if ( arg[0] != '-' || arg[1] != '-' ) continue;
			if ( strncmp(cur->name, &arg[2], maxlen-2) != 0 ) continue;

			/* got a match, proceed with copy and shift argument */
			size_t n = 2;

			/* ensure valid argument follows */
			if ( arg[maxlen] == '=' ){ /* "--foo=bar" */
				n = 1;
			} else { /* "--foo=bar */
				if ( (i+1) == *src_argc || ptr[1][0] == '-' ){
					fprintf(stderr, "%s: option '--%s' requires an argument\n", src_argv[0], cur->name);
					n = 1;
				}
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

	/* always mask the address based on mask */
	addr->s_addr &= mask->s_addr;

	return 1;
}

static int parse_port(const char* src, uint16_t* port, uint16_t* mask, const char* flag){
	*mask = 0xFFFF;

	/* test if mask was passed */
	char* separator = strchr(src, '/');
	if ( separator ){
		separator[0] = 0;
		const char* tmp = separator+1;
		int base = 10;
		if ( strncasecmp(tmp, "0x", 2) == 0 ){
			base = 16;
			tmp+=2;
		}
		*mask = strtol(tmp, (char **) NULL, base);
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

	/* always mask the port based on mask */
	*port &= *mask;

	return 1;
}

static int parse_eth_type(const char* src, uint16_t* type, uint16_t* mask, const char* flag){
	*mask = 0xFFFF;

	/* test if mask was passed */
	char* separator = strchr(src, '/');
	if ( separator ){
		separator[0] = 0;
		const char* tmp = separator+1;
		int base = 10;
		if ( strncasecmp(tmp, "0x", 2) == 0 ){
			base = 16;
			tmp+=2;
		}
		*mask = strtol(tmp, (char **) NULL, base);
	}

	/* search for protocol name */
	const struct ethertype* ethertype = ethertype_by_name(src);
	if ( ethertype ){
		*type = ethertype->value;
	} else {
		/* try to match a number */
		if ( sscanf(src, "%hd", type) == 0 ){
			fprintf(stderr, "Invalid ethernet protocol given to --%s: %s. Ignoring.\n", flag, src);
			return 0;
		}
	}

	*type &= *mask;
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

	/* apply mask */
	for ( int i = 0; i < ETH_ALEN; i++ ){
		addr->ether_addr_octet[i] &= mask->ether_addr_octet[i];
	}

	return 1;
}

static int bpf_set(struct filter* filter, const char* expr, const char* program_name){
#ifdef HAVE_PCAP
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_dead(DLT_EN10MB, 2040); /* 2040 because it is default DAG snapshot according to souces, e.g. see dagconvert */
	if ( !handle ){
		fprintf(stderr, "%s: BPF error: cannot open pcap device: %s\n", program_name, errbuf);
		return EINVAL;
	}

	/* release previous filter */
	struct bpf_program prg = {0, filter->bpf_insn};
	pcap_freecode(&prg);
	free(filter->bpf_expr);

	/* compile new filter */
	if ( pcap_compile(handle, &prg, expr, 1, 0xffffffff) != 0 ){
		fprintf(stderr, "%s: BPF error: %s\n", program_name, pcap_geterr(handle));
		return EINVAL;
	}
	filter->bpf_insn = prg.bf_insns;

	pcap_close(handle);
#else
	fprintf(stderr, "%s: warning: pcap support has been disabled, bpf filters cannot be used.\n", program_name);
#endif

	filter->bpf_expr = strdup(expr);
	return 0;
}

void filter_from_argv_usage(){
	printf("libcap_filter-" VERSION " options\n"
	       "      --starttime=DATETIME      Discard all packages before starttime described by\n"
	       "                                the unix timestamp. See capfilter(1) for\n"
	       "                                additional accepted formats.\n"
	       "      --endtime=DATETIME        Discard all packets after endtime.\n"
	       "      --begin                   Alias for --starttime\n"
	       "      --end                     Alias for --endtime\n"
	       "      --mampid=STRING           Filter on MAMPid.\n"
	       "      --mpid=STRING             Alias for --mampid.\n"
	       "      --iface=STRING            Filter on networkinterface on MP.\n"
	       "      --if=STRING               Alias for --iface.\n"
	       "      --eth.vlan=TCI[/MASK]     Filter on VLAN TCI and mask.\n"
	       "      --eth.type=STRING[/MASK]  Filter on carrier protocol (IP, ARP, RARP).\n"
	       "      --eth.src=ADDR[/MASK]     Filter on ethernet source.\n"
	       "      --eth.dst=ADDR[/MASK]     Filter on ethernet destination.\n"
	       "      --ip.proto=STRING         Filter on ip protocol (TCP, UDP, ICMP).\n"
	       "      --ip.src=ADDR[/MASK]      Filter on source ip address, dotted decimal.\n"
	       "      --ip.dst=ADDR[/MASK]      Filter on destination ip address, dotted decimal.\n"
	       "      --tp.sport=PORT[/MASK]    Filter on source portnumber.\n"
	       "      --tp.dport=PORT[/MASK]    Filter on destination portnumber.\n"
	       "      --tp.port=PORT[/MASK]     Filter or source or destination portnumber (if\n"
	       "                                either is a match the packet matches).\n"
	       "      --frame-max-dt=TIME       Starts to reject packets after the interarrival-\n"
	       "                                time is greater than TIME (WRT matched packets).\n"
	       "      --caplen=BYTES            Store BYTES of the captured packet. [default=ALL]\n"
	       "      --filter-mode=MODE        Set filter mode to AND or OR. [default=AND]\n"
#ifdef HAVE_PCAP
	       "      --bpf=FILTER              In addition to regular DPMI filter also use the\n"
	       "                                supplied BPF. Matching takes place after DPMI\n"
	       "                                filter.\n"
#endif
		);
}

int filter_from_argv(int* argcptr, char** argv, struct filter* filter){
	if ( !(argcptr && filter) ){
		return EINVAL;
	}

	int argc = *argcptr;

	/* reset filter */
	memset(filter, 0, sizeof(struct filter));
	filter->caplen = -1; /* capture everything (-1 overflows to a very large int) */
	filter->mode = FILTER_AND;
	filter->first = 1;

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

	int ret = 0;
	int index;
	int op;
	while ( (op=getopt_long(filter_argc, filter_argv, "", options, &index)) != -1 && ret == 0 ){
		if ( op == '?' ){ /* error occured, e.g. missing argument */
			ret = 1;
			break;
		}

		if ( op & PARAM_BIT ){
			switch ((enum Parameters)(op ^ PARAM_BIT)){
			case PARAM_CAPLEN:
				filter->caplen = atoi(optarg);
				break;

			case PARAM_MODE:
				if      ( strcasecmp(optarg, "and") == 0 ){ filter->mode = FILTER_AND; }
				else if ( strcasecmp(optarg, "or")  == 0 ){ filter->mode = FILTER_OR; }
				else {
					fprintf(stderr, "%s: Invalid filter mode `%s'. Ignored.\n", argv[0], optarg);
				}
				break;

			case PARAM_BPF:
				ret = bpf_set(filter, optarg, argv[0]);
				break;

			}
			continue;
		}

		const enum FilterBitmask bitmask = (enum FilterBitmask)op;

		switch (bitmask){
		case FILTER_PORT:
			if ( !parse_port(optarg, &filter->port, &filter->port_mask, "tp.port") ){
				continue;
			}
			break;

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
			break;

		case FILTER_IP_DST:
			if ( !parse_inet_addr(optarg, &filter->ip_dst, &filter->ip_dst_mask, "ip.dst") ){
				continue;
			}
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

		case FILTER_FRAME_MAX_DT:
			if ( timepico_from_string(&filter->frame_max_dt, optarg) != 0 ){
				fprintf(stderr, "Invalid time passed to --%s: %s. Ignoring.", options[index].name, optarg);
				continue;
			}
			break;

		default:
			fprintf(stderr, "op: %d\n", op);
		}

		/* update index bitmask */
		filter->index |= bitmask;
	}

	/* restore getopt */
	opterr = opterr_save;
	optind = optind_save;

	/* save argc */
	*argcptr = argc;
	return ret;
}

int filter_close(struct filter* filter){
#ifdef HAVE_PCAP
	struct bpf_program prg = {0, filter->bpf_insn};
	pcap_freecode(&prg);
	free(filter->bpf_expr);
#endif
	return 0;
}

void filter_src_port_set(struct filter* filter, uint16_t port, uint16_t mask){
	filter->index |= FILTER_SRC_PORT;
	filter->src_port = port & mask;
	filter->src_port_mask = mask;
}

void filter_dst_port_set(struct filter* filter, uint16_t port, uint16_t mask){
	filter->index |= FILTER_DST_PORT;
	filter->dst_port = port & mask;
	filter->dst_port_mask = mask;
}
