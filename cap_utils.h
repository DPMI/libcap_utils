/***************************************************************************
                          cap_utils.h  -  description
                             -------------------
    begin                : Fri Jan 31 2003
    copyright            : (C) 2003 by Anders Ekberg, 
    			 : (C) 2004 by Patrik Carlsson
    email                : anders.ekberg@bth.se
    			 : Patrik.Carlsson@bth.se
 ***************************************************************************/
/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#undef __CYGWIN
#ifdef __CYGWIN
#define fpos64_t fpos_t 	/* Cygwin >1.5 uses 64bit file operators by default */
#define fopen64 fopen
#define fclose64 fclose
#define fread64 fread
#define fwrite64 fwrite
#define fgetpos64 fgetpos
#define fsetpos64 fsetpos

#ifndef IPPROTO_GRE 
 #define IPPROTO_GRE 47	/* Apparently the Cygwin includes doesnt include this one. */
#endif
#endif


#ifndef CAP_UTILS
#define CAP_UTILS
#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#define VERSION "0.5"
#define VERSION_MAJOR 0
#define VERSION_MINOR 5
#define LLPROTO 0x0810
#define LISTENPORT 0x0810
#define PKT_CAPSIZE 96              //Maximum nr of bytes captured from each packet


// Time struct for precision down to picoseconds
struct picotime {
    time_t tv_sec;
    uint64_t tv_psec;
} __attribute__((packed));

typedef struct picotime timepico;

// Struct with the version of this libraryfile
// A simple structure used to store a version number. 
// The number is divided into a major and minor number. 
struct file_version{
  int major;
  int minor;
};

// File header, when a cap file is stored to disk. This header is placed first. 
// The header has two parts, header and comment. After the comment the frames 
// are stored. 
struct file_header{
  int comment_size;                     // How large is the comment
  struct file_version version;          // What version was used to store this file
  char mpid[200];                       // Which MP(or MPs) created this file. 
};

// Capture Header. This header is attached to each packet that we keep, i.e. it matched a filter.
//
//
struct cap_header{ 
  char nic[8];                          // Identifies the CI where the frame was caught
  char mampid[8];                       // Identifies the MP where the frame was caught, 
  timepico ts;                          // Identifies when the frame was caught
  int len;                              // Identifies the lenght of the frame
  int caplen;                           // Identifies how much of the frame that we find here
};
typedef struct cap_header  cap_head;


//Filter struct are base on binary indexing in filter.index
//Ex. to filter on source and destination adresses the index would look like:
// 1000 0000 0000 0000 0000 0000 0011 1100
// and the fields src_mask, dst_mask, src_ip and dst_ip contains the information
struct filter{
  u_int32_t index;			//{2^31}

  timepico starttime;			//{4096}    st
  timepico endtime;			//{2048}    et
  char mampid[8];                       //{1024]    mpid
  char nic[8];        			//{512}     if
  u_int16_t vlan;                       //{256}     eth.vlan
  u_int16_t eth_type;  			//{128}     eth.type
  unsigned char eth_src[6];             //{64}      eth.src
  unsigned char eth_dst[6];             //{32}      eth.dst
  u_int8_t ip_proto;  			//{16}      ip.proto
  char ip_src[16];    			//{8}       ip.src
  char ip_dst[16];    			//{4}       ip.dst
  u_int16_t tp_sport; 			//{2}       tp.port
  u_int16_t tp_dport; 			//{1}       tp.port

  u_int16_t vlan_mask;                  //
  u_int16_t eth_type_mask;              //
  unsigned char eth_src_mask[6];        //
  unsigned char eth_dst_mask[6];        //
  char ip_src_mask[16];			//
  char ip_dst_mask[16];			//
  u_int16_t tp_sport_mask;              //
  u_int16_t tp_dport_mask;              //

};

// Send Structure, used infront of each send data packet. The sequence number is indicates the number
// of sent data packets. I.e. after a send packet this value is increased by one. 
// 
struct sendhead {
  long sequencenr;                      // Sequence number.
  int nopkts;                           // How many packets are here.
  int flush;                            // Indicate that this is the last packet.
  struct file_version version;          // What version of the file format is used for storing mp_pkts.
};

// Stream structure, used to manage different types of streams
//
//
struct stream{
  int type;                             // What type of stream do we have?
                                        // 0, a file
                                        // 1, ethernet multicast
                                        // 2, udp uni/multi-cast
                                        // 3, tcp unicast
  FILE *myFile;                         // File pointer
  
  int mySocket;                         // Socket descriptor  
  long expSeqnr;                        // Expected sequence number
  long pktCount;                        // Received packets
#define buffLen 10000                   // Buffer size
  char buffer[buffLen];                 // Buffer space
  int bufferSize;                       // Amount of data in buffer.
  int readPos;                          // Read position
  int flushed;                          // Indicate that we got a flush signal.

  char *address;                        // network address to listen, used when opening socket. 
  char *filename;                       // filename
  int portnr;                           // port number to listen to.
  int ifindex;                          // 
  int if_mtu;                           // The MTU of the interface reading udp/ethernet multicasts.

  struct file_header FH;                //
  char *comment;                        //
};


//converts struct timeval to struct timepico (ms->ps)
timepico timeval_to_timepico(struct timeval);

//converts struct timespec to struct timepico (us->ps)
timepico timespec_to_timepico(struct timespec);

//compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
int timecmp(timepico *ts1, timepico *ts2);

//Converts an ASCII representation of an ethernet address to char[6]
int eth_aton(char *dest,char *org);


int openstream(struct stream* myStream,char *address, int protocol, char *nic, int port);
int closestream(struct stream* myStream);
int createstream(struct stream* myStream,char *address, int protocol, char *nic);


int write_post(struct stream* myStream, u_char* data, int size);
int read_post(struct stream* myStream, char** data,struct filter *myFilter);

struct filter* createfilter(int argc, char** argv);
int checkFilter(char* pkt, struct filter* theFilter);

int close_cap_stream(int *SD);
//int read_post_stream(int *SD, u_char* data, int size,long seqnr, char *addr, int proto);
//int read_filter_post_stream(int *SD, u_char* data, int size, struct filter my_filter);

int alloc_buffer(FILE **infile, u_char **data);
int dealloc_buffer(u_char **data);
#endif

/*
This file contains _ALL_ protocol definitions that cap_utils can handle.
We are using this file instead of the system includes just to handle different 
environments, and the small but significant difference between header files from 
"The Regents..." and "The Free...". Furthermore, the library rather static, and 
does not utilize the knowledge that the headers can include. 


*/
#ifndef CU_PROTOCOLS
#define CU_PROTOCOLS

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <features.h>

/* Lets start with ALL defines */
#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#define ETH_HLEN        14              /* Total octets in header.       */
#define ETH_ZLEN        60              /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500            /* Max. octets in payload        */
#define ETH_FRAME_LEN   1514            /* Max. octets in frame sans FCS */

/*
 *      These are the defined Ethernet Protocol ID's.
 */

#define ETH_P_LOOP      0x0060          /* Ethernet Loopback packet     */
#define ETH_P_PUP       0x0200          /* Xerox PUP packet             */
#define ETH_P_PUPAT     0x0201          /* Xerox PUP Addr Trans packet  */
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_X25       0x0805          /* CCITT X.25                   */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#define ETH_P_BPQ       0x08FF          /* G8BPQ AX.25 Ethernet Packet  [ NOT AN O FFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP   0x0a00          /* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT 0x0a01          /* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
#define ETH_P_ATALK     0x809B          /* Appletalk DDP                */
#define ETH_P_AARP      0x80F3          /* Appletalk AARP               */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX       0x8137          /* IPX over DIX                 */
#define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */
#define ETH_P_PPP_DISC  0x8863          /* PPPoE discovery messages     */
#define ETH_P_PPP_SES   0x8864          /* PPPoE session messages       */
#define ETH_P_ATMMPOA   0x884c          /* MultiProtocol Over ATM       */
#define ETH_P_ATMFATE   0x8884          /* Frame-based ATM Transport
                                         * over Ethernet */
/*
 *      Non DIX types. Won't clash for 1500 types.
 */
 
#define ETH_P_802_3     0x0001          /* Dummy type for 802.3 frames  */
#define ETH_P_AX25      0x0002          /* Dummy protocol id for AX.25  */
#define ETH_P_ALL       0x0003          /* Every packet (be careful!!!) */
#define ETH_P_802_2     0x0004          /* 802.2 frames                 */
#define ETH_P_SNAP      0x0005          /* Internal only                */
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only     */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009          /* Localtalk pseudo type        */
#define ETH_P_PPPTALK   0x0010          /* Dummy type for Atalk over PPP*/
#define ETH_P_TR_802_2  0x0011          /* 802.2 frames                 */
#define ETH_P_MOBITEX   0x0015          /* Mobitex (kaz@cafe.net)       */
#define ETH_P_CONTROL   0x0016          /* Card specific control frames */
#define ETH_P_IRDA      0x0017          /* Linux-IrDA                   */
#define ETH_P_ECONET    0x0018          /* Acorn Econet                 */
#define ETH_P_HDLC      0x0019          /* HDLC frames                  */

/*
 *      This is an Ethernet frame header.
 */
 
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
#define ETHERTYPE_IP            0x0800          /* IP */
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */

#define ETHER_ADDR_LEN  ETH_ALEN                 /* size of ethernet addr */
#define ETHER_TYPE_LEN  2                        /* bytes in type field */
#define ETHER_CRC_LEN   4                        /* bytes in CRC field */
#define ETHER_HDR_LEN   ETH_HLEN                 /* total octets in header */
#define ETHER_MIN_LEN   (ETH_ZLEN + ETHER_CRC_LEN) /* min packet length */
#define ETHER_MAX_LEN   (ETH_FRAME_LEN + ETHER_CRC_LEN) /* max packet length */

/* make sure ethenet length is valid */
#define ETHER_IS_VALID_LEN(foo) \
        ((foo) >= ETHER_MIN_LEN && (foo) <= ETHER_MAX_LEN)

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define ETHERTYPE_TRAIL         0x1000          /* Trailer packet */
#define ETHERTYPE_NTRAILER      16

#define ETHERMTU        ETH_DATA_LEN
#define ETHERMIN        (ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)

/*------------------------------------*/
/* flag bits for ipt_flg */
#define IPOPT_TS_TSONLY         0               /* timestamps only */
#define IPOPT_TS_TSANDADDR      1               /* timestamps and addresses */
#define IPOPT_TS_PRESPEC        3               /* specified modules only */

/* bits for security (not byte swapped) */
#define IPOPT_SECUR_UNCLASS     0x0000
#define IPOPT_SECUR_CONFID      0xf135
#define IPOPT_SECUR_EFTO        0x789a
#define IPOPT_SECUR_MMMM        0xbc4d
#define IPOPT_SECUR_RESTR       0xaf13
#define IPOPT_SECUR_SECRET      0xd788
#define IPOPT_SECUR_TOPSECRET   0x6bc5

/*
 * Internet implementation parameters.
 */
#define MAXTTL          255             /* maximum time to live (seconds) */
#define IPDEFTTL        64              /* default ttl, from RFC 1340 */
#define IPFRAGTTL       60              /* time to live for frags, slowhz */
#define IPTTLDEC        1               /* subtracted when forwarding */

#define IP_MSS          576             /* default maximum segment size */

#ifdef _IP_VHL
#define IP_MAKE_VHL(v, hl)      ((v) << 4 | (hl))
#define IP_VHL_HL(vhl)          ((vhl) & 0x0f)
#define IP_VHL_V(vhl)           ((vhl) >> 4)
#define IP_VHL_BORING           0x45
#endif

#define IP_MAXPACKET    65535           /* maximum packet size */

/*
 * Definitions for IP type of service (ip_tos)
 */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY          0x10
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_RELIABILITY       0x04
#endif
#define IPTOS_MINCOST           0x02
/* ECN bits proposed by Sally Floyd */
#define IPTOS_CE                0x01    /* congestion experienced */
#define IPTOS_ECT               0x02    /* ECN-capable transport */


/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00

/*
 * Definitions for options.
 */
#define IPOPT_COPIED(o)         ((o)&0x80)
#define IPOPT_CLASS(o)          ((o)&0x60)
#define IPOPT_NUMBER(o)         ((o)&0x1f)

#define IPOPT_CONTROL           0x00
#define IPOPT_RESERVED1         0x20
#define IPOPT_DEBMEAS           0x40
#define IPOPT_RESERVED2         0x60

#define IPOPT_EOL               0               /* end of option list */
#define IPOPT_NOP               1               /* no operation */

#define IPOPT_RR                7               /* record packet route */
#define IPOPT_TS                68              /* timestamp */
#define IPOPT_SECURITY          130             /* provide s,c,h,tcc */
#define IPOPT_LSRR              131             /* loose source route */
#define IPOPT_SATID             136             /* satnet id */
#define IPOPT_SSRR              137             /* strict source route */
#define IPOPT_RA                148             /* router alert */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define IPOPT_OPTVAL            0               /* option ID */
#define IPOPT_OLEN              1               /* option length */
#define IPOPT_OFFSET            2               /* offset within option */
#define IPOPT_MINOFF            4               /* min value of above */

/* Added by Wu Yongwei */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   1234
#define BIG_ENDIAN      4321
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER      LITTLE_ENDIAN
#endif
#define IPVERSION       4


/*
 * User-settable options (used with setsockopt).
 */
#define TCP_NODELAY      1      /* Don't delay send to coalesce packets  */
#define TCP_MAXSEG       2      /* Set maximum segment size  */
#define TCP_CORK         3      /* Control sending of partial frames  */
#define TCP_KEEPIDLE     4      /* Start keeplives after this period */
#define TCP_KEEPINTVL    5      /* Interval between keepalives */
#define TCP_KEEPCNT      6      /* Number of keepalives before death */
#define TCP_SYNCNT       7      /* Number of SYN retransmits */
#define TCP_LINGER2      8      /* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT 9      /* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP 10     /* Bound advertised window */
#define TCP_INFO         11     /* Information about this connection. */
#define TCP_QUICKACK     12     /* Bock/reenable quick ACKs.  */

/* Ethernet Header */
struct ethhdr{
        unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
        unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
        unsigned short  h_proto;                /* packet type ID field */
};

/* Ethernet VLAN Header */
struct ether_vlan_header{
  u_int8_t  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  u_int8_t  ether_shost[ETH_ALEN];	/* source ether addr	*/
  u_int16_t vlan_proto;		        // vlan is present if feild begins with 0x8100
  u_int16_t vlan_tci;		        // vlan is present if feild begins with 0x8100
  u_int16_t h_proto;                    // Ethernet payload protocol 
};


/*------------------------------------------------*/
/* IP Header */
/*------------------------------------------------*/

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */

/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#ifdef _IP_VHL
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
#else
#if BYTE_ORDER == LITTLE_ENDIAN
        u_int   ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
        u_int   ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
#endif /* not _IP_VHL */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};



/* UDP Header */
/* UDP header as specified by RFC 768, August 1980. */
struct udphdr {
  u_int16_t     source;			/* source port */
  u_int16_t     dest;			/* destination port */
  u_int16_t     len;			/* udp length */
  u_int16_t     check;			/* udp checksum */
};
#define SOL_UDP            17      	/* sockopt level for UDP */




/* TCP Header 
 * Per RFC 793, September, 1981.
 */

struct tcphdr{
    u_int16_t source;		/* source port */
    u_int16_t dest;		/* destination port */
    u_int32_t seq;		/* sequence number */
    u_int32_t ack_seq;		/* acknowledgement number */
#if BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;		/* (unused) */
    u_int16_t doff:4;		/* data offset */
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#endif
#if BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;		/* data offset */
    u_int16_t res1:4;		/* data offset */
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#endif
    u_int16_t window;		/* window */
    u_int16_t check;		/* checksum */
    u_int16_t urg_ptr;		/* urgent pointer */
};

struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18




#endif /*CU_PROTOCOLS*/
