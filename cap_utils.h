/***************************************************************************
                          cap_utils.h  -  description
                             -------------------
    begin                : Fri Jan 31 2003
    copyright            : (C) 2003 by Anders Ekberg, 
    			 : (C) 2005 by Patrik Arlos
    email                : anders.ekberg@bth.se
    			 : Patrik.Arlos@bth.se
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
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <ctype.h>
#define VERSION "0.5.1"
#define VERSION_MAJOR 0
#define VERSION_MINOR 5
#define LLPROTO 0x0810
#define LISTENPORT 0x0810
#define PKT_CAPSIZE 96              //Maximum nr of bytes captured from each packet

/* Protocol definitions */
enum protocol_t {
  PROTOCOL_LOCAL_FILE = 0,
  PROTOCOL_ETHERNET_MULTICAST,
  PROTOCOL_UDP_MULTICAST,
  PROTOCOL_TCP_UNICAST,
};

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
  uint32_t len;                              // Identifies the lenght of the frame
  uint32_t caplen;                           // Identifies how much of the frame that we find here
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

  /* Callback functions */
  int (*fill_buffer)(struct stream* st);
  int (*destroy)(struct stream* st);
};

struct ether_vlan_header{
  u_int8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  u_int16_t vlan_proto;             /* vlan is present if feild begins with 0x8100 */
  u_int16_t vlan_tci;               /* vlan is present if feild begins with 0x8100 */
  u_int16_t h_proto;                /* Ethernet payload protocol */
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


int is_valid_version(struct file_header* fhptr);
int stream_file_init(struct stream* st, const char* filename);

#endif /* CAP_UTILS */
