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

#include <caputils/version.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <net/ethernet.h>

#define LLPROTO 0x0810
#define LISTENPORT 0x0810
#define buffLen 10000                   // Buffer size

/* Protocol definitions */
enum protocol_t {
  PROTOCOL_LOCAL_FILE = 0,
  PROTOCOL_ETHERNET_MULTICAST,
  PROTOCOL_UDP_MULTICAST,
  PROTOCOL_TCP_UNICAST,
};

// Time struct for precision down to picoseconds
struct picotime {
    uint32_t tv_sec;
    uint64_t tv_psec;
} __attribute__((packed));

typedef struct picotime timepico;

// Struct with the version of this libraryfile
// A simple structure used to store a version number. 
// The number is divided into a major and minor number. 
struct file_version{
  uint16_t major;
  uint16_t minor;
};

// File header, when a cap file is stored to disk. This header is placed first. 
// The header has two parts, header and comment. After the comment the frames 
// are stored. 
struct file_header_t {
  /* Magic number to identify capfiles. (nowadays 8 bytes are recommended due to
   * the large number of formats available). */
  uint64_t magic;

  /*  What version was used to store this file */
  struct file_version version;
  
  /* sizeof(header) so future revisions of this header can be made without
   * breaking older files too much. E.g fill in missing fields based on version
   * and seek to the right location. */
  uint16_t header_offset;

  /* Length of the comment string */
  uint16_t comment_size;

  /* MP(s) ID */
  char mpid[200];
};

struct file_header_06 {
  uint32_t comment_size;
  struct {
    uint8_t major;
    uint8_t minor;
  } version;
  char mpid[200];
};

struct file_header_05 {
  uint32_t comment_size;
  struct {
    uint32_t major;
    uint32_t minor;
  } version;
  char mpid[200];
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

  /* convenience accessor (since array size is 0 it won't affect sizeof) */
  char payload[0];
};
typedef struct cap_header  cap_head;


//Filter struct are base on binary indexing in filter.index
//Ex. to filter on source and destination adresses the index would look like:
// 1000 0000 0000 0000 0000 0000 0011 1100
// and the fields src_mask, dst_mask, src_ip and dst_ip contains the information
struct filter{
  uint32_t index;			//{2^31}

  timepico starttime;			//{4096}    st
  timepico endtime;			//{2048}    et
  char mampid[8];                       //{1024]    mpid
  char nic[8];        			//{512}     if
  uint16_t vlan;                       //{256}     eth.vlan
  uint16_t eth_type;  			//{128}     eth.type
  struct ether_addr eth_src;             //{64}      eth.src
  struct ether_addr eth_dst;             //{32}      eth.dst
  uint8_t ip_proto;  			//{16}      ip.proto
  char ip_src[16];    			//{8}       ip.src
  char ip_dst[16];    			//{4}       ip.dst
  uint16_t tp_sport; 			//{2}       tp.port
  uint16_t tp_dport; 			//{1}       tp.port

  uint16_t vlan_mask;                  //
  uint16_t eth_type_mask;              //
  struct ether_addr eth_src_mask;        //
  struct ether_addr eth_dst_mask;        //
  char ip_src_mask[16];			//
  char ip_dst_mask[16];			//
  uint16_t tp_sport_mask;              //
  uint16_t tp_dport_mask;              //

};

// Send Structure, used infront of each send data packet. The sequence number is indicates the number
// of sent data packets. I.e. after a send packet this value is increased by one. 
// 
struct sendhead {
  uint32_t sequencenr;                      // Sequence number.
  uint32_t nopkts;                           // How many packets are here.
  uint32_t flush;                            // Indicate that this is the last packet.
  struct file_version version;          // What version of the file format is used for storing mp_pkts.
};

struct ether_vlan_header{
  uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
  uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
  uint16_t vlan_proto;             /* vlan is present if feild begins with 0x8100 */
  uint16_t vlan_tci;               /* vlan is present if feild begins with 0x8100 */
  uint16_t h_proto;                /* Ethernet payload protocol */
};

#include <caputils/stream.h>

//converts struct timeval to struct timepico (ms->ps)
timepico timeval_to_timepico(struct timeval);

//converts struct timespec to struct timepico (us->ps)
timepico timespec_to_timepico(struct timespec);

//compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
int timecmp(const timepico *ts1, const timepico *ts2);

/**
 * Open an existing stream.
 * @return 1 if successful.
 */
int openstream(struct stream* myStream, const char* address, int protocol, const char* nic, int port);

/**
 * Create a new stream.
 */
int createstream(struct stream* myStream, const char *address, int protocol, const char* nic, const char* mpid, const char* comment);

/**
 * Create a filestream.
 * @param file A stream open for writing.
 * @return Zero on failures.
 */
int createstream_file(struct stream* st, FILE* file, const char* mpid, const char* comment);

/**
 * Close stream.
 */
int closestream(struct stream* myStream);

/**
 * Write a captured frame to a stream.
 */
int write_post(struct stream* myStream, u_char* data, int size);

/**
 * Read the next matching frame from a stream.
 * @param st Stream to read from
 * @param data Returns a pointer to the internal buffer for reading the frame.
 * @param filter Filter to match frames with.
 */
int read_post(struct stream* st, char** data, const struct filter*filter);

struct filter* createfilter(int argc, char** argv);
int closefilter(struct filter* filter);

int close_cap_stream(int *SD);

/**
 * Text representation of error code.
 */
const char* caputils_error_string(int code);

#endif /* CAP_UTILS */
