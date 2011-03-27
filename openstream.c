/***************************************************************************
                          openstream.c  -  description
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
/***************************************************************************
 This function opens a large file (64bits) and reads the fileheader
 described in caputils/caputils.h. the file pointer the points to the first packet.
 Function returns 1 if success and 0 if open failed.
 ***************************************************************************/

/*
INPUT:
  struct stream *myStream; Pointer to a struct handling the stream. 
  char *address;           A pointer to a string identifying the address/file we try to open.
  int  protocol;           Transport mode, 
                           0 -- Local file
			   1 -- Ethernet multicast
			   2 -- UDP multi/uni-cast
			   3 -- TCP unicast ??
  char *nic;               A pointer to a string identifying the interface to listen to. (NULL if a file)
  int port;                Port to listen to, incase of UDP or TCP. Not used for ethernet.

OUTPUT:
  int 0 if fail
  int 1 if ok.
*/

#include "caputils/caputils.h"
#include "caputils_int.h"
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <features.h>

#include <signal.h>
#include <getopt.h>
#include <unistd.h>

//#include <netpacket/packet.h>
#include <linux/if_packet.h>
//#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

/**
 * Validates the file_header version against libcap_utils version. Prints
 * warning to stderr if version mismatch.
 * @return Non-zero if version is valid.
 */
int is_valid_version(struct file_header* fhptr){
  if( fhptr->version.major <= VERSION_MAJOR && fhptr->version.minor <= VERSION_MINOR ) {
    return 1;
  }

  fprintf(stderr,"Stream uses version %d.%d, this application uses ", fhptr->version.major, fhptr->version.minor);
  fprintf(stderr,"Libcap_utils version " VERSION "\n");
  fprintf(stderr,"Change libcap version or convert file.\n");
  return 0;
}

int openstream(struct stream *myStream, const char* address, int protocol, const char* nic, int port){
  int ret = 0;

  /* Initialize the structure */
  if ( (ret=stream_init(myStream, protocol, port)) != 0 ){
    errno = ret;
    return 0;
  }

  switch(protocol){
    case PROTOCOL_TCP_UNICAST:
      ret = stream_tcp_init(myStream, address, port);
      break;

    case PROTOCOL_UDP_MULTICAST:
      ret = stream_udp_init(myStream, address, port);
      break;

    case PROTOCOL_ETHERNET_MULTICAST:
      ret = stream_ethernet_init(myStream, address, nic);
      break;
    case PROTOCOL_LOCAL_FILE:
      ret = stream_file_init(myStream, address);
      break;

    default:
      fprintf(stderr, "Unhandled protocol %d\n", protocol);
      return 0;
  }

  /* initialize a file stream */
  if ( ret != 0 ){
    errno = ret;
    return 0;
  }

  return 1;
}
