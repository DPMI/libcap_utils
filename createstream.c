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
  char *address; A pointer to a string identifying the address/file we try to open.
  int  protocol; Transport mode, 
  0 -- Local file
  1 -- Ethernet multicast
  2 -- UDP multi/uni-cast
  3 -- TCP unicast ??
  char *nic; A pointer to a string identifying the interface to listen to. (NULL if a file)

OUTPUT:
  int 0 if fail
  int 1 if ok.
*/

#include "caputils/caputils.h"
#include "caputils_int.h"

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <features.h>

#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

long createstream_file(struct stream** stptr, FILE* file, const char* filename, const char* mpid, const char* comment){
  return stream_file_create(stptr, file, filename, mpid, comment);
}

long createstream(struct stream** stptr, const destination_t* dest, const char* nic, const char* mpid, const char* comment){
  /* struct ifreq ifr; */
  /* int ifindex=0; */
  /* int socket_descriptor=0; */
  /* int ret; */
  /* struct sockaddr_in destination; */
  /* struct ether_addr ethernet_address; */

  switch ( dest->type ){
  case PROTOCOL_ETHERNET_MULTICAST:
    return stream_ethernet_create(stptr, &dest->ether_addr, nic, mpid, comment);

  case PROTOCOL_LOCAL_FILE:
    return stream_file_create(stptr, NULL, (dest->flags & DEST_LOCAL) ? dest->local_filename : dest->filename, mpid, comment);

  default:
    return ERROR_NOT_IMPLEMENTED;
  }


  /* switch(protocol){ */
  /*   case 3: // TCP unicast */
  /*     socket_descriptor=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); */
  /*     if(socket_descriptor<0) { */
  /* 	perror("Cannot open socket. "); */
  /* 	return(0); */
  /*     }      */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
  /*     destination.sin_family = AF_INET; */
  /*     destination.sin_port = htons(LISTENPORT); */
  /*     inet_aton(address,&destination.sin_addr); */
  /*     if(connect(socket_descriptor,(struct sockaddr*)&(destination),sizeof(destination))!=0){ */
  /* 	perror("Cannot connect TCP socket."); */
  /* 	return(0); */
  /*     } */
  /*     printf("Connected."); */
  /*     address=(char*)calloc(strlen(address)+1,1); */
  /*     strcpy(st->address,address);  */

  /*     break; */

  /*   case 2: // UDP multi/unicast */
  /*     socket_descriptor=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); */
  /*     if(socket_descriptor<0) { */
  /* 	perror("Cannot open socket. "); */
  /* 	return(0); */
  /*     }      */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int)); */
  /*     setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int)); */
  /*     destination.sin_family = AF_INET; */
  /*     inet_aton(address,&destination.sin_addr); */
  /*     destination.sin_port = htons(LISTENPORT); */
  /*     if(connect(socket_descriptor,(struct sockaddr*)&destination,sizeof(destination))!=0){ */
  /* 	perror("Cannot connect UDP socket."); */
  /* 	return(0); */
  /*     } */
  /*     address=(char*)calloc(strlen(address)+1,1); */
  /*     strcpy(st->address,address); */
  /*     break; */

  /*   case 1: // Ethernet multicast */
  /*   case 0: */
  /*   default: */
  /* }  */

  /* //  st->mySocket=socket_descriptor; */
  /* //  st->ifindex=ifindex; */
  
  /* return(1);   */
}
