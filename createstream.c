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

#include <linux/if_packet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>



int createstream(struct stream* myStream, const char *address, int protocol, const char *nic){
  struct ifreq ifr;
  int ifindex=0;
  int socket_descriptor=0;
  struct sockaddr_in destination;
  struct ether_addr ethernet_address;

  if(nic!=0) {
    strncpy(ifr.ifr_name, nic, IFNAMSIZ);
  }

  int i=0;
  /* Initialize the structure */
  myStream->type=protocol;
  myStream->readPos=0;
  myStream->myFile=0;
  myStream->mySocket=0;
  myStream->address=0;
  myStream->filename=0;
  myStream->ifindex=0;
  myStream->comment=0;
  for(i=0;i<buffLen;i++){
    myStream->buffer[i]=0;
  }
  if(myStream->FH.comment_size==0){
    myStream->FH.comment_size=0;
    for(i=0;i<200;i++){
      myStream->FH.mpid[i]=0;
    }
  }
  printf("Creating a %d stream. \n",protocol);

  
  switch(protocol){
    case 3: // TCP unicast
      socket_descriptor=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
      if(socket_descriptor<0) {
	perror("Cannot open socket. ");
	return(0);
      }     
      setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));
      destination.sin_family = AF_INET;
      destination.sin_port = htons(LISTENPORT);
      inet_aton(address,&destination.sin_addr);
      if(connect(socket_descriptor,(struct sockaddr*)&(destination),sizeof(destination))!=0){
	perror("Cannot connect TCP socket.");
	return(0);
      }
      printf("Connected.");
      address=(char*)calloc(strlen(address)+1,1);
      strcpy(myStream->address,address); 

      break;

    case 2: // UDP multi/unicast
      socket_descriptor=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
      if(socket_descriptor<0) {
	perror("Cannot open socket. ");
	return(0);
      }     
      setsockopt(socket_descriptor,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));
      setsockopt(socket_descriptor,SOL_SOCKET,SO_BROADCAST,(void*)1,sizeof(int));
      destination.sin_family = AF_INET;
      inet_aton(address,&destination.sin_addr);
      destination.sin_port = htons(LISTENPORT);
      if(connect(socket_descriptor,(struct sockaddr*)&destination,sizeof(destination))!=0){
	perror("Cannot connect UDP socket.");
	return(0);
      }
      address=(char*)calloc(strlen(address)+1,1);
      strcpy(myStream->address,address);
      break;

    case 1: // Ethernet multicast
      socket_descriptor=socket(AF_PACKET, SOCK_RAW, htons(LLPROTO));
      if(socket_descriptor<0) {
	perror("Cannot open socket. ");
	return(0);
      }
      if(ioctl(socket_descriptor, SIOCGIFINDEX, &ifr) == -1 ){
	perror("SIOCGIFINDEX error. ");
	return(0);
      }
      ifindex=ifr.ifr_ifindex;
      eth_aton(&ethernet_address, address);
      struct packet_mreq mcast;
      mcast.mr_ifindex = ifindex;
      mcast.mr_type = PACKET_MR_MULTICAST;
      mcast.mr_alen = ETH_ALEN;
      memcpy(mcast.mr_address, &ethernet_address, ETH_ALEN);
      if(setsockopt(socket_descriptor, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mcast,sizeof(mcast))==-1){
	perror("Adding multicast address failed..");
	return(0);
      }
      struct sockaddr_ll sll;
      sll.sll_family=AF_PACKET;
      sll.sll_ifindex=ifindex;
      sll.sll_protocol=htons(LLPROTO);
      sll.sll_pkttype=PACKET_MULTICAST;
      memcpy(sll.sll_addr, &ethernet_address, ETH_ALEN);
      if (bind(socket_descriptor, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
	perror("Binding to interface.");
	return(0);
      }
      printf("Ethernet Multicast\nEthernet.type=%04X\Ethernet.dst=%02X:%02X:%02X:%02X:%02X:%02X\nInterface=%s\n", LLPROTO
	     ,mcast.mr_address[0], mcast.mr_address[1], mcast.mr_address[2]
	     ,mcast.mr_address[3], mcast.mr_address[4], mcast.mr_address[5]
	     ,nic);

      myStream->address = (char*)malloc(7); /* 6 chars + null terminator */
      strncpy(myStream->address, (char*)&ethernet_address, ETH_ALEN);
      break;
    case 0:
    default:
      myStream->myFile=fopen64(address,"wb");
      if(myStream->myFile==NULL) {
	perror("open input failed");
	return 0;
      }
      char com[20]="No Comment";
      myStream->FH.version.major=VERSION_MAJOR;
      myStream->FH.version.minor=VERSION_MINOR;
      myStream->FH.comment_size=strlen(com);
      fwrite(&(myStream->FH),1,sizeof(struct file_header), myStream->myFile);
      fwrite(&com,1, strlen(com),myStream->myFile);
      return(1);
      break;
  } 

  myStream->mySocket=socket_descriptor;
  myStream->ifindex=ifindex;


  
  return(1);
  
}
