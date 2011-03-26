/***************************************************************************
                          filter.c  -  description
                             -------------------
    begin                : Mnn Aug 1 2004
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
 This function reads a captured packet from the file and stores it in data.
  The function returns 1 until the file ends and a 0 is returned.
 ***************************************************************************/
#include "caputils/caputils.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

int matchEth(char desired[6],char mask[6], char net[6]){
  int i;
  for(i=0;i<6;i++){
    if((net[i]&mask[i])!=desired[i]){
       break;
    }
  }
  if(i==6)
    return(1);
  return(0);
}



int checkFilter(char *pkt, const struct filter* theFilter){
/*
  printf("f:theFilter        = %p \n", theFilter);
  if(theFilter!=NULL){
    printf("f:theFilter->index = %u \n",theFilter->index);
  }
*/
  struct cap_header *head;
  struct ether_vlan_header *vlan_hdr;
  struct ethhdr *eth_hdr;
  struct ip *ip_hdr;
  struct tcphdr *tcp_hdr;
  struct udphdr *udp_hdr;
  int match=1;
  int VLAN_PRESENT=0;
  int packetLength=0;

  if(theFilter==0){
    printf("No filter present. EXIT.\n");
    return(1);
  }

// If no filters are present, all packet are correct.
//  printf("filter()\ntheFilter.index=%d\n",theFilter->index);
  if(theFilter->index==0) {
//    printf("Filter present, all frames match.EXIT\n");
    return(1);
  }

  


  head=(cap_head*)pkt;
  packetLength=head->caplen;
/* A length of 
   14 allows us to work on the Ethernet header 
   34 allows us to work on the IP header
   54 allows us to work on the IP,TCP header
   42 allows us to work on the IP,UDP header
   74 allows us to work on the IP+options, TCP header
   62 allows us to work on the IP+options, UDP header
   94 allows us to work on the IP+options, TCP+options header
   +2 to handle VLAN. 
*/

  if(theFilter->index&(2+1)){//The filter requires Transport level information
    if(packetLength<42){// We do not have TP level information.
      return(0);
    }
  }
  if(theFilter->index&(16+8+4)){// The filter requires Network level information
    if(packetLength<34){ // We do not have Network level information
      return(0);
    }
  }
  if(theFilter->index&(128+64+32)){// The filter requires Link level information
    if(packetLength<14){// We do not have Link level information
      return(0);
    }
  }



// filter on start time
  if(theFilter->index&4096 && (theFilter->index&2048)==0) {
    if(timecmp(&theFilter->starttime,&head->ts)<1) {
      match*=1;
    } else {
      return(0);
    }
  }
// filter on end time
  if(theFilter->index&2048 && (theFilter->index&4096)==0) {
    if(timecmp(&theFilter->endtime,&head->ts)<1){
      return(0);
    } else {
      match*=1;
    }
  }
  
// filter on both start and end time
  if(theFilter->index&2048 && theFilter->index&4096) {
    if(timecmp(&theFilter->starttime,&head->ts)<1) {
      if(timecmp(&theFilter->endtime,&head->ts)<1){
	return(0);
      } else {
	match*=1;
      }
    } else {
      return(0);
    }
  }
// filter on MAMPid
  if((theFilter->index&1024) && (match==1)){
    if(!(strcmp(theFilter->mampid,head->mampid)==0))
      return(0);
    else
      match*=1;
  }
  

// filter on Nic
  if((theFilter->index&512) && (match==1)){
    if(!(strcmp(theFilter->nic,head->nic)==0))
      return(0);
    else
      match*=1;
  }
  

//are the packets captured on a vlan? add vlan header.
  if((packetLength>=14)){
    eth_hdr=(struct ethhdr*)(pkt+sizeof(cap_head));
    if(packetLength>=14 && ntohs(eth_hdr->h_proto)==0x8100)
      VLAN_PRESENT=4;
    else
      VLAN_PRESENT=0;
  }
//filter on vlan
  if((packetLength>=14)&&(VLAN_PRESENT==4)&&(theFilter->index&256)&&(match==1)){
    vlan_hdr=(struct ether_vlan_header*)(pkt+sizeof(cap_head));
    if(!((theFilter->vlan)==(ntohs(vlan_hdr->vlan_tci)&theFilter->vlan_mask)))
      return(0);
    else
      match*=1;
  }
  
//filter on ethertype
  if((packetLength>=14)&&(theFilter->index&128)&&(match==1)) {
    eth_hdr=(struct ethhdr*)(pkt+sizeof(cap_head)+VLAN_PRESENT);
    if(!(theFilter->eth_type==(ntohs(eth_hdr->h_proto)&theFilter->eth_type_mask)))
      return(0);
    else
      match*=1;
  }

//filter on ethernet source
  if((packetLength>=14)&&(theFilter->index&64)&&(match==1)){
   eth_hdr=(struct ethhdr*)(pkt+sizeof(cap_head)+VLAN_PRESENT);
   if(matchEth(theFilter->eth_src,theFilter->eth_src_mask,eth_hdr->h_source)==0)
     return(0);
    else
      match*=1;
  }
//filter on ethernet destination
  if((theFilter->index&32)&&(match==1)){
   eth_hdr=(struct ethhdr*)(pkt+sizeof(cap_head)+VLAN_PRESENT);
   if(matchEth(theFilter->eth_src,theFilter->eth_dst_mask, eth_hdr->h_dest)==0)
      return(0);
    else
      match*=1;
  }

//filter on ip protocol
  if((packetLength>=34)&&(theFilter->index&16)&&(match==1)) {
    ip_hdr=(struct ip*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+VLAN_PRESENT);
//    printf("pkt.ip.proto = %d <> %d theFilter.ip_proto \n", ip_hdr->ip_p,theFilter->ip_proto);
    if(!(theFilter->ip_proto==ip_hdr->ip_p))
      return(0);
    else
      match*=1;
  }
//filter on ip.source
  if((packetLength>=34)&&(theFilter->index&8)&&(match==1)) {
    ip_hdr=(struct ip*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+VLAN_PRESENT);
    if(!((ip_hdr->ip_src.s_addr&inet_addr(theFilter->ip_src_mask))==inet_addr(theFilter->ip_src)))
      return(0);
    else
      match*=1;
  }
//filter on destination
  if(((packetLength>=34)&&theFilter->index&4)&&(match==1)) {
    ip_hdr=(struct ip*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+VLAN_PRESENT);
    if(!((ip_hdr->ip_dst.s_addr&inet_addr(theFilter->ip_dst_mask))==inet_addr(theFilter->ip_dst)))
      return(0);
    else
      match*=1;
  }
//filter on source port
  if((packetLength>=42)&&(theFilter->index&2)&&(match==1)) {
    ip_hdr=(struct ip*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+VLAN_PRESENT);
    if(IPPROTO_UDP==ip_hdr->ip_p) {
      udp_hdr=(struct udphdr*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+4*(ip_hdr->ip_hl)+VLAN_PRESENT);
      if(!(theFilter->tp_sport==(ntohs(udp_hdr->source)&theFilter->tp_sport_mask))) {
	return(0);
      } else{
	match*=1;
      }
    } else if(IPPROTO_TCP==ip_hdr->ip_p) {
      tcp_hdr=(struct tcphdr*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+4*(ip_hdr->ip_hl)+VLAN_PRESENT);
      if(!(theFilter->tp_sport==(ntohs(tcp_hdr->source)&theFilter->tp_sport_mask))) {
	return(0);
      } else {
	match*=1;
      }
    }
    else
      return(0);
  }
//filter on detination port
  if((packetLength>=42)&&(theFilter->index&1)&&(match==1)) {
    ip_hdr=(struct ip*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+VLAN_PRESENT);
    if(IPPROTO_UDP==ip_hdr->ip_p) {
      udp_hdr=(struct udphdr*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+4*(ip_hdr->ip_hl)+VLAN_PRESENT);
      if(!(theFilter->tp_dport==(ntohs(udp_hdr->dest)&theFilter->tp_dport_mask))){
	return(0);
      } else {
	match*=1;
      }
    } else if(IPPROTO_TCP==ip_hdr->ip_p) {
      tcp_hdr=(struct tcphdr*)(pkt+sizeof(cap_head)+sizeof(struct ethhdr)+4*(ip_hdr->ip_hl)+VLAN_PRESENT);
      if(!(theFilter->tp_dport==(ntohs(tcp_hdr->dest)&theFilter->tp_dport_mask))){
	return(0);
      } else {
	match*=1;
      }
    } else {
      return(0);
    }
  }
//  printf("\nMatched all %u \n",theFilter->index);
  return(match);
  
}
