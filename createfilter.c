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
#include "caputils/caputils.h"
#include "caputils_int.h"

#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

const char * parse_date_time (const char *input, struct tm *tm){
  const char *cp;
  // First clear the result structure.
  memset (tm, '\0', sizeof (*tm));

  cp = strptime (input, "%F %T", tm);//ISO 8601 YYYY-MM-DD hh:mm:ss.x, x can be upto 12 digits
  if(cp == NULL)  {
    cp = strptime (input, "%Y%m%d %T", tm);//YYYYMMDD hh:mm:ss.x, x can be upto 12 digits
  }
  if(cp == NULL)  {
    cp = strptime (input, "%y%m%d %T", tm);//YYMMDD hh:mm:ss.x, x can be upto 12 digits
  }
  if(cp == NULL) {
    cp = strptime(input, "%s", tm);//Seconds since the epoch 1970-01-01 00:00:00 UTC
  }

#ifdef DEBUG
  printf("Input = %s  ==> fractional seconds = %s\n",input,cp);
#endif
  return cp;
}

struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};


struct filter* createfilter(int argc, char** argv){


  static struct option myOptions[]= {
    {"starttime", 1, 0, 4096},     {"A",1,0,4096},
    {"endtime",   1, 0, 2048},     {"B",1,0,2048},
    {"mpid",      1,0,1024},       {"M",1,0,1024},
    {"if",        1, 0, 512},      {"I",1,0,512},
    {"eth.vlan",  1,0,256},        {"C",1,0,256},
    {"eth.type",  1, 0, 128},      {"D",1,0,128},
    {"eth.src",   1,0,64},         {"E",1,0,64},
    {"eth.dst",   1,0,32},         {"F",1,0,32},
    {"ip.proto",  1, 0, 16},       {"N",1,0,16},
    {"ip.src",    1, 0, 8},        {"O",1,0,8},
    {"ip.dst",    1, 0, 4},        {"P",1,0,4},
    {"tp.sport",  1, 0, 2},        {"T",1,0,2},
    {"tp.dport",  1, 0, 1},        {"U",1,0,1},
    {"help",      0, 0, 'h'},      {"h",0,0,'h'}
  };

  
  char longop[3]="--";
  char *lop=longop;

  struct tm tid;
  char* picostring;
  int digits=0;
  char* maskstring=0;

  struct filter *myfilter=(struct filter*)calloc(sizeof(struct filter),1);

//  printf("sizeof myOptions = %d i.e. %d options \n", sizeof(myOptions),sizeof(myOptions)/sizeof(struct option));
  int noOptions=sizeof(myOptions)/sizeof(struct option);

  int op,i,k, optionIndex;
//  printf("option Parser \n");
  for(i=1;i<argc;i++){
//    printf("[%d] = %s\t",i, argv[i]);
    optionIndex=-1;
    if(strstr(argv[i],lop)!=NULL){
//      printf("Long option.\t");
      for(k=0;k<noOptions;k++){
	if(strstr(argv[i],myOptions[k].name)!=NULL){
//	  printf(" <-> %s  --> return %c \n",myOptions[k].name,myOptions[k].val);
	  optionIndex=k;
	  break;
	}
      }
    } else  if(index(argv[i],'-')!=NULL){
//      printf("Short option.\t");
      for(k=0;k<noOptions;k++){
	if(strstr(argv[i],myOptions[k].name)!=NULL){
//	  printf(" <-> %s  --> return %c \n",myOptions[k].name,myOptions[k].val);
	  optionIndex=k;
	  break;
	}
      }
    } else {
      // Incase of an argument 
      optionIndex=-2;
    }
    if(optionIndex==-1){
//      printf("Unknown option.\n");
    } 

    if(optionIndex>-1){ 
      // j indicates which option that was matched.
      op=myOptions[optionIndex].val;
//      printf("-->(%c)%d \t",op,op);
      switch(op){
	case 4096: // Set starttime
	  if(parse_date_time(argv[i+1], &tid)==NULL) {
	    printf("unrecognized start time arg %s\n no rule added",argv[i+1]);
	    break;
	  } else {
	    myfilter->starttime.tv_sec=mktime(&tid);
	    picostring=strchr(argv[i+1],'.');
	    if(picostring!=NULL) {
	      digits=strlen(picostring);
	      myfilter->starttime.tv_psec=atol(picostring+1);
	      while(digits<13) {
		myfilter->starttime.tv_psec=myfilter->starttime.tv_psec*10;
		digits++;
	      }
	    } else {
	      myfilter->starttime.tv_psec=0;
	    }
	    myfilter->index+=4096;
#ifdef DEBUG      
	    printf("Start time: %d.%012"PRId64" \n",(int)myfilter->starttime.tv_sec,myfilter->starttime.tv_psec);
#endif
	  }
	  break;
	  
	case 2048: // Set Endtime
	  if(parse_date_time(argv[i+1], &tid)==NULL) {
	    printf("unrecognized end time arg %s\n no rule added",argv[i+1]);
	    break;
	  } else  {
	    myfilter->endtime.tv_sec=mktime(&tid);
	    picostring=strchr(argv[i+1],'.');
	    if(picostring!=NULL) {
	      digits=strlen(picostring);
	      myfilter->endtime.tv_psec=atol(picostring+1);
	      while(digits<13) {
		myfilter->endtime.tv_psec=myfilter->endtime.tv_psec*10;
		digits++;
	      }
	    } else {
	      myfilter->endtime.tv_psec=0;
	    }
	    myfilter->index+=2048;
	  }
#ifdef DEBUG      
	  printf("End time: %d.%012"PRId64" \n",(int)myfilter->endtime.tv_sec,myfilter->endtime.tv_psec);
#endif
	  break;
	  
	case 1024:// Set MP id
	  strncpy(myfilter->mampid,argv[i+1],8);
	  myfilter->index+=1024;
#ifdef DEBUG
	  printf("mpid = %s\n",myfilter->mampid);
#endif	  
	  break;

	case 512:// Set Nic
	  myfilter->index+=512;
	  strncpy(myfilter->nic,argv[i+1],8);
#ifdef DEBUG
	  printf("if = %s\n",myfilter->nic);
#endif
	  break;

	case 256:// Set vlan 
	  myfilter->index+=256;
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    myfilter->vlan_mask=65535;
	  } else {
	    myfilter->vlan_mask=atoi(maskstring+1);
	    *(maskstring)='\0';
	  }
	  myfilter->vlan=atoi(argv[i+1]);
#ifdef DEBUG
	  printf("eth.vlan = %04x / %04x \n",myfilter->vlan,myfilter->vlan_mask);
#endif
	  break;
	  
	case 128:// Set Ethernet type
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){ // No Mask was given
	    myfilter->eth_type_mask=65535;
	  } else { 
	    myfilter->eth_type_mask=atoi(maskstring+1);
	    *(maskstring)='\0';
	  }
	  if(strcmp(argv[i+1],"ip")==0)
	    myfilter->eth_type=ETH_P_IP;
	  else if(strcmp(argv[i+1],"arp")==0)
	    myfilter->eth_type=ETH_P_ARP;
	  else if(strcmp(argv[i+1],"rarp")==0)
	    myfilter->eth_type=ETH_P_RARP;
	  else  {
//	    printf("unrecognized eth arg %s. Will try to parse as an integer value.\n",argv[i+1]);
	    myfilter->eth_type=atoi(argv[i+1]);
	  }
	  myfilter->index+=128;
#ifdef DEBUG
	  printf("eth.type = %04x / %04x \n",myfilter->eth_type, myfilter->eth_type_mask);
#endif
	  break;
	  
	case 64:// Set Ethernet source
	  myfilter->index+=64;
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    eth_aton(&myfilter->eth_src_mask,"FF:FF:FF:FF:FF:FF");
	  } else {
	    eth_aton(&myfilter->eth_src_mask,(maskstring+1));
	    *(maskstring)='\0';
	  }
	  eth_aton(&myfilter->eth_src, argv[i+1]);
	  break;

	case 32:// Set Ethernet destination
	  myfilter->index+=32;
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    eth_aton(&myfilter->eth_dst_mask, "FF:FF:FF:FF:FF:FF");
	  } else {
	    eth_aton(&myfilter->eth_dst_mask, (maskstring+1));
	    *(maskstring)='\0';
	  }
	  eth_aton(&myfilter->eth_dst, argv[i+1]);
	  break;

	case 16:// Set IP protocol
	  if(strcmp(argv[i+1],"tcp")==0)
	    myfilter->ip_proto=IPPROTO_TCP;
	  else if(strcmp(argv[i+1],"udp")==0)
	    myfilter->ip_proto=IPPROTO_UDP;
	  else if(strcmp(argv[i+1],"icmp")==0)
	    myfilter->ip_proto=IPPROTO_ICMP;
	  else if(strcmp(argv[i+1],"gre")==0)
	    myfilter->ip_proto=IPPROTO_GRE;
	  else {
	    printf(" unrecognized ip arg %s. Will try to parse as an integer value.\n",argv[i+1]);
	    myfilter->ip_proto=atoi(argv[i+1]);
	    /*	 break;*/
	  }       
#ifdef DEBUG
	  printf("ip.proto = %02x\n",myfilter->ip_proto);
#endif
	  myfilter->index+=16;
	  break;
	  
	case 8:// Set source host ip, or host net
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    strncpy(myfilter->ip_src_mask,"255.255.255.255",16);
	  } else {
	    strncpy(myfilter->ip_src_mask,(maskstring+1),16);
	    *(maskstring)='\0';
	  }
	  strncpy(myfilter->ip_src,argv[i+1],16);
	  myfilter->index+=8;
#ifdef DEBUG
	  printf("ip.src = %s / %s \n",myfilter->ip_src,myfilter->ip_src_mask);
#endif

	  break;
	  
	case 4:// Set destination host ip, or host net
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    strncpy(myfilter->ip_dst_mask,"255.255.255.255",16);
	  } else {
	    strncpy(myfilter->ip_dst_mask,(maskstring+1),16);
	    *(maskstring)='\0';
	  }
	  strncpy(myfilter->ip_dst,argv[i+1],16);
#ifdef DEBUG
	  printf("ip.dst = %s / %s \n",myfilter->ip_dst,myfilter->ip_dst_mask);
#endif
	  myfilter->index+=4;
	  // Set dst_mask
	  break;
	  
	case 2:// Set source port
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    myfilter->tp_sport_mask=65535;
	  } else {
	    myfilter->tp_sport_mask=atoi(maskstring+1);
	    *(maskstring)='\0';
	  }
	  myfilter->tp_sport=atoi(argv[i+1]);
	  myfilter->index+=2;
#ifdef DEBUG
	  printf("tp.sport = %d / %d \n",myfilter->tp_sport, myfilter->tp_sport_mask);
#endif
	  break;
	  
	case 1:// Set destination port
	  maskstring=index(argv[i+1],'/');
	  if(maskstring==NULL){// No mask was given set default. 
	    myfilter->tp_dport_mask=65535;
	  } else {
	    myfilter->tp_dport_mask=atoi(maskstring+1);
	    *(maskstring)='\0';
	  }
	  myfilter->tp_dport=atoi(argv[i+1]);
#ifdef DEBUG
	  printf("tp.dport = %d / %d \n",myfilter->tp_dport, myfilter->tp_dport_mask);
#endif
	  myfilter->index+=1;
	  break;
	  
	case 'h':
	  printf("Help\nLibcap_utils Version %d.%d\n",VERSION_MAJOR, VERSION_MINOR);
	  printf("Libcap_utils Filter Options\n");
	  printf("-A or --starttime filter on all packets after starttime in ISO-8601 format\n");
	  printf("-B or --endtime   filter on all packets before endtime in ISO-8601 format\n");
	  printf("                  ISO 8601 YYYY-MM-DD hh:mm:ss.x, x can be upto 12 digits,\n");	  
	  printf("-M or --mpid      filter on mpid           \n");
	  printf("-I or --if        filter on networkinterface on MP\n");

	  printf("-C or --eth.vlan  filter on vlan                                   value/[mask]\n");
	  printf("-D or --eth.type  filter on carrier protocol (ip, arp,rarp)        value/[mask]\n");
	  printf("-E or --eth.src   filter on ethernet source                        value/[mask]\n");
	  printf("-F or --eth.dst   filter on ethernet destination                   value/[mask]\n");

	  printf("-N or --ip.proto  filter on ip protocol (tcp, udp, icmp,)          value/[mask]\n");
	  printf("-O or --ip.src    filter on source ip address, dotted decimal      value/[mask]\n");
	  printf("-P or --ip.dst    filter on destination ip address, dotted decimal value/[mask]\n");
	  printf("-T or --tp.sport  filter on source portnumber                      value/[mask]\n");
	  printf("-U or --tp.dport  filter on destination portnumber                 value/[mask]\n");
//	  printf("-h or --help      this text\n");
	  myfilter->index=0;
#ifdef DEBUG 
	  printf("Returning NULL, since help was called.\n");
#endif
	  return(0);
	  break;
	  
	default:
	  printf("No function implemented.\n");
	  break;
      }
      if(myOptions[optionIndex].has_arg==1){
	i++;
      }
    }
  }
  

#ifdef resultFilter
  printf("Returning pointer to this structure\n");
  printf("myfilter.index = %d \n",myfilter->index);
  printf("Start time: %d.%012llu \n",(int)myfilter->starttime.tv_sec,myfilter->starttime.tv_psec);
  printf("End time: %d.%012llu \n",(int)myfilter->endtime.tv_sec,myfilter->endtime.tv_psec);
  printf("mpid = %s\n",myfilter->mampid);
  printf("if = %s\n",myfilter->nic);
  printf("eth.vlan = %04x / %04x \n",myfilter->vlan,myfilter->vlan_mask);
  printf("eth.type = %04x / %04x \n",myfilter->eth_type, myfilter->eth_type_mask);
  printf("eth.src = %02x:%02x:%02x:%02x:%02x:%02x: / %02x:%02x:%02x:%02x:%02x:%02x\n"
	 ,myfilter->eth_src[0],myfilter->eth_src[1],myfilter->eth_src[2]
	 ,myfilter->eth_src[3],myfilter->eth_src[4],myfilter->eth_src[5]
	 ,myfilter->eth_src_mask[0],myfilter->eth_src_mask[1],myfilter->eth_src_mask[2]
	 ,myfilter->eth_src_mask[3],myfilter->eth_src_mask[4],myfilter->eth_src_mask[5]);
  printf("eth.dst = %02x:%02x:%02x:%02x:%02x:%02x: / %02x:%02x:%02x:%02x:%02x:%02x\n"
	 ,myfilter->eth_dst[0],myfilter->eth_dst[1],myfilter->eth_dst[2]
	 ,myfilter->eth_dst[3],myfilter->eth_dst[4],myfilter->eth_dst[5]
	 ,myfilter->eth_dst_mask[0],myfilter->eth_dst_mask[1],myfilter->eth_dst_mask[2]
	 ,myfilter->eth_dst_mask[3],myfilter->eth_dst_mask[4],myfilter->eth_dst_mask[5]);
  printf("ip.proto = %02x\n",myfilter->ip_proto);
  printf("ip.src = %s / %s \n",myfilter->ip_src,myfilter->ip_src_mask);
  printf("ip.dst = %s / %s \n",myfilter->ip_dst,myfilter->ip_dst_mask);
  printf("tp.sport = %d / %d \n",myfilter->tp_sport, myfilter->tp_sport_mask);
  printf("tp.dport = %d / %d \n",myfilter->tp_dport, myfilter->tp_dport_mask);
#endif

  return(myfilter);
}

int closefilter(struct filter* filter){
  free(filter);
  return 0;
}
