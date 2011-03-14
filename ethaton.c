/***************************************************************************
                          eth_aton.c  -  description
                             -------------------
    begin                : Mon Feb 3 2003
    copyright            : (C) 2004 by Patrik Carlsson
    email                : patrik.carlsson@bth.se
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
 described in cap_utils.h. the file pointer the points to the first packet.
 Function returns 1 if success and 0 if open failed.
 ***************************************************************************/

/*
INPUT:
 char *dest, pointer to destination area. 
 char *org, pointer to string containing ethernet address. SYNTAX is 
 XX:XX:XX:XX:XX:XX the ":" can be replaced with any char. BUT something MUST be present!
OUTPUT:
  int 0 if fail
  int 1 if ok.
*/

#include "cap_utils.h"

int eth_aton(char *dest,char *org){
  char tmp[3];
  char *ptr;
  ptr=tmp;
  tmp[2]='\0';
  int j,k;
  j=k=0;
  int t;
//  printf("eth_aton:");
//  printf("src = %s: --> ",org);
  for(j=0;j<ETH_ALEN;j++){
    strncpy(tmp,org+k,2);
    t=(int)strtoul(tmp,NULL,16);
    *(dest+j)=t;
    k=k+3;
//    printf("%02x:",t);
  }
//  printf("\n");
  return 1;
}
