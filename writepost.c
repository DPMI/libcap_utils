/***************************************************************************
                          writepost.c  -  description
                             -------------------
    begin                : Thu Feb 6 2003
    copyright            : (C) 2003 by Anders Ekberg
    email                : anders.ekberg@bth.se
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
 This function writes a packet to file.
 ***************************************************************************/
#include "cap_utils.h"

int write_post(struct stream *outStream, u_char* data, int size){
//  printf("STREAM is %d myFile=%p mySocket=%d\n",outStream->type,outStream->myFile,outStream->mySocket);
  switch(outStream->type){
    case 3:// TCP
    case 2:// UDP
      break;

    case 1:// Ethernet
      break;
    case 0:// File
    default:
      if(fwrite(data, 1, size, outStream->myFile)!=size){
	perror("Cannot write data to file");
	return 0;
      } 
  }
  return(1);
}
