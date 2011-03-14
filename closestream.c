/***************************************************************************
                          closestream.c  -  description
                             -------------------
    begin                : Mon Aug 1 2004
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
 This function closes a socket  and returns 1 on complition, else 0.
 ***************************************************************************/

#include "cap_utils.h"
#include <unistd.h>

int closestream(struct stream *myStream){
  errno=0;
  switch(myStream->type){
    case 3://TCP
    case 2://UDP
    case 1://Ethernet
      if(close(myStream->mySocket)==-1){
	perror("Close failed.");
	return(0);
      }
      break;
    case 0:
    default:
      if(fclose(myStream->myFile)==EOF){
	perror("Close failed.");
	return(0);
      }
      break;
  }
  if(myStream->address!=0)
    free(myStream->address);
  if(myStream->filename!=0)
    free(myStream->address);
  if(myStream->comment!=0)
    free(myStream->comment);

  return(1);
}
