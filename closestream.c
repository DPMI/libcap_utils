/***************************************************************************
                          closestream.c  -  description
                             -------------------
    begin                : Mon Aug 1 2004
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
 This function closes a socket  and returns 1 on complition, else 0.
 ***************************************************************************/

#include "caputils/caputils.h"
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

long closestream(struct stream* st){
  return st->destroy ? st->destroy(st) : 0;

  /* ret */
  /* errno=0; */
  /* switch(myStream->type){ */
  /*   case 3://TCP */
  /*   case 2://UDP */
  /*   case 1://Ethernet */
  /*     if(close(myStream->mySocket)==-1){ */
  /* 	perror("Close failed."); */
  /* 	return(0); */
  /*     } */
  /*     break; */
  /*   case 0: */
  /*   default: */
  /*     if(fclose(myStream->myFile)==EOF){ */
  /* 	perror("Close failed."); */
  /* 	return(0); */
  /*     } */
  /*     break; */
  /* } */

  /* free(myStream->address); */
  /* free(myStream->comment); */
  /* free(myStream->filename); */

  /* return(1); */
}
