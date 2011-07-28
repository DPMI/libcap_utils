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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "caputils/caputils.h"
#include "stream.h"
#include <assert.h>

long write_post(struct stream *outStream, u_char* data, int size){
  assert(outStream);
  assert(outStream->write);
  return outStream->write(outStream, data, size);
}
