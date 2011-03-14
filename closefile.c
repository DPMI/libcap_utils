/***************************************************************************
                          closefile.c  -  description
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
 This function closes a large file (64bits) and returns 1 on complition, else 0.
 ***************************************************************************/

#include "cap_utils.h"

int close_cap_file(FILE **infile)
{
  errno=0;

  if(fclose(*infile)==EOF)
  {
    //    fprintf(stderr,"close (\"%s\") failed: %s\n", filename, strerror(errno));
    fprintf(stderr,"close failed: %s\n",strerror(errno));
    return 0;
  }
  else
    return 1;
}
