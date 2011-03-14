/***************************************************************************
                          valtopico.c  -  description
                             -------------------
    begin                : Mon Feb 3 2003
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
 This function converts a struct timeval to a struct timepico (ms->ps)
 ***************************************************************************/
#include "cap_utils.h"

timepico timeval_to_timepico(struct timeval in)
{
  timepico out;
  out.tv_sec=in.tv_sec;
  out.tv_psec=in.tv_usec;
  out.tv_psec*=1000;
  out.tv_psec*=1000;
  return out;
}

