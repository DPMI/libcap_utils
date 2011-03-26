/***************************************************************************
                          timecmp.c  -  description
                             -------------------
    begin                : Fri Feb 7 2003
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
 This function compares two struct timepico (ts1<ts2=-1, ts1>ts2=1, ts1==ts2=0)
 ***************************************************************************/

#include "caputils/caputils.h"

int timecmp(const timepico *ts1, const timepico *ts2)
{
  if (ts1->tv_sec < ts2->tv_sec){ //if ts1 is before ts2
    return -1;
  }
  if (ts1->tv_sec > ts2->tv_sec){//if ts1 is after ts2
    return 1;
  }

//same second
  if (ts1->tv_psec < ts2->tv_psec){//if ts1 is before ts2
    return -1;
  }
  if (ts1->tv_psec > ts2->tv_psec){//if ts1 is before ts2
    return 1;
  }
  return 0; // if ts1 and ts2 are identical
}
