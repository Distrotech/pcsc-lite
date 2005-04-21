/*
    proto-t1.h: header file for proto-t1.c
    Copyright (C) 2004   Ludovic Rousseau

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
*/

/* $Id$ */

#ifndef __CHECKSUM_H__
#define __CHECKSUM_H__

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <unistd.h>

extern unsigned int	csum_lrc_compute(const uint8_t *, size_t, unsigned char *);
extern unsigned int	csum_crc_compute(const uint8_t *, size_t, unsigned char *);

#endif

