/*
    ccid.h: CCID structures
    Copyright (C) 2003   Ludovic Rousseau

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * $Id$
 */

typedef struct
{
	/*
	 * CCID Sequence number
	 */
	unsigned char bSeq;

	/*
	 * VendorID << 16 + ProductID
	 */
	int readerID;

	/*
	 * Maximum message length
	 */
	int dwMaxCCIDMessageLength;

	/*
	 * Features supported by the reader (directly from class Descriptor)
	 */
	int dwFeatures;

} _ccid_descriptor;

#define CCID_CLASS_AUTO_VOLTAGE		0x00000008
#define CCID_CLASS_EXCHANGE_MASK	0x00070000
#define CCID_CLASS_TPDU				0x00010000
#define CCID_CLASS_SHORT_APDU		0x00020000
#define CCID_CLASS_EXTENDED_APDU	0x00040000

/* See CCID specs ch. 4.2.1 */
#define CCID_COMMAND_FAILED			0x40	/* 01 0000 00 */
#define CCID_TIME_EXTENSION			0x80	/* 10 0000 00 */

/* Product identification for special treatments */
#define GEMPC433	0x08E64433
#define GEMPCKEY	0x08E63438
#define GEMPCTWIN	0x08E63437
#define CARDMAN3121	0x076B3021

/* Escape sequence codes */
#define ESC_GEMPC_SET_ISO_MODE		1
#define ESC_GEMPC_SET_APDU_MODE		2


int ccid_open_hack(int lun);
void ccid_error(int error, char *file, int line);
_ccid_descriptor *get_ccid_descriptor(int lun);

/* convert a 4 byte integer in USB format into an int */
#define dw2i(a, x) ((((((a[x+3] << 8) + a[x+2]) << 8) + a[x+1]) << 8) + a[x])

