/*
    ccid_serial.h:  Serial access routines
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

status_t OpenSerial(int lun, int channel);
status_t WriteSerial(int lun, int length, unsigned char *Buffer);
status_t ReadSerial(int lun, int *length, unsigned char *Buffer);
int skip_echo(unsigned char *buffer, int buffer_length);
int ReadChunk(int fd, unsigned char *buffer, int buffer_length, int min_length, int lun);
status_t CloseSerial(int lun);

