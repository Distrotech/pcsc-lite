/*
    ccid_usb.h:  USB access routines using the libusb library
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

#ifndef _LIBUSB_WRAP_
#define _LIBUSB_WRAP_

/* convert a 4 byte integer in USB format into an int */
#define dw2i(a, x) ((((((a[x+3] << 8) + a[x+2]) << 8) + a[x+1]) << 8) + a[x])

status_t OpenUSB(int lun, int channel);
status_t WriteUSB(int lun, int length, unsigned char *Buffer);
status_t ReadUSB(int lun, int *length, unsigned char *Buffer);
status_t CloseUSB(int lun);

int ccid_get_seq(int lun);
void ccid_error(int error, char *file, int line);
void i2dw(int value, unsigned char *buffer);
#ifdef __USB_H__
int get_desc(int channel, char *device_name[], usb_dev_handle **handle,
	struct usb_device **dev);
#endif
#ifdef __CCID_USB__
int get_end_points(struct usb_device *dev, _usbDevice *usb_device);
#endif

#endif
