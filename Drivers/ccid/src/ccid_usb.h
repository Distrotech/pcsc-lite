/*
    ccid_usb.h:  USB access routines using the libusb library
    Copyright (C) 2003-2004   Ludovic Rousseau

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

status_t OpenUSB(int lun, int channel);
status_t OpenUSBByName(int lun, char *device);
status_t WriteUSB(int lun, int length, unsigned char *Buffer);
status_t ReadUSB(int lun, int *length, unsigned char *Buffer);
status_t CloseUSB(int lun);

#ifdef __USB_H__
int get_desc(int channel, usb_dev_handle **handle, struct usb_device **dev);
struct usb_interface *get_ccid_usb_interface(struct usb_device *dev);
#endif
#ifdef __CCID_USB__
int get_end_points(struct usb_device *dev, _usbDevice *usb_device);
#endif

