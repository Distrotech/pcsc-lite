/*
    ccid_usb.c: USB access routines using the libusb library
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

#define __CCID_USB__

#include <stdio.h>
#include <string.h> 
#include <errno.h>
#include <usb.h>

#include "ccid.h"
#include "config.h"
#include "debug.h"
#include "defs.h"
#include "utils.h"
#include "parser.h"
#include "ccid_ifdhandler.h"


/* read timeout
 * we must wait enough so that the card can finish its calculation
 * the card, and then the reader should send TIME REQUEST bytes
 * so this timeout should never occur */
#define USB_READ_TIMEOUT (60 * 1000)	/* 1 minute timeout */

/* write timeout
 * we don't have to wait a long time since the card was doing nothing */
#define USB_WRITE_TIMEOUT (5 * 1000)  /* 5 seconds timeout */

/*
 * Proprietary USB Class (0xFF) are (or are not) accepted
 * A proprietary class is used for devices released before the final CCID
 * specifications were ready.
 * We should not have problems with non CCID devices becasue the
 * Manufacturer and Product ID are also used to identify the device */
#define ALLOW_PROPRIETARY_CLASS

#define BUS_DEVICE_STRSIZE 32

typedef struct
{
	usb_dev_handle *handle;
	struct usb_device *dev;

	/*
	 * Endpoints
	 */
	int bulk_in;
	int bulk_out;

	/*
	 * CCID infos common to USB and serial
	 */
	_ccid_descriptor ccid;

} _usbDevice;

/* The _usbDevice structure must be defined before including ccid_usb.h */
#include "ccid_usb.h"

static int get_end_points(struct usb_device *dev, _usbDevice *usb_device);

/* ne need to initialize to 0 since it is static */
static _usbDevice usbDevice[PCSCLITE_MAX_READERS];

#define PCSCLITE_MANUKEY_NAME                   "ifdVendorID"
#define PCSCLITE_PRODKEY_NAME                   "ifdProductID"
#define PCSCLITE_NAMEKEY_NAME                   "ifdFriendlyName"


/*****************************************************************************
 *
 *					OpenUSB
 *
 ****************************************************************************/
status_t OpenUSB(unsigned int lun, int Channel)
{
	return OpenUSBByName(lun, NULL);
} /* OpenUSB */


/*****************************************************************************
 *
 *					OpenUSBByName
 *
 ****************************************************************************/
status_t OpenUSBByName(unsigned int lun, char *device)
{
	static struct usb_bus *busses = NULL;
	unsigned int reader = LunToReaderIndex(lun);
	int alias = 0;
	struct usb_bus *bus;
	struct usb_dev_handle *dev_handle;
	char keyValue[TOKEN_MAX_VALUE_SIZE];
	int vendorID, productID;
	char infofile[FILENAME_MAX];
	unsigned int device_vendor, device_product;
	char *dirname = NULL, *filename = NULL;

	DEBUG_COMM3("Lun: %X, Device: %s", lun, device);

	/* device name specified */
	if (device)
	{
		/* format: usb:%04x/%04x, vendor, product */
		if (strncmp("usb:", device, 4) != 0)
		{
			DEBUG_CRITICAL2("device name does not start with \"usb:\": %s",
				device);
			return STATUS_UNSUCCESSFUL;
		}

		if (sscanf(device, "usb:%x/%x", &device_vendor, &device_product) != 2)
		{
			DEBUG_CRITICAL2("device name can't be parsed: %s", device);
			return STATUS_UNSUCCESSFUL;
		}

		/* format usb:%04x/%04x:libusb:%s
		 * with %s set to %s:%s, dirname, filename */
		if ((dirname = strstr(device, "libusb:")) != NULL)
		{
			/* dirname points to the first char after libusb: */
			dirname += strlen("libusb:");

			/* search the : (separation) char */
			filename = strchr(dirname, ':');

			if (filename)
			{
				/* end the dirname string */
				*filename = '\0';

				/* filename points to the first char after : */
				filename++;
			}
			else
			{
				/* parse failed */
				dirname = NULL;

				DEBUG_CRITICAL2("can't parse using libusb scheme: %s", device);
			}
		}
	}

	if (busses == NULL)
		usb_init();

	usb_find_busses();
	usb_find_devices();

	busses = usb_get_busses();

	if (busses == NULL)
	{
		DEBUG_CRITICAL("No USB busses found");
		return STATUS_UNSUCCESSFUL;
	}

	/* is the lun already used? */
	if (usbDevice[reader].handle != NULL)
	{
		DEBUG_CRITICAL2("USB driver with lun %X already in use", lun);
		return STATUS_UNSUCCESSFUL;
	}

	/* Info.plist full patch filename */
	snprintf(infofile, sizeof(infofile), "%s/%s/Contents/Info.plist",
		PCSCLITE_HP_DROPDIR, BUNDLE);

	/* general driver info */
	if (!LTPBundleFindValueWithKey(infofile, "ifdManufacturerString", keyValue, 0))
	{
		DEBUG_CRITICAL2("Manufacturer: %s", keyValue);
	}
	else
	{
		DEBUG_CRITICAL2("LTPBundleFindValueWithKey error. Can't find %s?",
			infofile);
		return STATUS_UNSUCCESSFUL;
	}
	if (!LTPBundleFindValueWithKey(infofile, "ifdProductString", keyValue, 0))
	{
		DEBUG_CRITICAL2("ProductString: %s", keyValue);
	}
	else
		return STATUS_UNSUCCESSFUL;
	if (!LTPBundleFindValueWithKey(infofile, "Copyright", keyValue, 0))
	{
		DEBUG_CRITICAL2("Copyright: %s", keyValue);
	}
	else
		return STATUS_UNSUCCESSFUL;
	vendorID = strlen(keyValue);
	alias = 0x1D;
	for (; vendorID--;)
		alias ^= keyValue[vendorID];

	/* for any supported reader */
	while (LTPBundleFindValueWithKey(infofile, PCSCLITE_MANUKEY_NAME, keyValue, alias) == 0)
	{
		vendorID = strtoul(keyValue, 0, 16);

		if (LTPBundleFindValueWithKey(infofile, PCSCLITE_PRODKEY_NAME, keyValue, alias))
			goto end;
		productID = strtoul(keyValue, 0, 16);

		if (LTPBundleFindValueWithKey(infofile, PCSCLITE_NAMEKEY_NAME, keyValue, alias))
			goto end;

		/* go to next supported reader for next round */
		alias++;

		/* the device was specified but is not the one we are trying to find */
		if (device
			&& (vendorID != device_vendor || productID != device_product))
			continue;

		/* on any USB buses */
		for (bus = busses; bus; bus = bus->next)
		{
			struct usb_device *dev;

			/* any device on this bus */
			for (dev = bus->devices; dev; dev = dev->next)
			{
				/* device defined by name? */
				if (dirname && (strcmp(dirname, bus->dirname)
					|| strcmp(filename, dev->filename)))
					continue;

				if (dev->descriptor.idVendor == vendorID
					&& dev->descriptor.idProduct == productID)
				{
					int r, already_used;
					struct usb_interface *usb_interface = NULL;
					int interface;

					/* is it already opened? */
					already_used = FALSE;

					for (r=0; r<PCSCLITE_MAX_READERS; r++)
					{
						if (usbDevice[r].dev)
						{
							DEBUG_COMM3("Checking device: %s/%s",
								bus->dirname, dev->filename);
							/* same busname, same filename */
							if (strcmp(usbDevice[r].dev->bus->dirname, bus->dirname) == 0 && strcmp(usbDevice[r].dev->filename, dev->filename) == 0)
								already_used = TRUE;
						}
					}

					/* this reader is already managed by us */
					if (already_used)
					{
						DEBUG_INFO3("USB device %s/%s already in use. Checking next one.",
							bus->dirname, dev->filename);

						continue;
					}

					DEBUG_COMM3("Trying to open USB bus/device: %s/%s",
						 bus->dirname, dev->filename);

					dev_handle = usb_open(dev);
					if (dev_handle == NULL)
					{
						DEBUG_CRITICAL4("Can't usb_open(%s/%s): %s",
							bus->dirname, dev->filename, strerror(errno));

						continue;
					}

					/* now we found a free reader and we try to use it */
					if (dev->config == NULL)
					{
						DEBUG_CRITICAL3("No dev->config found for %s/%s",
							 bus->dirname, dev->filename);
						return STATUS_UNSUCCESSFUL;
					}

					usb_interface = get_ccid_usb_interface(dev);
					if (usb_interface == NULL)
					{
						DEBUG_CRITICAL3("Can't find a CCID interface on %s/%s",
							bus->dirname, dev->filename);
						return STATUS_UNSUCCESSFUL;
					}			

					if (usb_interface->altsetting->extralen != 54)
					{
						DEBUG_CRITICAL4("Extra field for %s/%s has a wrong length: %d", bus->dirname, dev->filename, usb_interface->altsetting->extralen);
						return STATUS_UNSUCCESSFUL;
					}

					interface = usb_interface->altsetting->bInterfaceNumber;
					if (usb_claim_interface(dev_handle, interface) < 0)
					{
						DEBUG_CRITICAL4("Can't claim interface %s/%s: %s",
							bus->dirname, dev->filename, strerror(errno));
						return STATUS_UNSUCCESSFUL;
					}

					DEBUG_INFO4("Found Vendor/Product: %04X/%04X (%s)",
						dev->descriptor.idVendor,
						dev->descriptor.idProduct, keyValue);
					DEBUG_INFO3("Using USB bus/device: %s/%s",
						 bus->dirname, dev->filename);

					/* Get Endpoints values*/
					get_end_points(dev, &usbDevice[reader]);

					/* store device information */
					usbDevice[reader].handle = dev_handle;
					usbDevice[reader].dev = dev;

					/* CCID common informations */
					usbDevice[reader].ccid.bSeq = 0;
					usbDevice[reader].ccid.readerID =
						(dev->descriptor.idVendor << 16) +
						dev->descriptor.idProduct;
					usbDevice[reader].ccid.dwFeatures = dw2i(usb_interface->altsetting->extra, 40);
					usbDevice[reader].ccid.bPINSupport = usb_interface->altsetting->extra[52];
					usbDevice[reader].ccid.dwMaxCCIDMessageLength = dw2i(usb_interface->altsetting->extra, 44);
					usbDevice[reader].ccid.dwMaxIFSD = dw2i(usb_interface->altsetting->extra, 28);
					usbDevice[reader].ccid.dwDefaultClock = dw2i(usb_interface->altsetting->extra, 10);
					usbDevice[reader].ccid.dwMaxDataRate = dw2i(usb_interface->altsetting->extra, 23);

					goto end;
				}
			}
		}
	}
end:
	if (usbDevice[reader].handle == NULL)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
} /* OpenUSBByName */


/*****************************************************************************
 *
 *					WriteUSB
 *
 ****************************************************************************/
status_t WriteUSB(unsigned int lun, unsigned int length, unsigned char *buffer)
{
	int rv;
	unsigned int reader = LunToReaderIndex(lun);
#ifdef DEBUG_LEVEL_COMM
	char debug_header[] = "-> 121234 ";

	sprintf(debug_header, "-> %06X ", (int)lun);
#endif

#ifdef DEBUG_LEVEL_COMM
	DEBUG_XXD(debug_header, buffer, length);
#endif

	rv = usb_bulk_write(usbDevice[reader].handle, usbDevice[reader].bulk_out,
		(char *)buffer, length, USB_WRITE_TIMEOUT);

	if (rv < 0)
	{
		DEBUG_CRITICAL4("usb_bulk_write(%s/%s): %s",
			usbDevice[reader].dev->bus->dirname,
			usbDevice[reader].dev->filename, strerror(errno));
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
} /* WriteUSB */


/*****************************************************************************
 *
 *					ReadUSB
 *
 ****************************************************************************/
status_t ReadUSB(unsigned int lun, unsigned int * length, unsigned char *buffer)
{
	int rv;
	unsigned int reader = LunToReaderIndex(lun);
#ifdef DEBUG_LEVEL_COMM
	char debug_header[] = "<- 121234 ";

	sprintf(debug_header, "<- %06X ", (int)lun);
#endif

	rv = usb_bulk_read(usbDevice[reader].handle, usbDevice[reader].bulk_in,
		(char *)buffer, *length, USB_READ_TIMEOUT);

	if (rv < 0)
	{
		*length = 0;
		DEBUG_CRITICAL4("usb_bulk_read(%s/%s): %s",
			usbDevice[reader].dev->bus->dirname,
			usbDevice[reader].dev->filename, strerror(errno));
		return STATUS_UNSUCCESSFUL;
	}

	*length = rv;

#ifdef DEBUG_LEVEL_COMM
	DEBUG_XXD(debug_header, buffer, *length);
#endif

	return STATUS_SUCCESS;
} /* ReadUSB */


/*****************************************************************************
 *
 *					CloseUSB
 *
 ****************************************************************************/
status_t CloseUSB(unsigned int lun)
{
	struct usb_interface *usb_interface;
	int interface;
	unsigned int reader = LunToReaderIndex(lun);

	/* device not opened */
	if (usbDevice[reader].dev == NULL)
		return STATUS_UNSUCCESSFUL;

	DEBUG_COMM3("Closing USB device: %s/%s",
		usbDevice[reader].dev->bus->dirname, usbDevice[reader].dev->filename);

  	usb_interface = get_ccid_usb_interface(usbDevice[reader].dev);
	interface = usb_interface ?
		usb_interface->altsetting->bInterfaceNumber :
		usbDevice[reader].dev->config->interface->altsetting->bInterfaceNumber;
	
	/* reset so that bSeq starts at 0 again */
	usb_reset(usbDevice[reader].handle);

	usb_release_interface(usbDevice[reader].handle, interface);
	usb_close(usbDevice[reader].handle);

	/* mark the resource unused */
	usbDevice[reader].handle = NULL;
	usbDevice[reader].dev = NULL;

	return STATUS_SUCCESS;
} /* CloseUSB */


/*****************************************************************************
 *
 *					get_ccid_descriptor
 *
 ****************************************************************************/
_ccid_descriptor *get_ccid_descriptor(unsigned int lun)
{
	return &usbDevice[LunToReaderIndex(lun)].ccid;
} /* get_ccid_descriptor */


/*****************************************************************************
 *
 *					get_desc
 *
 ****************************************************************************/
int get_desc(int channel, usb_dev_handle **handle, struct
	usb_device **dev)
{
	if (channel < 0 || channel > PCSCLITE_MAX_READERS)
		return 1;

	*handle = usbDevice[channel].handle;
	*dev = usbDevice[channel].dev;

	return 0;
} /* get_desc */


/*****************************************************************************
 *
 *					get_end_points
 *
 ****************************************************************************/
static int get_end_points(struct usb_device *dev, _usbDevice *usb_device)
{
	int i;
	int bEndpointAddress;
	struct usb_interface *usb_interface = get_ccid_usb_interface(dev);
	
	/*
	 * 3 Endpoints maximum: Interrupt In, Bulk In, Bulk Out
	 */
	for (i=0; i<3; i++)
	{
		if (usb_interface->altsetting->endpoint[i].bmAttributes != USB_ENDPOINT_TYPE_BULK)
			continue;

		bEndpointAddress = usb_interface->altsetting->endpoint[i].bEndpointAddress;

		if ((bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_IN)
			usb_device->bulk_in = bEndpointAddress;

		if ((bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_ENDPOINT_OUT)
			usb_device->bulk_out = bEndpointAddress;
	}

	return 0;
} /* get_end_points */


/*****************************************************************************
 *
 *					get_ccid_usb_interface
 *
 ****************************************************************************/
struct usb_interface * get_ccid_usb_interface(struct usb_device *dev)
{
	struct usb_interface *usb_interface = NULL; 

	/* if multiple interfaces use the first one with CCID class type */
	if (dev->config->bNumInterfaces > 1)
	{
		int ii;
		for (ii=0; ii<dev->config->bNumInterfaces; ii++)
		{
			/* CCID Class? */
			if (dev->config->interface[ii].altsetting->bInterfaceClass == 0xb
#ifdef ALLOW_PROPRIETARY_CLASS
				|| dev->config->interface[ii].altsetting->bInterfaceClass == 0xff
#endif
				)
			{
				usb_interface = &dev->config->interface[ii];
				break;
			}
		}
	}
	else
		/* we keep this in case a reader reports a bad class value */
		usb_interface = dev->config->interface;

	return usb_interface;
} /* get_ccid_usb_interface */

