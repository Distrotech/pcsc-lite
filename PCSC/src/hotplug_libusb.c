/******************************************************************

	MUSCLE SmartCard Development ( http://www.linuxnet.com )
	Title  : hotplug_linux.c
	Package: pcsc lite
	Author : David Corcoran, Ludovic Rousseau
	Date   : 02/28/01, last update 4/6/2003
	License: Copyright (C) 2001,2003 David Corcoran, Ludovic Rousseau
			<corcoran@linuxnet.com>
	Purpose: This provides a search API for hot pluggble devices.
	Credits: The USB code was based partly on Johannes Erdfelt
		libusb code found at libusb.sourceforge.org

$Id$

********************************************************************/

#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <usb.h>

#include "config.h"
#include "wintypes.h"
#include "pcsclite.h"
#include "readerfactory.h"
#include "winscard_msg.h"
#include "debuglog.h"
#include "sys_generic.h"
#include "parser.h"

// PCSCLITE_HP_DROPDIR is defined using ./configure --enable-usbdropdir=foobar
#define PCSCLITE_MANUKEY_NAME			"ifdVendorID"
#define PCSCLITE_PRODKEY_NAME			"ifdProductID"
#define PCSCLITE_NAMEKEY_NAME			"ifdFriendlyName"
#define PCSCLITE_LIBRKEY_NAME			"CFBundleExecutable"
// PCSCLITE_MAX_READERS is defined in pcsclite.h
#define PCSCLITE_MAX_DRIVERS			16
#define BUS_DEVICE_STRSIZE				256
#define PCSCLITE_HP_BASE_PORT			0x200000

#define READER_ABSENT	0
#define READER_PRESENT	1

#define FALSE 0
#define TRUE 1

/* set to 1 if you want to see USB hotplug debug messages */
#define DEBUG_USB_HOTPLUG 0

extern int LTPBundleFindValueWithKey(char *, char *, char *, int);
extern PCSCLITE_MUTEX usbNotifierMutex;

static PCSCLITE_THREAD_T usbNotifyThread;
static int driverSize = -1;

/*
 * keep track of PCSCLITE_MAX_DRIVERS simultaneous drivers
 */
static struct _driverTracker
{
	long manuID;
	long productID;

	char *bundleName;
	char *libraryPath;
	char *readerName;
} driverTracker[PCSCLITE_MAX_DRIVERS];

/*
 * keep track of PCSCLITE_MAX_READERS simultaneous readers
 */
static struct _readerTracker
{
//	short plugged;
	char status;
	char bus_device[BUS_DEVICE_STRSIZE];	/* device name */

	struct _driverTracker *driver;	/* driver for this reader */
} readerTracker[PCSCLITE_MAX_READERS];

LONG HPReadBundleValues(void);
LONG HPAddHotPluggable(struct usb_device *dev, const char bus_device[],
	struct _driverTracker *driver);
LONG HPRemoveHotPluggable(int index);

LONG HPReadBundleValues(void)
{
	LONG rv;
	DIR *hpDir;
	struct dirent *currFP = 0;
	char fullPath[FILENAME_MAX];
	char fullLibPath[FILENAME_MAX];
	char keyValue[TOKEN_MAX_VALUE_SIZE];
	int listCount = 0;

	hpDir = opendir(PCSCLITE_HP_DROPDIR);

	if (hpDir == NULL)
	{
		DebugLogA("Cannot open PC/SC drivers directory: " PCSCLITE_HP_DROPDIR);
		DebugLogA("Disabling USB support for pcscd.");
		return -1;
	}

	while ((currFP = readdir(hpDir)) != 0)
	{
		if (strstr(currFP->d_name, ".bundle") != 0)
		{
			int alias = 0;

			/*
			 * The bundle exists - let's form a full path name and get the
			 * vendor and product ID's for this particular bundle
			 */
			snprintf(fullPath, FILENAME_MAX, "%s%s%s", PCSCLITE_HP_DROPDIR,
				currFP->d_name, "/Contents/Info.plist");
			fullPath[FILENAME_MAX - 1] = '\0';

			// while we find a nth ifdVendorID in Info.plist
			while (LTPBundleFindValueWithKey(fullPath, PCSCLITE_MANUKEY_NAME,
				keyValue, alias) == 0)
			{
				driverTracker[listCount].bundleName = strdup(currFP->d_name);

				// Get ifdVendorID
				rv = LTPBundleFindValueWithKey(fullPath, PCSCLITE_MANUKEY_NAME,
					keyValue, alias);
				if (rv == 0)
					driverTracker[listCount].manuID = strtol(keyValue, 0, 16);

				// get ifdProductID
				rv = LTPBundleFindValueWithKey(fullPath, PCSCLITE_PRODKEY_NAME,
					keyValue, alias);
				if (rv == 0)
					driverTracker[listCount].productID =
						strtol(keyValue, 0, 16);

				// get ifdFriendlyName
				rv = LTPBundleFindValueWithKey(fullPath, PCSCLITE_NAMEKEY_NAME,
					keyValue, alias);
				if (rv == 0)
					driverTracker[listCount].readerName = strdup(keyValue);

				// get CFBundleExecutable
				rv = LTPBundleFindValueWithKey(fullPath, PCSCLITE_LIBRKEY_NAME,
					keyValue, 0);
				if (rv == 0)
				{
					snprintf(fullLibPath, FILENAME_MAX, "%s%s%s%s", PCSCLITE_HP_DROPDIR,
						currFP->d_name, "/Contents/Linux/", keyValue);
					fullLibPath[FILENAME_MAX - 1] = '\0';
					driverTracker[listCount].libraryPath = strdup(fullLibPath);
				}

#if DEBUG_USB_HOTPLUG
					DebugLogB("Found driver for: %s",
						driverTracker[listCount].readerName);
#endif

				listCount++;
				alias++;
			}
		}
	}

	driverSize = listCount;
	closedir(hpDir);

	if (driverSize == 0)
	{
		DebugLogA("No bundle files in pcsc drivers directory: " PCSCLITE_HP_DROPDIR);
		DebugLogA("Disabling USB support for pcscd");
	}

	return 0;
}

void HPEstablishUSBNotifications()
{
	int i, j;
	struct usb_bus *bus;
	struct usb_device *dev;
	char bus_device[BUS_DEVICE_STRSIZE];

	usb_init();
	while (1)
	{
		usb_find_busses();
		usb_find_devices();

		for (i=0; i < PCSCLITE_MAX_READERS; i++)
			/* clear rollcall */
			readerTracker[i].status = READER_ABSENT;

		/* For each USB bus */
		for (bus = usb_get_busses(); bus; bus = bus->next)
		{
			/* For each USB device */
			for (dev = bus->devices; dev; dev = dev->next)
			{
				/* check if the device is supported by one driver */
				for (i=0; i<PCSCLITE_MAX_DRIVERS; i++)
				{
					if (driverTracker[i].libraryPath != NULL &&
						dev->descriptor.idVendor == driverTracker[i].manuID &&
						dev->descriptor.idProduct == driverTracker[i].productID)
					{
						int newreader;

						/* A known device has been found */
						snprintf(bus_device, BUS_DEVICE_STRSIZE, "%s:%s",
							bus->dirname, dev->filename);
						bus_device[BUS_DEVICE_STRSIZE - 1] = '\0';
#if DEBUG_USB_HOTPLUG
						DebugLogB("Found matching USB device: %s", bus_device);
#endif
						newreader = TRUE;

						/* Check if the reader is a new one */
						for (j=0; j<PCSCLITE_MAX_READERS; j++)
						{
							if (strncmp(readerTracker[j].bus_device,
								bus_device, BUS_DEVICE_STRSIZE) == 0)
							{
								/* The reader is already known */
								readerTracker[j].status = READER_PRESENT;
								newreader = FALSE;
#if DEBUG_USB_HOTPLUG
								DebugLogB("Refresh USB device: %s", bus_device);
#endif
								break;
							}
						}

						/* New reader found */
						if (newreader)
							HPAddHotPluggable(dev, bus_device, &driverTracker[i]);
					}
				}
			} /* End of USB device for..loop */

		} /* End of USB bus for..loop */

		/*
		 * check if all the previously found readers are still present
		 */
		for (i=0; i<PCSCLITE_MAX_READERS; i++)
		{
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
			int fd;
			char filename[BUS_DEVICE_STRSIZE];

			/*	BSD workaround:
			 *	ugenopen() in sys/dev/usb/ugen.c returns EBUSY
			 *	when the character device file is already open.
			 *	Because of this, open usb devices will not be
			 *	detected by usb_find_devices(), so we have to
			 *	check for this explicitly.
			 */
			if (readerTracker[i].status == READER_PRESENT ||
				 readerTracker[i].driver == NULL)
				continue;

			sscanf(readerTracker[i].bus_device, "%*[^:]%*[:]%s", filename);
			fd = open(filename, O_RDONLY);
			if (fd == -1)
			{
				if (errno == EBUSY)
				{
					/* The device is present */
#ifdef DEBUG_USB_HOTPLUG
					DebugLogB("BSD: EBUSY on %s", filename);
#endif
					readerTracker[i].status = READER_PRESENT;
				}
#ifdef DEBUG_USB_HOTPLUG
				else
					DebugLogC("BSD: %s error: %s", filename,
						strerror(errno));
#endif
			}
			else
			{
#ifdef DEBUG_USB_HOTPLUG
				DebugLogB("BSD: %s still present", filename);
#endif
				readerTracker[i].status = READER_PRESENT;
				close(fd);
			}
#endif
			if (readerTracker[i].status == READER_ABSENT &&
					readerTracker[i].driver != NULL)
				HPRemoveHotPluggable(i);
		}

		SYS_Sleep(1);

	}	/* End of while loop */
}

LONG HPSearchHotPluggables(void)
{
	int i;

	for (i=0; i < PCSCLITE_MAX_DRIVERS; i++)
	{
		driverTracker[i].productID  = 0;
		driverTracker[i].manuID     = 0;
		driverTracker[i].bundleName = NULL;
		driverTracker[i].libraryPath = NULL;
		driverTracker[i].readerName = NULL;
	}

	for (i=0; i<PCSCLITE_MAX_READERS; i++)
	{
		readerTracker[i].driver = NULL;
		readerTracker[i].status = READER_ABSENT;
		readerTracker[i].bus_device[0] = '\0';
	}

	HPReadBundleValues();

	SYS_ThreadCreate(&usbNotifyThread, NULL,
		(LPVOID) HPEstablishUSBNotifications, 0);

	return 0;
}

LONG HPAddHotPluggable(struct usb_device *dev, const char bus_device[],
	struct _driverTracker *driver)
{
	int i;

	SYS_MutexLock(&usbNotifierMutex);

	DebugLogB("Adding USB device: %s", bus_device);

	/* find a free entry */
	for (i=0; i<PCSCLITE_MAX_READERS; i++)
	{
		if (readerTracker[i].driver == NULL)
			break;
	}
	
	if (i==PCSCLITE_MAX_READERS)
	{
		DebugLogB("Not enough reader entries. Already found %d readers", i);
		return 0;
	}

	if (RFAddReader(driver->readerName, PCSCLITE_HP_BASE_PORT + i,
		driver->libraryPath) == SCARD_S_SUCCESS)
	{
		strncpy(readerTracker[i].bus_device, bus_device, BUS_DEVICE_STRSIZE);
		readerTracker[i].bus_device[BUS_DEVICE_STRSIZE - 1] = '\0';

		readerTracker[i].status = READER_PRESENT;
		readerTracker[i].driver = driver;
	}

	SYS_MutexUnLock(&usbNotifierMutex);

	return 1;
}	/* End of function */

LONG HPRemoveHotPluggable(int index)
{
	SYS_MutexLock(&usbNotifierMutex);

	DebugLogC("Removing USB device[%d]: %s", index, readerTracker[index].bus_device);

	RFRemoveReader(readerTracker[index].driver->readerName,
		PCSCLITE_HP_BASE_PORT + index);
	readerTracker[index].status = READER_ABSENT;
	readerTracker[index].bus_device[0] = '\0';
	readerTracker[index].driver = NULL;

	SYS_MutexUnLock(&usbNotifierMutex);

	return 1;
}	/* End of function */

/*
 * Sets up callbacks for device hotplug events. Not currently implemented
 * for Linux.
 */
ULONG HPRegisterForHotplugEvents(void)
{
	return 0;
}

