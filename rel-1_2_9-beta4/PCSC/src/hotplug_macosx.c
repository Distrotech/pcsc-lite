/*
 * This provides a search API for hot pluggble devices.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2002-2004
 *  Stephen M. Webb <stephenw@cryptocard.com>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#include "config.h"
#include "PCSC/pcsclite.h"

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <stdlib.h>
#include <string.h>

#include "PCSC/debuglog.h"
#include "PCSC/parser.h"
#include "readerfactory.h"
#include "winscard_msg.h"
#include "sys_generic.h"
#include "hotplug.h"

#undef DEBUG_HOTPLUG

/*
 * An aggregation of useful information on a driver bundle in the
 * drop directory.
 */
typedef struct HPDriver
{
	UInt32 m_vendorId;			/* unique vendor's manufacturer code */
	UInt32 m_productId;			/* manufacturer's unique product code */
	char *m_friendlyName;		/* bundle friendly name */
	char *m_libPath;			/* bundle's plugin library location */
} HPDriver, *HPDriverVector;

/*
 * An aggregation on information on currently active reader drivers.
 */
typedef struct HPDevice
{
	HPDriver *m_driver;			/* driver bundle information */
	UInt32 m_address;			/* unique system address of device */
	struct HPDevice *m_next;	/* next device in list */
} HPDevice, *HPDeviceList;

/*
 * Pointer to a list of (currently) known hotplug reader devices (and their
 * drivers).
 */
static HPDeviceList sDeviceList = NULL;

/*
 * A callback to handle the asynchronous appearance of new devices that are
 * candidates for PCSC readers.
 */
static void HPDeviceAppeared(void *refCon, io_iterator_t iterator)
{
	kern_return_t kret;
	io_service_t obj;

	while ((obj = IOIteratorNext(iterator)))
		kret = IOObjectRelease(obj);

	HPSearchHotPluggables();
}

/*
 * A callback to handle the asynchronous disappearance of devices that are
 * possibly PCSC readers.
 */
static void HPDeviceDisappeared(void *refCon, io_iterator_t iterator)
{
	kern_return_t kret;
	io_service_t obj;

	while ((obj = IOIteratorNext(iterator)))
		kret = IOObjectRelease(obj);

	HPSearchHotPluggables();
}


/*
 * Creates a vector of driver bundle info structures from the hot-plug driver
 * directory.
 *
 * Returns NULL on error and a pointer to an allocated HPDriver vector on
 * success.  The caller must free the HPDriver with a call to
 * HPDriversRelease().
 */
static HPDriverVector HPDriversGetFromDirectory(const char *driverBundlePath)
{
	int i;
#ifdef DEBUG_HOTPLUG
	DebugLogB("Entering HPDriversGetFromDirectory: %s", driverBundlePath);
#endif

	int readersNumber = 0;
	HPDriverVector bundleVector = NULL;
	CFArrayRef bundleArray;
	CFStringRef driverBundlePathString =
		CFStringCreateWithCString(kCFAllocatorDefault,
		driverBundlePath,
		kCFStringEncodingMacRoman);
	CFURLRef pluginUrl = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
		driverBundlePathString,
		kCFURLPOSIXPathStyle, TRUE);

	CFRelease(driverBundlePathString);
	if (!pluginUrl)
	{
		DebugLogA("error getting plugin directory URL");
		return NULL;
	}
	bundleArray = CFBundleCreateBundlesFromDirectory(kCFAllocatorDefault,
		pluginUrl, NULL);
	if (!bundleArray)
	{
		DebugLogA("error getting plugin directory bundles");
		return NULL;
	}
	CFRelease(pluginUrl);

	size_t bundleArraySize = CFArrayGetCount(bundleArray);

	/* get the number of readers (including aliases) */
	for (i = 0; i < bundleArraySize; i++)
	{
		CFBundleRef currBundle =
			(CFBundleRef) CFArrayGetValueAtIndex(bundleArray, i);
		CFDictionaryRef dict = CFBundleGetInfoDictionary(currBundle);

		const void * blobValue = CFDictionaryGetValue(dict,
			CFSTR(PCSCLITE_HP_MANUKEY_NAME));

		if (!blobValue)
		{
			DebugLogA("error getting vendor ID from bundle");
			return NULL;
		}

		if (CFGetTypeID(blobValue) == CFArrayGetTypeID())
		{
			/* alias found, each reader count as 1 */
			CFArrayRef propertyArray = blobValue;
			readersNumber += CFArrayGetCount(propertyArray);
		}
		else
			/* No alias, only one reader supported */
			readersNumber++;
	}
#ifdef DEBUG_HOTPLUG
	DebugLogB("Total of %d readers supported", readersNumber);
#endif

	/* The last entry is an end marker (m_vendorId = 0)
	 * see checks in HPDriversMatchUSBDevices:503
	 *  and HPDriverVectorRelease:376 */
	readersNumber++;

	bundleVector = (HPDriver *) calloc(readersNumber, sizeof(HPDriver));
	if (!bundleVector)
	{
		DebugLogA("memory allocation failure");
		return NULL;
	}

	HPDriver *driverBundle = bundleVector;
	for (i = 0; i < bundleArraySize; i++)
	{
		CFBundleRef currBundle =
			(CFBundleRef) CFArrayGetValueAtIndex(bundleArray, i);
		CFDictionaryRef dict = CFBundleGetInfoDictionary(currBundle);

		CFURLRef bundleUrl = CFBundleCopyBundleURL(currBundle);
		CFStringRef bundlePath = CFURLCopyPath(bundleUrl);

		driverBundle->m_libPath = strdup(CFStringGetCStringPtr(bundlePath,
				CFStringGetSystemEncoding()));

		const void * blobValue = CFDictionaryGetValue(dict,
			CFSTR(PCSCLITE_HP_MANUKEY_NAME));

		if (!blobValue)
		{
			DebugLogA("error getting vendor ID from bundle");
			return bundleVector;
		}

		if (CFGetTypeID(blobValue) == CFArrayGetTypeID())
		{
			CFArrayRef vendorArray = blobValue;
			CFArrayRef productArray;
			CFArrayRef friendlyNameArray;
			char *libPath = driverBundle->m_libPath;

#ifdef DEBUG_HOTPLUG
			DebugLogB("Driver with aliases: %s", libPath);
#endif
			/* get list of ProductID */
			productArray = CFDictionaryGetValue(dict,
				 CFSTR(PCSCLITE_HP_PRODKEY_NAME));
			if (!productArray)
			{
				DebugLogA("error getting product ID from bundle");
				return bundleVector;
			}

			/* get list of FriendlyName */
			friendlyNameArray = CFDictionaryGetValue(dict,
				 CFSTR(PCSCLITE_HP_NAMEKEY_NAME));
			if (!friendlyNameArray)
			{
				DebugLogA("error getting product ID from bundle");
				return bundleVector;
			}

			int reader_nb = CFArrayGetCount(vendorArray);

			if (reader_nb != CFArrayGetCount(productArray))
			{
				DebugLogC("Malformed Info.plist: %d vendors and %d products",
					reader_nb, CFArrayGetCount(productArray));
				return bundleVector;
			}

			if (reader_nb != CFArrayGetCount(friendlyNameArray))
			{
				DebugLogC("Malformed Info.plist: %d vendors and %d friendlynames",
					reader_nb, CFArrayGetCount(friendlyNameArray));
				return bundleVector;
			}

			int j;
			for (j=0; j<reader_nb; j++)
			{
				CFStringRef strValue = CFArrayGetValueAtIndex(vendorArray, j);
				
				driverBundle->m_vendorId = strtoul(CFStringGetCStringPtr(strValue,
					CFStringGetSystemEncoding()), NULL, 16);

				strValue = CFArrayGetValueAtIndex(productArray, j);
				driverBundle->m_productId = strtoul(CFStringGetCStringPtr(strValue,
					CFStringGetSystemEncoding()), NULL, 16);

				strValue = CFArrayGetValueAtIndex(friendlyNameArray, j);
				const char *cstr = CFStringGetCStringPtr(strValue,
					CFStringGetSystemEncoding());

				driverBundle->m_friendlyName = strdup(cstr);
				if (!driverBundle->m_libPath)
					driverBundle->m_libPath = strdup(libPath);

#ifdef DEBUG_HOTPLUG
				DebugLogB("VendorID: 0x%04X", driverBundle->m_vendorId);
				DebugLogB("ProductID: 0x%04X", driverBundle->m_productId);
				DebugLogB("Friendly name: %s", driverBundle->m_friendlyName);
				DebugLogB("Driver: %s", driverBundle->m_libPath);
#endif

				/* go to next bundle in the vector */
				driverBundle++;
			}
		}
		else
		{
			CFStringRef strValue = blobValue;

#ifdef DEBUG_HOTPLUG
			DebugLogC("Driver without alias: %s", driverBundle, driverBundle->m_libPath);
#endif

			driverBundle->m_vendorId = strtoul(CFStringGetCStringPtr(strValue,
					CFStringGetSystemEncoding()), NULL, 16);

			strValue = (CFStringRef) CFDictionaryGetValue(dict,
				CFSTR(PCSCLITE_HP_PRODKEY_NAME));
			if (!strValue)
			{
				DebugLogA("error getting product ID from bundle");
				return bundleVector;
			}
			driverBundle->m_productId = strtoul(CFStringGetCStringPtr(strValue,
				CFStringGetSystemEncoding()), NULL, 16);

			strValue = (CFStringRef) CFDictionaryGetValue(dict,
				CFSTR(PCSCLITE_HP_NAMEKEY_NAME));
			if (!strValue)
			{
				DebugLogA("error getting product friendly name from bundle");
				driverBundle->m_friendlyName = strdup("unnamed device");
			}
			else
			{
				const char *cstr = CFStringGetCStringPtr(strValue,
					CFStringGetSystemEncoding());

				driverBundle->m_friendlyName = strdup(cstr);
			}
#ifdef DEBUG_HOTPLUG
			DebugLogB("VendorID: 0x%04X", driverBundle->m_vendorId);
			DebugLogB("ProductID: 0x%04X", driverBundle->m_productId);
			DebugLogB("Friendly name: %s", driverBundle->m_friendlyName);
			DebugLogB("Driver: %s", driverBundle->m_libPath);
#endif

			/* go to next bundle in the vector */
			driverBundle++;
		}
	}
	CFRelease(bundleArray);
	return bundleVector;
}

/*
 * Copies a driver bundle instance.
 */
static HPDriver *HPDriverCopy(HPDriver * rhs)
{
	if (!rhs)
		return NULL;

	HPDriver *newDriverBundle = (HPDriver *) calloc(1, sizeof(HPDriver));

	if (!newDriverBundle)
		return NULL;

	newDriverBundle->m_vendorId = rhs->m_vendorId;
	newDriverBundle->m_productId = rhs->m_productId;
	newDriverBundle->m_friendlyName = strdup(rhs->m_friendlyName);
	newDriverBundle->m_libPath = strdup(rhs->m_libPath);

	return newDriverBundle;
}

/*
 * Releases resources allocated to a driver bundle vector.
 */
static void HPDriverRelease(HPDriver * driverBundle)
{
	if (driverBundle)
	{
		free(driverBundle->m_friendlyName);
		free(driverBundle->m_libPath);
	}
}

/*
 * Releases resources allocated to a driver bundle vector.
 */
static void HPDriverVectorRelease(HPDriverVector driverBundleVector)
{
	if (driverBundleVector)
	{
		HPDriver *b;

		for (b = driverBundleVector; b->m_vendorId; ++b)
			HPDriverRelease(b);

		free(driverBundleVector);
	}
}

/*
 * Inserts a new reader device in the list.
 */
static HPDeviceList
HPDeviceListInsert(HPDeviceList list, HPDriver * bundle, UInt32 address)
{
	HPDevice *newReader = (HPDevice *) calloc(1, sizeof(HPDevice));

	if (!newReader)
	{
		DebugLogA("memory allocation failure");
		return list;
	}

	newReader->m_driver = HPDriverCopy(bundle);
	newReader->m_address = address;
	newReader->m_next = list;

	return newReader;
}

/*
 * Frees resources allocated to a HPDeviceList.
 */
static void HPDeviceListRelease(HPDeviceList list)
{
	HPDevice *p;

	for (p = list; p; p = p->m_next)
		HPDriverRelease(p->m_driver);
}

/*
 * Compares two driver bundle instances for equality.
 */
static int HPDeviceEquals(HPDevice * a, HPDevice * b)
{
	return (a->m_driver->m_vendorId == b->m_driver->m_vendorId)
		&& (a->m_driver->m_productId == b->m_driver->m_productId)
		&& (a->m_address == b->m_address);
}

/*
 * Finds USB devices currently registered in the system that match any of
 * the drivers detected in the driver bundle vector.
 */
static int
HPDriversMatchUSBDevices(HPDriverVector driverBundle,
	HPDeviceList * readerList)
{
	CFDictionaryRef usbMatch = IOServiceMatching("IOUSBDevice");

	if (0 == usbMatch)
	{
		DebugLogA("error getting USB match from IOServiceMatching()");
		return 1;
	}

	io_iterator_t usbIter;
	kern_return_t kret = IOServiceGetMatchingServices(kIOMasterPortDefault,
		usbMatch, &usbIter);

	if (kret != 0)
	{
		DebugLogA
			("error getting iterator from IOServiceGetMatchingServices()");
		return 1;
	}

	IOIteratorReset(usbIter);
	io_object_t usbDevice = 0;

	while ((usbDevice = IOIteratorNext(usbIter)))
	{
		char namebuf[1024];

		kret = IORegistryEntryGetName(usbDevice, namebuf);
		if (kret != 0)
		{
			DebugLogA
				("error getting device name from IORegistryEntryGetName()");
			return 1;
		}

		IOCFPlugInInterface **iodev;
		SInt32 score;

		kret = IOCreatePlugInInterfaceForService(usbDevice,
			kIOUSBDeviceUserClientTypeID,
			kIOCFPlugInInterfaceID, &iodev, &score);
		if (kret != 0)
		{
			DebugLogA
				("error getting plugin interface from IOCreatePlugInInterfaceForService()");
			return 1;
		}
		IOObjectRelease(usbDevice);

		IOUSBDeviceInterface **usbdev;
		HRESULT hres = (*iodev)->QueryInterface(iodev,
			CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID),
			(LPVOID *) & usbdev);

		(*iodev)->Release(iodev);
		if (hres)
		{
			DebugLogA("error querying interface in QueryInterface()");
			return 1;
		}

		UInt16 vendorId = 0;
		UInt16 productId = 0;
		UInt32 usbAddress = 0;

		kret = (*usbdev)->GetDeviceVendor(usbdev, &vendorId);
		kret = (*usbdev)->GetDeviceProduct(usbdev, &productId);
		kret = (*usbdev)->GetLocationID(usbdev, &usbAddress);
		(*usbdev)->Release(usbdev);

		HPDriver *driver;
		for (driver = driverBundle; driver->m_vendorId; ++driver)
		{
			if ((driver->m_vendorId == vendorId)
				&& (driver->m_productId == productId))
			{
				*readerList =
					HPDeviceListInsert(*readerList, driver, usbAddress);
			}
		}
	}

	IOObjectRelease(usbIter);
	return 0;
}

/*
 * Finds PC Card devices currently registered in the system that match any of
 * the drivers detected in the driver bundle vector.
 */
static int
HPDriversMatchPCCardDevices(HPDriver * driverBundle,
	HPDeviceList * readerList)
{
	CFDictionaryRef pccMatch = IOServiceMatching("IOPCCard16Device");

	if (pccMatch == NULL)
	{
		DebugLogA("error getting PCCard match from IOServiceMatching()");
		return 1;
	}

	io_iterator_t pccIter;
	kern_return_t kret =
		IOServiceGetMatchingServices(kIOMasterPortDefault, pccMatch,
		&pccIter);
	if (kret != 0)
	{
		DebugLogA("error getting iterator from IOServiceGetMatchingServices()");
		return 1;
	}

	IOIteratorReset(pccIter);
	io_object_t pccDevice = 0;

	while ((pccDevice = IOIteratorNext(pccIter)))
	{
		char namebuf[1024];

		kret = IORegistryEntryGetName(pccDevice, namebuf);
		if (kret != 0)
		{
			DebugLogA("error getting plugin interface from IOCreatePlugInInterfaceForService()");
			return 1;
		}
		UInt32 vendorId = 0;
		UInt32 productId = 0;
		UInt32 pccAddress = 0;
		CFTypeRef valueRef =
			IORegistryEntryCreateCFProperty(pccDevice, CFSTR("VendorID"),
			kCFAllocatorDefault, NULL);

		if (!valueRef)
		{
			DebugLogA("error getting vendor");
		}
		else
		{
			CFNumberGetValue((CFNumberRef) valueRef, kCFNumberSInt32Type,
				&vendorId);
		}
		valueRef =
			IORegistryEntryCreateCFProperty(pccDevice, CFSTR("DeviceID"),
			kCFAllocatorDefault, NULL);
		if (!valueRef)
		{
			DebugLogA("error getting device");
		}
		else
		{
			CFNumberGetValue((CFNumberRef) valueRef, kCFNumberSInt32Type,
				&productId);
		}
		valueRef =
			IORegistryEntryCreateCFProperty(pccDevice, CFSTR("SocketNumber"),
			kCFAllocatorDefault, NULL);
		if (!valueRef)
		{
			DebugLogA("error getting PC Card socket");
		}
		else
		{
			CFNumberGetValue((CFNumberRef) valueRef, kCFNumberSInt32Type,
				&pccAddress);
		}
		HPDriver *driver = driverBundle;

		for (; driver->m_vendorId; ++driver)
		{
			if ((driver->m_vendorId == vendorId)
				&& (driver->m_productId == productId))
			{
				*readerList =
					HPDeviceListInsert(*readerList, driver, pccAddress);
			}
		}
	}
	IOObjectRelease(pccIter);
	return 0;
}


static void HPEstablishUSBNotification(void)
{
	io_iterator_t deviceAddedIterator;
	io_iterator_t deviceRemovedIterator;
	CFMutableDictionaryRef matchingDictionary;
	IONotificationPortRef notificationPort;
	IOReturn kret;

	notificationPort = IONotificationPortCreate(kIOMasterPortDefault);
	CFRunLoopAddSource(CFRunLoopGetCurrent(),
		IONotificationPortGetRunLoopSource(notificationPort),
		kCFRunLoopDefaultMode);

	matchingDictionary = IOServiceMatching("IOUSBDevice");
	if (!matchingDictionary)
	{
		DebugLogB("IOServiceMatching() failed", 0);
	}
	matchingDictionary =
		(CFMutableDictionaryRef) CFRetain(matchingDictionary);

	kret = IOServiceAddMatchingNotification(notificationPort,
		kIOMatchedNotification,
		matchingDictionary, HPDeviceAppeared, NULL, &deviceAddedIterator);
	if (kret)
	{
		DebugLogB("IOServiceAddMatchingNotification()-1 failed with code %d",
			kret);
	}
	HPDeviceAppeared(NULL, deviceAddedIterator);

	kret = IOServiceAddMatchingNotification(notificationPort,
		kIOTerminatedNotification,
		matchingDictionary,
		HPDeviceDisappeared, NULL, &deviceRemovedIterator);
	if (kret)
	{
		DebugLogB("IOServiceAddMatchingNotification()-2 failed with code %d",
			kret);
	}
	HPDeviceDisappeared(NULL, deviceRemovedIterator);
}

static void HPEstablishPCCardNotification(void)
{
	io_iterator_t deviceAddedIterator;
	io_iterator_t deviceRemovedIterator;
	CFMutableDictionaryRef matchingDictionary;
	IONotificationPortRef notificationPort;
	IOReturn kret;

	notificationPort = IONotificationPortCreate(kIOMasterPortDefault);
	CFRunLoopAddSource(CFRunLoopGetCurrent(),
		IONotificationPortGetRunLoopSource(notificationPort),
		kCFRunLoopDefaultMode);

	matchingDictionary = IOServiceMatching("IOPCCard16Device");
	if (!matchingDictionary)
	{
		DebugLogB("IOServiceMatching() failed", 0);
	}
	matchingDictionary =
		(CFMutableDictionaryRef) CFRetain(matchingDictionary);

	kret = IOServiceAddMatchingNotification(notificationPort,
		kIOMatchedNotification,
		matchingDictionary, HPDeviceAppeared, NULL, &deviceAddedIterator);
	if (kret)
	{
		DebugLogB("IOServiceAddMatchingNotification()-1 failed with code %d",
			kret);
	}
	HPDeviceAppeared(NULL, deviceAddedIterator);

	kret = IOServiceAddMatchingNotification(notificationPort,
		kIOTerminatedNotification,
		matchingDictionary,
		HPDeviceDisappeared, NULL, &deviceRemovedIterator);
	if (kret)
	{
		DebugLogB("IOServiceAddMatchingNotification()-2 failed with code %d",
			kret);
	}
	HPDeviceDisappeared(NULL, deviceRemovedIterator);
}

/*
 * Thread runner (does not return).
 */
static void HPDeviceNotificationThread(void)
{
	HPEstablishUSBNotification();
	HPEstablishPCCardNotification();
	CFRunLoopRun();
}

/*
 * Scans the hotplug driver directory and looks in the system for
 * matching devices.
 * Adds or removes matching readers as necessary.
 */
LONG HPSearchHotPluggables(void)
{
	HPDriver *drivers = HPDriversGetFromDirectory(PCSCLITE_HP_DROPDIR);

	if (!drivers)
		return 1;

	HPDeviceList devices = NULL;

	if (HPDriversMatchUSBDevices(drivers, &devices))
		return -1;

	if (HPDriversMatchPCCardDevices(drivers, &devices))
		return -1;

	HPDevice *a;

	for (a = devices; a; a = a->m_next)
	{
		int found = FALSE;
		HPDevice *b;

		for (b = sDeviceList; b; b = b->m_next)
		{
			if (HPDeviceEquals(a, b))
			{
				found = TRUE;
				break;
			}
		}
		if (!found)
		{
			/* NOTE: The deviceName is an empty string "" until someone
			 * implements the code to get it */
			RFAddReader(a->m_driver->m_friendlyName,
				PCSCLITE_HP_BASE_PORT + a->m_address, a->m_driver->m_libPath, "");
		}
	}

	for (a = sDeviceList; a; a = a->m_next)
	{
		int found = FALSE;
		HPDevice *b;

		for (b = devices; b; b = b->m_next)
		{
			if (HPDeviceEquals(a, b))
			{
				found = TRUE;
				break;
			}
		}
		if (!found)
		{
			RFRemoveReader(a->m_driver->m_friendlyName,
				PCSCLITE_HP_BASE_PORT + a->m_address);
		}
	}

	HPDeviceListRelease(sDeviceList);
	sDeviceList = devices;
	HPDriverVectorRelease(drivers);

	return 0;
}


PCSCLITE_THREAD_T sHotplugWatcherThread;

/*
 * Sets up callbacks for device hotplug events.
 */
ULONG HPRegisterForHotplugEvents(void)
{
	SYS_ThreadCreate(&sHotplugWatcherThread,
		NULL, (LPVOID) HPDeviceNotificationThread, NULL);

	return 0;
}

LONG HPStopHotPluggables(void)
{
	return 0;
}

#endif	/* __APPLE__ */

