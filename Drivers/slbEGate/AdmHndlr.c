/*****************************************************************
/
/ File   :   AdmHndlr.c
/ Author :   David Corcoran
/ Date   :   October 15, 1999
/ Purpose:   This handles administrative functions like reset/power.
/            See http://www.linuxnet.com for more information.
/ License:   See file LICENSE
/
******************************************************************/

#include "pcscdefines.h"
#include "AdmHndlr.h"
#include "usbserial_osx.h"
#include <time.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/USB.h>
#include <IOKit/usb/USBSpec.h>
#include <IOKit/usb/IOUSBLib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFPlugIn.h>
#include <CoreFoundation/CFBundle.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include <stdio.h>


DWORD timeOut = 500000;

void RawDeviceAdded(void *, io_iterator_t);
void RawDeviceRemoved(void *, io_iterator_t);

static io_iterator_t gRawAddedIter;
static io_iterator_t gRawRemovedIter;
static IONotificationPortRef gNotifyPort;

/*
 * A list to keep track of 20 simultaneous readers 
 */

static long hpManu_id, hpProd_id;
static CFMutableDictionaryRef matchingDict;

static int deviceStatus = 0;


void RawDeviceAdded(void *refCon, io_iterator_t iterator)
{
        ULONG rv;
	kern_return_t kr;
	io_service_t obj;

	while (obj = IOIteratorNext(iterator))
	{
            rv = OpenUSB(0);
            usleep(500000);
            deviceStatus = 1;
            kr = IOObjectRelease(obj);
	}

}

void RawDeviceRemoved(void *refCon, io_iterator_t iterator)
{
	kern_return_t kr;
	io_service_t obj;

	while (obj = IOIteratorNext(iterator))
	{
            CloseUSB(0);
            deviceStatus = 0;
            kr = IOObjectRelease(obj);
	}
}

void HPEstablishUSBNotifications()
{
        io_iterator_t 		iter = 0;
        mach_port_t 		tmpMasterPort;
	const char 		*cStringValue;
	CFStringRef 		propertyString;
	kern_return_t 		kr;
	CFRunLoopSourceRef 	runLoopSource;
	int 			i;

        // first create a master_port for my task
        kr = IOMasterPort(MACH_PORT_NULL, &tmpMasterPort);
        if (kr || !tmpMasterPort)
        {
            printf("ERR: Couldn't create a master IOKit Port(%08x)\n", kr);
            return;
        }

                hpManu_id = 0x0973;
		hpProd_id = 0x0001;

		// Set up the matching criteria for the devices we're interested
		// in
		matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
                
		if (!matchingDict)
		{
                    printf("Can't make USBMatch dict.\n");
		}
		// Add our vendor and product IDs to the matching criteria
		CFDictionarySetValue(matchingDict,
                                        CFSTR(kUSBVendorName),
                                        CFNumberCreate(kCFAllocatorDefault, 
                                        kCFNumberSInt32Type,
                                        &hpManu_id));
		CFDictionarySetValue(matchingDict,
                                        CFSTR(kUSBProductName), 
                                        CFNumberCreate(kCFAllocatorDefault,
                                        kCFNumberSInt32Type, 
                                        &hpProd_id));



		// Create a notification port and add its run loop event source to 
		// our run loop
		// This is how async notifications get set up.
		gNotifyPort = IONotificationPortCreate(tmpMasterPort);
		runLoopSource = IONotificationPortGetRunLoopSource(gNotifyPort);

		CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource,
                                    kCFRunLoopDefaultMode);

		// Retain additional references because we use this same
		// dictionary with four calls to 
		// IOServiceAddMatchingNotification, each of which consumes one
		// reference.
		matchingDict =
			(CFMutableDictionaryRef) CFRetain(matchingDict);
		matchingDict =
			(CFMutableDictionaryRef) CFRetain(matchingDict);
		matchingDict =
			(CFMutableDictionaryRef) CFRetain(matchingDict);

		// Now set up two notifications, one to be called when a raw
		// device is first matched by I/O Kit, and the other to be
		// called when the device is terminated.
		kr = IOServiceAddMatchingNotification(gNotifyPort,
                                                        kIOFirstMatchNotification,
                                                        matchingDict,
                                                        RawDeviceAdded, NULL, 
                                                        &gRawAddedIter);

		/*
		 * The void * 1 allows me to distinguish this initialization
		 * packet from a real event so that I can filter it well 
		 */

		RawDeviceAdded(NULL, gRawAddedIter);

		kr = IOServiceAddMatchingNotification(gNotifyPort,
                                                        kIOTerminatedNotification,
                                                        matchingDict,
                                                        RawDeviceRemoved, NULL, 
                                                        &gRawRemovedIter);

		RawDeviceRemoved(NULL, gRawRemovedIter);
        
        // Now done with the master_port
        mach_port_deallocate(mach_task_self(), tmpMasterPort);
        tmpMasterPort = 0;

	CFRunLoopRun();

}

DWORD Adm_IsICCPresent( DWORD Lun ) {
  return deviceStatus;
}


DWORD Adm_ResetICC( DWORD Lun, PUCHAR Atr, PDWORD AtrLength) {

  ULONG rv;
  UCHAR ucCommand[MAX_BUFFER_SIZE];
  UCHAR ucResponse[MAX_BUFFER_SIZE];
  unsigned long int len;

  ucCommand[0] = 0x90; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
  ucCommand[3] = 0x00; ucCommand[4] = 0x00;  ucCommand[5] = 0x00;

  rv = ControlUSB(Lun, 0, 5, ucCommand, 0, ucResponse); 

  ucCommand[0] = 0x83; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
  ucCommand[3] = 0x00; ucCommand[4] = 0x00;  ucCommand[5] = 0x00;

  len = 64;

  rv = ControlUSB(Lun, 1, 5, ucCommand, &len, ucResponse);

  if ( rv == STATUS_SUCCESS ) {
    memcpy(Atr, &ucResponse, len);
    *AtrLength = len;
    return STATUS_SUCCESS;
  } else {
    *AtrLength = 0;
    return STATUS_UNSUCCESSFUL;
  }

  
}

UCHAR Adm_PollStatus( DWORD Lun ) {

  DWORD rv;
  UCHAR ucCommand[MAX_BUFFER_SIZE];
  UCHAR ucResponse[MAX_BUFFER_SIZE];
  DWORD ulRecvLength;
  int transferType;

  do {

  ucCommand[0] = 0xA0; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
  ucCommand[3] = 0x00; ucCommand[4] = 0x00;    

  ulRecvLength  = 1;
  ucResponse[0] = 0;
  ControlUSB(Lun, 1, 5, ucCommand, 
	     &ulRecvLength, ucResponse);


  if ( ucResponse[0] & 0x10 ) {
    transferType = 1;
    break;
  } else if ( ucResponse[0] & 0x20 ) {
    transferType = 2;
    break;
  } else if ( ucResponse[0] & 0x40 ) {
    usleep(5000);
    continue;
  } else if ( ucResponse[0] & 0x80 ) {
    return -1;
  } else {
    return -1;
  }

  } while (1);

  return transferType;
}


DWORD Adm_TransmitICC( DWORD Lun, PUCHAR pucTxBuffer, DWORD ulTxLength, 
		       PUCHAR pucRxBuffer, PDWORD pulRxLength ) {

  DWORD rv;
  UCHAR ucCommand[MAX_BUFFER_SIZE];
  UCHAR ucResponse[MAX_BUFFER_SIZE];
  DWORD ulRecvLength, ulTimeout;
  int i, numberSends;
  int remainingData;
  int transferType;

  ulTimeout = 0;

#define USB_MAXPACKET_SIZE 8

  
  /* Send APDU */

  ucCommand[0] = 0x80; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
  ucCommand[3] = 0x00; ucCommand[4] = 0x00;
  
  
  memcpy(&ucCommand[5], pucTxBuffer, 5);
  
  ControlUSB(Lun, 0, 10, ucCommand, 
	     0, ucResponse);

  transferType = Adm_PollStatus(Lun);

  if ( (transferType == 1) && (ulTxLength > 5) ) {    
    /* Send Data */    
    
    ucCommand[0] = 0x82; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
    ucCommand[3] = 0x00; ucCommand[4] = 0x00;
    
    memcpy(&ucCommand[5], &pucTxBuffer[5], ulTxLength - 5);
    ControlUSB(Lun, 0, ulTxLength, ucCommand, 0, ucResponse);
    
    transferType = Adm_PollStatus(Lun);
    
    if ( transferType == 2 ) {
      ucCommand[0] = 0x81; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
      ucCommand[3] = 0x00; ucCommand[4] = 0x00;
      
      ulRecvLength = 2;
      
      ControlUSB(Lun, 1, 5, ucCommand, 
		 &ulRecvLength, ucResponse);
      
      memcpy( pucRxBuffer, ucResponse, ulRecvLength );
      *pulRxLength = 2;
    }
    
    
  } else if ( transferType == 1 && ulTxLength == 5 ) {

    /* Send Data */    
    numberSends   = (pucTxBuffer[4]) / USB_MAXPACKET_SIZE;
    remainingData = (pucTxBuffer[4]) % USB_MAXPACKET_SIZE;

    ucCommand[0] = 0x81; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
    ucCommand[3] = 0x00; ucCommand[4] = 0x00;
    
    ulRecvLength = pucTxBuffer[4];
    
    ControlUSB(Lun, 1, 5, ucCommand, 
	       &ulRecvLength, ucResponse);
    
    transferType = Adm_PollStatus(Lun);

    if ( transferType == 2 ) {
      ucCommand[0] = 0x81; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
      ucCommand[3] = 0x00; ucCommand[4] = 0x00;
      
      ulRecvLength = 2;

      ControlUSB(Lun, 1, 5, ucCommand, 
		 &ulRecvLength, &ucResponse[pucTxBuffer[4]]);
      
      memcpy( pucRxBuffer, ucResponse, pucTxBuffer[4] + 2 );
      *pulRxLength = pucTxBuffer[4] + 2;
    }

    
  } else if ( transferType == 2 ) {

    ucCommand[0] = 0x81; ucCommand[1] = 0x00; ucCommand[2] = 0x00;
    ucCommand[3] = 0x00; ucCommand[4] = 0x00;
    
    ulRecvLength = 2;
    
    ControlUSB(Lun, 1, 5, ucCommand, 
	       &ulRecvLength, ucResponse);
    
    memcpy( pucRxBuffer, ucResponse, ulRecvLength );
    *pulRxLength = 2;    
    
    return STATUS_SUCCESS;
  }

  return STATUS_SUCCESS;
}

