/******************************************************************

        MUSCLE SmartCard Development ( http://www.linuxnet.com )
            Title  : mscdefines.h
            Package: MuscleCard Framework
            Author : David Corcoran
            Date   : 10/02/01
            License: Copyright (C) 2001-2002 David Corcoran
                     <corcoran@linuxnet.com>
            Purpose: This provides high level definitions for
                     data types, structures.

	    You may not remove this header from this file
	    without prior permission from the author.
   
********************************************************************/

#ifndef __mscdefines_h__
#define __mscdefines_h__

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__APPLE__)
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#ifndef MAX_BUFFER_SIZE
#define MAX_BUFFER_SIZE		265
#endif

	/*
	 * Some type defines used in MuscleCard 
	 */

	typedef unsigned long MSC_RV;
	typedef char MSCChar8;
	typedef unsigned char *MSCPUChar8;
	typedef const unsigned char *MSCPCUChar8;
	typedef unsigned char MSCUChar8;
	typedef unsigned short *MSCPUShort16;
	typedef unsigned short MSCUShort16;
	typedef short *MSCPShort16;
	typedef short MSCShort16;
	typedef unsigned long *MSCPULong32;
	typedef unsigned long MSCULong32;
	typedef long *MSCPLong32;
	typedef long MSCLong32;
	typedef const void *MSCPCVoid32;
	typedef void *MSCPVoid32;
	typedef const char *MSCCString;
	typedef char *MSCString;

	typedef struct
	{
		MSCPVoid32 pvfWriteFramework;
		MSCPVoid32 pvfInitializePlugin;
		MSCPVoid32 pvfIdentifyToken;
		MSCPVoid32 pvfFinalizePlugin;
		MSCPVoid32 pvfGetStatus;
		MSCPVoid32 pvfGetCapabilities;
		MSCPVoid32 pvfExtendedFeature;
		MSCPVoid32 pvfGenerateKeys;
		MSCPVoid32 pvfImportKey;
		MSCPVoid32 pvfExportKey;
		MSCPVoid32 pvfComputeCrypt;
		MSCPVoid32 pvfExtAuthenticate;
		MSCPVoid32 pvfListKeys;
		MSCPVoid32 pvfCreatePIN;
		MSCPVoid32 pvfVerifyPIN;
		MSCPVoid32 pvfChangePIN;
		MSCPVoid32 pvfUnblockPIN;
		MSCPVoid32 pvfListPINs;
		MSCPVoid32 pvfCreateObject;
		MSCPVoid32 pvfDeleteObject;
		MSCPVoid32 pvfWriteObject;
		MSCPVoid32 pvfReadObject;
		MSCPVoid32 pvfListObjects;
		MSCPVoid32 pvfLogoutAll;
		MSCPVoid32 pvfGetChallenge;

	}
	CFDyLibPointers, *LPCFDyLibPointers;

#define MSC_MAXSIZE_TOKENAME      150
#define MSC_MAXSIZE_SVCPROV       200
#define MSC_MAXSIZE_OBJID          16
#define MSC_MAXSIZE_AID            64
#define MSC_MAXSIZE_MAC           128
#define MSC_MAXSIZE_LABEL          32
#define MSC_MAXSIZE_CERT_ISSUER    512
#define MSC_MAXSIZE_CERT_SUBJECT   512
#define MSC_MAXSIZE_CERT_SERIAL    512
#define MSC_MAXSIZE_BUFFER     MAX_BUFFER_SIZE

	typedef struct
	{
	        MSCChar8 tokenName[MSC_MAXSIZE_TOKENAME]; /* Token name */ 
                MSCChar8 slotName[MAX_READERNAME];	/* Slot/reader name */
		MSCChar8 svProvider[MSC_MAXSIZE_SVCPROV]; /* Library */
		MSCUChar8 tokenId[MAX_ATR_SIZE];     /* Token ID (ATR) */
		MSCUChar8 tokenApp[MSC_MAXSIZE_AID]; /* Default app ID */
		MSCULong32 tokenAppLen;	  /* Default AID Length */
		MSCULong32 tokenIdLength; /* ID Length (ATR Length) */
		MSCULong32 tokenState;	  /* State (dwEventState) */
		MSCULong32 tokenType;	  /* Type - RFU */
		MSCPVoid32 addParams;	  /* Additional Data */
		MSCULong32 addParamsSize; /* Size of additional data */
	}
	MSCTokenInfo, *MSCLPTokenInfo;

	/*
	 * Callback function definitions 
	 */

	typedef MSCULong32(*MSCCallBack) (MSCLPTokenInfo, MSCULong32,
					  MSCPVoid32);

	typedef struct
	{
		MSCULong32 arraySize;
		MSCLPTokenInfo tokenArray;
		MSCPVoid32 appData;
		MSCCallBack callBack;
	}
	MSCEventWaitInfo, *MSCLPEventWaitInfo;

	typedef MSC_RV(*LPRWEventCallback) (MSCPVoid32, int);

	typedef struct
	{
		MSCLong32 hContext;	      /* Handle to resource manager */
		MSCLong32 hCard;	      /* Handle to the connection */
		LPSCARD_IO_REQUEST ioType;    /* Type of protocol */
		MSCUChar8 pMac[MSC_MAXSIZE_MAC];  /* MAC code */
		MSCULong32 macSize;	      /* Size of the MAC code */
		MSCPVoid32 tokenLibHandle;    /* Handle to token library */
		CFDyLibPointers libPointers;  /* Function pointers */
		MSCTokenInfo tokenInfo;	/* token information */
		MSCUChar8 loggedIDs;	/* Verification bit mask */
		MSCULong32 shareMode;	/* Sharing mode for this */
		LPRWEventCallback rwCallback;	/* Registered callback */
	}
	MSCTokenConnection, *MSCLPTokenConnection;

#define MSC_OK MSC_SUCCESS

#ifdef __cplusplus
}
#endif

#endif							/* __mscdefines_h__ */
