/*
 * This keeps track of a list of currently available reader structures.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#ifndef __readerfactory_h__
#define __readerfactory_h__

#include <thread_generic.h>

#ifdef __cplusplus
extern "C"
{
#endif

	struct FctMap
	{
		LPVOID pvfCreateChannel;
		LPVOID pvfCreateChannelByName;	/* MUSCLE IFD 3.0 Compliance */
		LPVOID pvfCloseChannel;
		LPVOID pvfGetCapabilities;
		LPVOID pvfSetCapabilities;
		LPVOID pvfSetProtocol;
		LPVOID pvfPowerICC;
		LPVOID pvfSwallowICC;		/* Deprecated in 2.0 */
		LPVOID pvfEjectICC;		/* Deprecated in 2.0 */
		LPVOID pvfConfiscateICC;	/* Deprecated in 2.0 */
		LPVOID pvfTransmitICC;
		LPVOID pvfICCPresent;
		LPVOID pvfICCAbsent;		/* Deprecated in 2.0 */
		LPVOID pvfControl;		/* MUSCLE IFD 2.0 Compliance */
	};

	typedef struct FctMap FCT_MAP, *PFCT_MAP;

	/*
	 * The following is not currently used but in place if needed 
	 */

	struct RdrCapabilities
	{
		DWORD dwAsynch_Supported;	/* Asynchronous Support */
		DWORD dwDefault_Clock;	/* Default Clock Rate */
		DWORD dwMax_Clock;		/* Max Clock Rate */
		DWORD dwDefault_Data_Rate;	/* Default Data Rate */
		DWORD dwMax_Data_Rate;	/* Max Data Rate */
		DWORD dwMax_IFSD;		/* Maximum IFSD Size */
		DWORD dwSynch_Supported;	/* Synchronous Support */
		DWORD dwPower_Mgmt;		/* Power Mgmt Features */
		DWORD dwCard_Auth_Devices;	/* Card Auth Devices */
		DWORD dwUser_Auth_Device;	/* User Auth Devices */
		DWORD dwMechanics_Supported;	/* Machanics Supported */
		DWORD dwVendor_Features;	/* User Defined.  */
	};

	typedef struct RdrCapabilities RDR_CAPABILITIES, *PRDR_CAPABILITIES;

	struct ProtOptions
	{
		DWORD dwProtocol_Type;	/* Protocol Type */
		DWORD dwCurrent_Clock;	/* Current Clock */
		DWORD dwCurrent_F;		/* Current F */
		DWORD dwCurrent_D;		/* Current D */
		DWORD dwCurrent_N;		/* Current N */
		DWORD dwCurrent_W;		/* Current W */
		DWORD dwCurrent_IFSC;	/* Current IFSC */
		DWORD dwCurrent_IFSD;	/* Current IFSD */
		DWORD dwCurrent_BWT;	/* Current BWT */
		DWORD dwCurrent_CWT;	/* Current CWT */
		DWORD dwCurrent_EBC;	/* Current EBC */
	};

	typedef struct ProtOptions PROT_OPTIONS, *PPROT_OPTIONS;

	struct RdrCliHandles
	{
		SCARDHANDLE hCard;		/* hCard for this connection */
		DWORD dwEventStatus;	/* Recent event that must be sent */
	};

	typedef struct RdrCliHandles RDR_CLIHANDLES, *PRDR_CLIHANDLES;

	struct ReaderContext
	{
		char lpcReader[MAX_READERNAME];	/* Reader Name */
		char lpcLibrary[MAX_LIBNAME];	/* Library Path */
		char lpcDevice[MAX_DEVICENAME];	/* Device Name */
		PCSCLITE_THREAD_T pthThread;	/* Event polling thread */
		PCSCLITE_MUTEX_T mMutex;	/* Mutex for this connection */
		RDR_CAPABILITIES psCapabilites;	/* Structure of reader
						   capabilities */
		PROT_OPTIONS psProtOptions;	/* Structure of protocol options */
		RDR_CLIHANDLES psHandles[PCSCLITE_MAX_READER_CONTEXT_CHANNELS];	
                                         /* Structure of connected handles */
		FCT_MAP psFunctions;	/* Structure of function pointers */
		UCHAR ucAtr[MAX_ATR_SIZE];	/* Atr for inserted card */
		DWORD dwAtrLen;			/* Size of the ATR */
		LPVOID vHandle;			/* Dlopen handle */
		DWORD dwVersion;		/* IFD Handler version number */
		DWORD dwPort;			/* Port ID */
		DWORD dwProtocol;		/* Currently used protocol */
		DWORD dwSlot;			/* Current Reader Slot */
		DWORD dwBlockStatus;	/* Current blocking status */
		DWORD dwStatus;			/* Current Status Mask */
		DWORD dwLockId;			/* Lock Id */
		DWORD dwIdentity;		/* Shared ID High Nibble */
		DWORD dwContexts;		/* Number of open contexts */
		DWORD dwPublicID;		/* Public id of public state struct */
		PDWORD pdwFeeds;		/* Number of shared client to lib */
		PDWORD pdwMutex;		/* Number of client to mutex */
	};

	typedef struct ReaderContext READER_CONTEXT, *PREADER_CONTEXT;

	LONG RFAllocateReaderSpace(DWORD);
	LONG RFAddReader(LPTSTR, DWORD, LPTSTR, LPTSTR);
	LONG RFRemoveReader(LPTSTR, DWORD);
	LONG RFSetReaderName(PREADER_CONTEXT, LPTSTR, LPTSTR, DWORD, DWORD);
	LONG RFListReaders(LPTSTR, LPDWORD);
	LONG RFReaderInfo(LPTSTR, struct ReaderContext **);
	LONG RFReaderInfoNamePort(DWORD, LPTSTR, struct ReaderContext **);
	LONG RFReaderInfoById(DWORD, struct ReaderContext **);
	LONG RFCheckSharing(DWORD);
	LONG RFLockSharing(DWORD);
	LONG RFUnlockSharing(DWORD);
	LONG RFUnblockReader(PREADER_CONTEXT);
	LONG RFUnblockContext(SCARDCONTEXT);
	LONG RFLoadReader(PREADER_CONTEXT);
	LONG RFBindFunctions(PREADER_CONTEXT);
	LONG RFUnBindFunctions(PREADER_CONTEXT);
	LONG RFUnloadReader(PREADER_CONTEXT);
	LONG RFInitializeReader(PREADER_CONTEXT);
	LONG RFUnInitializeReader(PREADER_CONTEXT);
	SCARDHANDLE RFCreateReaderHandle(PREADER_CONTEXT);
	LONG RFDestroyReaderHandle(SCARDHANDLE hCard);
	LONG RFAddReaderHandle(PREADER_CONTEXT, SCARDHANDLE);
	LONG RFFindReaderHandle(SCARDHANDLE);
	LONG RFRemoveReaderHandle(PREADER_CONTEXT, SCARDHANDLE);
	LONG RFSetReaderEventState(PREADER_CONTEXT, DWORD);
	LONG RFCheckReaderEventState(PREADER_CONTEXT, SCARDHANDLE);
	LONG RFClearReaderEventState(PREADER_CONTEXT, SCARDHANDLE);
	LONG RFCheckReaderStatus(PREADER_CONTEXT);
	void RFCleanupReaders(int);
        void RFSuspendAllReaders(); 
        void RFAwakeAllReaders(); 

#ifdef __cplusplus
}
#endif

#endif
