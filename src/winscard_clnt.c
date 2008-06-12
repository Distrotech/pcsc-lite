/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This handles smartcard reader communications and
 * forwarding requests over message queues.
 *
 * Here is exposed the API for client applications.
 */

#include <stdio.h>
#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <strings.h>
#include <arpa/inet.h>
#include <errno.h>
#include <thread.h>
#include <syslog.h>

#include "misc.h"
#include "pcsclite.h"
#include "winscard.h"
#include "pcsc_config.h"
#include "debug.h"
#include "thread_generic.h"

#include "readerfactory.h"
#include "eventhandler.h"
#include "sys_generic.h"
#include "winscard_msg.h"
#include "profile.h"

struct pcsc_cfg_data pcscCfg;

/** used for backward compatibility */
#define SCARD_PROTOCOL_ANY_OLD	0x1000

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

FILE *dbgFp;

/**
 * Represents an Application Context Channel.
 * A channel belongs to an Application Context (\c _psContextMap).
 */
struct _psChannelMap
{
	SCARDHANDLE hCard;
	LPSTR readerName;
};

typedef struct _psChannelMap CHANNEL_MAP, *PCHANNEL_MAP;

/**
 * @brief Represents the an Application Context on the Client side.
 *
 * An Application Context contains Channels (\c psChannelMap).
 */
static struct _psContextMap
{
	DWORD dwClientID;				/** Client Connection ID */
	SCARDCONTEXT hContext;			/** Application Context ID */
	DWORD contextBlockStatus;
	PCSCLITE_MUTEX_T mMutex;		/** Mutex for this context */
	CHANNEL_MAP psChannelMap[PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS];
} psContextMap[PCSCLITE_MAX_APPLICATION_CONTEXTS];

/**
 * Make sure the initialization code is executed only once.
 */
static short isExecuted = 0;

/**
 * Memory mapped address used to read status information about the readers.
 * Each element in the vector \c readerStates makes references to a part of
 * the memory mapped.
 */
static int mapAddr = 0;

/**
 * Ensure that some functions be accessed in thread-safe mode.
 * These function's names finishes with "TH".
 */
static PCSCLITE_MUTEX clientMutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Pointers to a memory mapped area used to read status information about the
 * readers.
 * Each element in the vector \c readerStates makes references to a part of
 * the memory mapped \c mapAddr.
 */
static PREADER_STATE readerStates[PCSCLITE_MAX_READERS_CONTEXTS];
static PCSCLITE_MUTEX readerStateMutex = PTHREAD_MUTEX_INITIALIZER;


PCSC_API SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0, 8 };
PCSC_API SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1, 8 };
PCSC_API SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, 8 };

static LONG SCardAddContext(SCARDCONTEXT, DWORD);
static LONG SCardGetContextIndice(SCARDCONTEXT);
static LONG SCardGetContextIndiceTH(SCARDCONTEXT);
static LONG SCardRemoveContext(SCARDCONTEXT);

static LONG SCardAddHandle(SCARDHANDLE, DWORD, LPSTR);
static LONG SCardGetIndicesFromHandle(SCARDHANDLE, PDWORD, PDWORD, PDWORD);
static LONG SCardGetIndicesFromHandleTH(SCARDHANDLE, PDWORD, PDWORD);
static LONG SCardRemoveHandle(SCARDHANDLE);

static LONG SCardGetSetAttrib(SCARDHANDLE hCard, int command, DWORD dwAttrId,
	LPBYTE pbAttr, LPDWORD pcbAttrLen);

static LONG SCardCheckDaemonAvailability(DWORD);

static PCSCLITE_MUTEX contextMutex = PTHREAD_MUTEX_INITIALIZER;
static void (*prevSIGPIPEhand)(int);

/*
 * Configuration routine debug logging routine. * Doesn't enforce line feeds as the global debugging
 * functions do, and only logs to stderr, and
 * and uses and independent debugging switch
 */

#include <stdarg.h>
#define NONULL(a) (a) ? (a) : "<null>"

//#define EXTRA_DEBUGGING
#ifdef EXTRA_DEBUGGING
#define DBG DBG_FUNC
#define DBGERR dbg
#else
#define DBG
#define DBGERR
#endif

void
DBG_FUNC(SCARDCONTEXT hContext, SCARDHANDLE hCard, const char *fmt, ...) {
	char buf[256], tmp[256];
	va_list ap;

	bzero(buf, 256);
	va_start(ap, fmt);
	vsnprintf(buf, 256, fmt, ap);
	va_end(ap);

	if (hContext == 0 && hCard != 0) {
		int i;
		for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++) {
			if (psContextMap[i].hContext != NULL) {
				int j;
				for (j = 0; j < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; j++) {
					if (psContextMap[i].psChannelMap[j].hCard == hCard) {
						hContext = psContextMap[i].hContext;
						break;
					}
				}
			}

		}
	}

	if (hContext != 0)
		sprintf(tmp,"\n[%8.8x, %x] ",
			hContext, thr_self());
	else
		sprintf(tmp,"           ", hContext);
#if 0
	write(2, tmp, strlen(tmp));
	write(2, NONULL(buf), strlen(NONULL(buf)));
#endif
	fprintf(stdout, "%s", tmp);
	fprintf(stdout, "%s", NONULL(buf));
	fflush(stdout);
}

/*
 * Assumes item being fetched is a pointer
 * If memory mapping is enabled, this MACRO is effectively
 * a NOP.
 */
#define FETCH(readerStatePtr, clientId) \
	(fetchReaderState((readerStatePtr), (clientId), __LINE__))

/*
 * This allows us to transparently retrieve the contents of
 * an arbitrary amount of the shared memory from the server
 * over the transport (as an alternative to the memory-mapped
 * file approach.
 */
PREADER_STATE
fetchReaderState(PREADER_STATE rsp, DWORD dwClientID, int dbgline)
{
	int i, rsi, rv;
	static unsigned long fn;

	++fn;

	if (pcscCfg.useMappedMemory)
		return rsp;

	SYS_MutexLock(&readerStateMutex);
	/*
	 * Find readerState array index based on pointer passed.
	 */
	for(rsi = -1, i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++) {
		if (rsp == readerStates[i]) {
			rsi = i;
			break;
		}
	}
	/*
	 * Try to fetch reader state from server.
	 * If that fails, return NULL.
	 * Disregard and re-try if EINTR and EAGAIN status is received.
	 */
	do {
		rv = SHMfetchReaderState(rsp, rsi, dwClientID);
		if (rv < 0) {
			switch(errno) {
			case EINTR:
			case EAGAIN:
				continue;
			default:
				/*
				 * This is a serious condition, but until
				 * we know the synchronization issues are
				 * worked out, we need to try to insulate
				 * the user while not losing track of them.
				 */
				syslog(LOG_ERR,
				    "libpcsclite.so <-> pcscd connection failed."
				    "  Couldn't fetch readerstate thr:%d, #%d\n%s",
					thr_self(), fn, strerror(errno));
				Log4(PCSC_LOG_DEBUG,
				    "libpcsclite.so <-> pcscd connection failed."
				    "  thr:%d, #%d\n%s", thr_self(), fn, strerror(errno));
				SYS_MutexUnLock(&readerStateMutex);
				return NULL;
			}
		}
	} while (rv < 0);
	SYS_MutexUnLock(&readerStateMutex);
	return rsp;
}

void dumpContexts()
{
	int i;
	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++) {
		printf("#%d: context:%x fd=%d\n",
			i, psContextMap[i].hContext, psContextMap[i].dwClientID);
	}
	printf("\n");
}

void
sigpipeHandler(int sig)
{
	void (*hand)(int);

	if (prevSIGPIPEhand != NULL && prevSIGPIPEhand != sigpipeHandler)
		prevSIGPIPEhand(sig);
	hand = sigset(SIGPIPE, sigpipeHandler);

}

static LONG SCardEstablishContextTH(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT);

/**
 * @brief Creates an Application Context to the PC/SC Resource Manager.

 * This must be the first function called in a PC/SC application.
 * This is a thread-safe wrapper to the function \c SCardEstablishContextTH().
 *
 * @param[in] dwScope Scope of the establishment.
 * This can either be a local or remote connection.
 * <ul>
 *   <li>SCARD_SCOPE_USER - Not used.
 *   <li>SCARD_SCOPE_TERMINAL - Not used.
 *   <li>SCARD_SCOPE_GLOBAL - Not used.
 *   <li>SCARD_SCOPE_SYSTEM - Services on the local machine.
 * </ul>
 * @param[in] pvReserved1 Reserved for future use. Can be used for remote connection.
 * @param[in] pvReserved2 Reserved for future use.
 * @param[out] phContext Returned Application Context.
 *
 * @return Connection status.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_NO_SERVICE The server is not runing
 * @retval SCARD_E_INVALID_VALUE Invalid scope type passed.
 * @retval SCARD_E_INVALID_PARAMETER phContext is null.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * @endcode
 */
LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1,
	LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	LONG rv;

	PROFILE_START
	rv = SCardEstablishContextTH(dwScope, pvReserved1,
		pvReserved2, phContext);
	PROFILE_END

	return rv;

}

/**
 * @brief Creates a communication context to the PC/SC Resource
 * Manager.
 *
 * This function shuld not be called directly. Instead, the thread-safe
 * function \c SCardEstablishContext() should be called.
 *
 * @param[in] dwScope Scope of the establishment.
 * This can either be a local or remote connection.
 * <ul>
 *   <li>SCARD_SCOPE_USER - Not used.
 *   <li>SCARD_SCOPE_TERMINAL - Not used.
 *   <li>SCARD_SCOPE_GLOBAL - Not used.
 *   <li>SCARD_SCOPE_SYSTEM - Services on the local machine.
 * </ul>
 * @param[in] pvReserved1 Reserved for future use. Can be used for remote connection.
 * @param[in] pvReserved2 Reserved for future use.
 * @param[out] phContext Returned reference to this connection.
 *
 * @return Connection status.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_NO_SERVICE The server is not runing
 * @retval SCARD_E_INVALID_PARAMETER phContext is null.
 * @retval SCARD_E_INVALID_VALUE Invalid scope type passed.
 */
static LONG SCardEstablishContextTH(DWORD dwScope, LPCVOID pvReserved1,
	LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	LONG rv;
	int i, cfgLoaded = 0;
	establish_struct scEstablishStruct;
	DWORD dwClientID = 0;
	int dpyNbr, screenNbr;
	in_addr_t xHostIp;
	char *homedir, homeconf[256];

	char *cfgSearchPaths[] = {
		"pcscd.conf",
		PCSCLITE_CONFIG_DIR "/pcscd.conf",
	};

	homedir = getenv("HOME");
	if (homedir != NULL) {
		sprintf(homeconf, "%s/pcscd.conf", homedir);
		cfgSearchPaths[0] = homeconf;
	}
	DBG(NULL, NULL, "SCardEstablishContextTH()/\n");

	CFGSetConfigConsumer(CLIENT);

	/*
	 * Get information about display. In some situation
	 * this determines which daemon to conact.
	 */
	 CFGParseXdisplay(SYS_Getenv("DISPLAY"), &dpyNbr, &screenNbr, &xHostIp);
	 pcscCfg.dpyNbr = dpyNbr;
	 pcscCfg.screenNbr = screenNbr;
	 pcscCfg.xHostIp = xHostIp;

	 /*
	  * Do this section only once
	  */
	 if (!isExecuted) {
#ifdef PCSCLITE_PORTSVC_PORTNO
		pcscCfg.portNbr = PCSCLITE_PORTSVC_PORTNO;
		pcscCfg.portNbrWild = 0;
		pcscCfg.launchMode = LAUNCHER;
		CFGDefault("TRANSPORT", "SOCKET_INETV4");
		CFGDefault("USE_MAPPED_MEMORY", "FALSE");
#else

		CFGDefault("PORT_NUMBER", "0");
		CFGDefault("PORT_NUMBER_WILD", "FALSE");
		CFGDefault("TRANSPORT", "SOCKET_UNIX");
		CFGDefault("USE_MAPPED_MEMORY", "TRUE");
#endif

		for (i = 0; i < sizeof(cfgSearchPaths) / sizeof(char *) && !cfgLoaded;
		    i++) {
			switch(rv = CFGLoadConfigFile(cfgSearchPaths[i])) {
			case CFG_SUCCESS:
				pcscCfg.pcscConfigFile = cfgSearchPaths[i];
				cfgLoaded = 1;
				break;
			case CFG_FILE_NOT_FOUND:
				break;
			}
		}
	}

#ifndef PCSCLITE_PORTSVC_PORTNO
	/* Try to figure out where server base directory is in case
	 * we are using that location to try to find the memory mapped
	 * file.
	 */
	if (pcscCfg.baseDir != NULL) {
	       if (pcscCfg.baseDirWild) {
		       char dpyNbr[6];
		       if (pcscCfg.dpyNbr == -1)
			      CFGErrChkCritical(CFG_UNDEFINED_DISPLAY);
		       sprintf(dpyNbr, "%d", pcscCfg.dpyNbr);
		       CFGresolveWildcard(&pcscCfg.baseDir, dpyNbr);
	       }
	}

	/*
	* Adjust port number by the wildcard specifier, if any.
	*/
	if (pcscCfg.portNbrWild) {
		if (pcscCfg.dpyNbr == -1)
			 CFGErrChkCritical(CFG_UNDEFINED_DISPLAY);
		CFGresolveWildcard(&pcscCfg.portNbr, (void *)pcscCfg.dpyNbr);
	}

	/*
	 * Adapt all of the client configuration file paths, assigning
	 * a default value (based on header constants) to any path
	 * unspecified by the administrator.
	 *.
	 * If a base directory was specified, adapt resultant filepaths
	 * to be relative to it using the following method:
	 *
	 *   a. Unspecified files which were assigned default names in the
	 *      first step are put into *default* subtree locations under
	 *      the base dir.
	 *
	 *   b. Filepaths that were specified by the administrator are
	 *      converted from absolute paths to relative paths under the
	 *      base dir.
	 *
	 * Note: If the IFD library plugin dir is specified by the admin,
	 *       it overrides any dir locations specified in readers.conf
	 */
	if (pcscCfg.useMappedMemory) {
	       if (pcscCfg.pcscdMemMappedFile == NULL)
		       pcscCfg.pcscdMemMappedFile =
		       CFGRetrofitPath(PCSCLITE_PUBSHM_FILE, "/var/run");
	       else
		       pcscCfg.pcscdMemMappedFile =
		       CFGRetrofitPath(pcscCfg.pcscdMemMappedFile, NULL);
	} else {
		pcscCfg.pcscdMemMappedFile = NULL;
	}

	if (pcscCfg.transportType == SOCKET_UNIX) {
		if (pcscCfg.netBindFile == NULL) {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(PCSCLITE_CSOCK_NAME, "/var/run");
		} else {
			pcscCfg.netBindFile =
			    CFGRetrofitPath(pcscCfg.netBindFile, NULL);
		}
	}
#endif
	if (pcscCfg.logLevel == INFO || pcscCfg.logLevel == DEBUG)
		CFGdumpCfg(NULL);

	if (phContext == NULL)
		return SCARD_E_INVALID_PARAMETER;
	else
		*phContext = 0;

	/* Check if the server is running */
	if (SCardCheckDaemonAvailability(0) != SCARD_S_SUCCESS)
		return SCARD_E_NO_SERVICE;

	/*
	 * Do this only once:
	 * - Initialize debug of need.
	 * - Set up the memory mapped structures for reader states.
	 * - Allocate each reader structure.
	 * - Initialize context struct.
	 */
	if (isExecuted == 0)
	{
		int pageSize;

		/*
		 * Do any system initilization here
		 */
		SYS_Initialize();

		prevSIGPIPEhand = sigset(SIGPIPE, sigpipeHandler);


		SYS_MutexLock(&readerStateMutex);

		if (pcscCfg.useMappedMemory) {
			/*
			* Set up the memory mapped reader stats structures
			*/
			mapAddr = SYS_OpenFile(pcscCfg.pcscdMemMappedFile,
				O_RDONLY, 0);
			if (mapAddr < 0)
			{
				Log2(PCSC_LOG_CRITICAL,
				"Cannot open public shared file: %s",
				pcscCfg.pcscdMemMappedFile);
				SYS_MutexUnLock(&readerStateMutex);
				return SCARD_E_NO_SERVICE;
			}
			pageSize = SYS_GetPageSize();

			/*
			* Allocate each reader structure in the memory map
			*/
			for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
			{
				readerStates[i] = (PREADER_STATE)
					SYS_PublicMemoryMap(sizeof(READER_STATE),
					mapAddr, (i * pageSize));
				if (readerStates[i] == NULL)
				{
				      Log1(PCSC_LOG_CRITICAL,
					   "Cannot public memory map");
				      SYS_CloseFile(mapAddr);
				      SYS_MutexUnLock(&readerStateMutex);
				      return SCARD_F_INTERNAL_ERROR;
				}
			}

		} else {
			for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
			{
				readerStates[i] =
				   (PREADER_STATE)malloc(sizeof(READER_STATE));
				if (readerStates[i] == NULL)
				{
					Log1(PCSC_LOG_CRITICAL,
						"Out of memory");
					SYS_MutexUnLock(&readerStateMutex);
					return SCARD_F_INTERNAL_ERROR;
				}

			}
		}

		SYS_MutexUnLock(&readerStateMutex);
		/*
		 * Initializes the application contexts and all channels for each one
		 */
		for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++)
		{
			int j;

			/*
			 * Initially set the context struct to zero
			 */
			psContextMap[i].dwClientID = 0;
			psContextMap[i].hContext = 0;
			psContextMap[i].contextBlockStatus = BLOCK_STATUS_RESUME;
			psContextMap[i].mMutex = NULL;

			for (j = 0; j < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; j++)
			{
				/*
				 * Initially set the hcard structs to zero
				 */
				psContextMap[i].psChannelMap[j].hCard = 0;
				psContextMap[i].psChannelMap[j].readerName = NULL;
			}
		}

	}
	SYS_MutexLock(&contextMutex);
       /*
	 * Is there a free slot for this connection ?
	 */

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++)
	{
		if (psContextMap[i].dwClientID == 0)
			break;
	}
	if (i == PCSCLITE_MAX_APPLICATION_CONTEXTS)
	{
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_MEMORY;
	}


	/* Establishes a connection to the server */
	if ((rv = SHMClientSetupSession(&dwClientID)) != 0)
	{
		if (pcscCfg.useMappedMemory)
			SYS_CloseFile(mapAddr);
		Log1(PCSC_LOG_INFO, "SCardEstablishContext(): client setup err");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}
	isExecuted = 1;
	if ((rv = SHMCheckProtocolVersion(
			PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
			dwClientID)) < 0)  {
			Log3(PCSC_LOG_CRITICAL,
			      "Returning error SHMCheckProtocolVersion(): 0x%x (%d)",
				rv, rv);
			SYS_MutexUnLock(&contextMutex);
			return rv;
	}
	isExecuted = 1;


	if (dwScope != SCARD_SCOPE_USER && dwScope != SCARD_SCOPE_TERMINAL &&
		dwScope != SCARD_SCOPE_SYSTEM && dwScope != SCARD_SCOPE_GLOBAL)
	{
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_VALUE;
	}

	/*
	 * Try to establish an Application Context with the server
	 */
	scEstablishStruct.dwScope = dwScope;
	scEstablishStruct.phContext = 0;
	scEstablishStruct.rv = 0;
	scEstablishStruct.clientXhostIP = pcscCfg.xHostIp;
	scEstablishStruct.screenNbr = pcscCfg.screenNbr;
	scEstablishStruct.dpyNbr = pcscCfg.dpyNbr;
	if ((rv = SHMrpc(SCARD_ESTABLISH_CONTEXT,
		dwClientID, &scEstablishStruct, sizeof (scEstablishStruct))) == -1) {
			Log1(PCSC_LOG_INFO, "SCardEstablish(): SHMrpc() returned error");
			SYS_MutexUnLock(&contextMutex);
			return SCARD_F_COMM_ERROR;
	}

	if (scEstablishStruct.rv != SCARD_S_SUCCESS) {
		Log1(PCSC_LOG_INFO, "Returning error from scEstablishStruct.rv");
		SYS_MutexUnLock(&contextMutex);
		return scEstablishStruct.rv;
	}

	*phContext = scEstablishStruct.phContext;
	Log3(PCSC_LOG_DEBUG, "Establish: context:%x, fd=%d\n", *phContext, dwClientID);
	/*
	 * Allocate the new hContext - if allocator full return an error
	 */
	rv = SCardAddContext(*phContext, dwClientID);

	SYS_MutexUnLock(&contextMutex);

	return rv;
}

/**
 * @brief This function destroys a communication context to the PC/SC Resource
 * Manager. This must be the last function called in a PC/SC application.
 *
 * @param[in] hContext Connection context to be closed.
 *
 * @return Connection status.
 * @retval SCARD_S_SUCCESS Successful.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardReleaseContext(hContext);
 * @endcode
 */
LONG SCardReleaseContext(SCARDCONTEXT hContext)
{
	LONG rv;
	release_struct scReleaseStruct;
	DWORD dwContextIndex;

	PROFILE_START

	DBG(hContext, NULL, "SCardReleaseContext()/\n");

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this context has been opened
	 */
	dwContextIndex = SCardGetContextIndice(hContext);
	if (dwContextIndex == -1) {
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	Log3(PCSC_LOG_DEBUG, "Release: context:%x, fd=%d\n", hContext,
		psContextMap[dwContextIndex].dwClientID);

	if (SCardCheckDaemonAvailability(
		psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS) {
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	psContextMap[dwContextIndex].contextBlockStatus = BLOCK_STATUS_RESUME;
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);

	scReleaseStruct.hContext = hContext;
	scReleaseStruct.rv = 0;

	if ((rv = SHMrpc(SCARD_RELEASE_CONTEXT,
			 psContextMap[dwContextIndex].dwClientID,
			 &scReleaseStruct, sizeof (scReleaseStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardReleaseContext(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				SYS_MutexUnLock(&contextMutex);
				return SCARD_F_COMM_ERROR;
	}

	/*
	 * Remove the local context from the stack
	 */
	SCardRemoveContext(hContext);
	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	PROFILE_END

	return scReleaseStruct.rv;
}

/**
 * @deprecated
 * This function is not in Microsoft(R) WinSCard API and is deprecated
 * in pcsc-lite API.
 * The function does not do anything except returning \c SCARD_S_SUCCESS.
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 * @param[in] dwTimeout New timeout value.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 */
LONG SCardSetTimeout(SCARDCONTEXT hContext, DWORD dwTimeout)
{
	/*
	 * Deprecated
	 */

	return SCARD_S_SUCCESS;
}

/**
 * This function establishes a connection to the friendly name of the reader
 * specified in szReader. The first connection will power up and perform a
 * reset on the card.
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 * @param[in] szReader Reader name to connect to.
 * @param[in] dwShareMode Mode of connection type: exclusive or shared.
 * <ul>
 *   <li>SCARD_SHARE_SHARED - This application will allow others to share the reader.
 *   <li>SCARD_SHARE_EXCLUSIVE - This application will NOT allow others to share the reader.
 *   <li>SCARD_SHARE_DIRECT - Direct control of the reader, even without a card.
 *       SCARD_SHARE_DIRECT can be used before using SCardControl() to send
 *       control commands to the reader even if a card is not present in
 *       the reader.
 * </ul>
 * @param[in] dwPreferredProtocols Desired protocol use.
 * <ul>
 *   <li>SCARD_PROTOCOL_T0 - Use the T=0 protocol.
 *   <li>SCARD_PROTOCOL_T1 - Use the T=1 protocol.
 *   <li>SCARD_PROTOCOL_RAW - Use with memory type cards.
 * </ul>
 * dwPreferredProtocols is a bit mask of acceptable protocols for the
 * connection. You can use (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1) if you
 * do not have a preferred protocol.
 * @param[out] phCard Handle to this connection.
 * @param[out] pdwActiveProtocol Established protocol to this connection.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hContext handle.
 * @retval SCARD_E_INVALID_VALUE Invalid sharing mode, requested protocol, or reader name.
 * @retval SCARD_E_NOT_READY Could not allocate the desired port.
 * @retval SCARD_E_READER_UNAVAILABLE Could not power up the reader or card.
 * @retval SCARD_E_SHARING_VIOLATION Someone else has exclusive rights.
 * @retval SCARD_E_UNSUPPORTED_FEATURE Protocol not supged.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED,
      SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * @endcode
 */
LONG SCardConnect(SCARDCONTEXT hContext, LPCSTR szReader,
	DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
	LPDWORD pdwActiveProtocol)
{
	LONG rv;
	connect_struct scConnectStruct;
	DWORD dwContextIndex;

	PROFILE_START

	DBG(hContext, NULL, "SCardConnect()/\n");
	/*
	 * Check for NULL parameters
	 */
	if (phCard == NULL || pdwActiveProtocol == NULL) {
		DBGERR("SCardConnect(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	} else
		*phCard = 0;

	if (szReader == NULL) {
		DBGERR("SCardConnect(SCARD_E_UNKNOWN_READER)\n");
		return SCARD_E_UNKNOWN_READER;
	}
	/*
	 * Check for uninitialized strings
	 */
	if (strlen(szReader) > MAX_READERNAME) {
		DBGERR("SCardConnect(MAX_READERNAME)\n");
		return SCARD_E_INVALID_VALUE;
	}

	if (!(dwPreferredProtocols & SCARD_PROTOCOL_T0) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_T1) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_RAW) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_ANY_OLD))
	{
		DBGERR("SCardConnect(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this context has been opened
	 */
	dwContextIndex = SCardGetContextIndice(hContext);
	if (dwContextIndex == -1) {
	    DBGERR("SCardConnect(SCARD_E_INVALID_HANDLE)\n");
	    SYS_MutexUnLock(&contextMutex);
	    return SCARD_E_INVALID_HANDLE;
	}

	if (SCardCheckDaemonAvailability(
	    psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardConnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	strncpy(scConnectStruct.szReader, szReader, MAX_READERNAME);

	scConnectStruct.hContext = hContext;
	scConnectStruct.dwShareMode = dwShareMode;
	scConnectStruct.dwPreferredProtocols = dwPreferredProtocols;
	scConnectStruct.phCard = *phCard;
	scConnectStruct.pdwActiveProtocol = *pdwActiveProtocol;

	if ((rv = SHMrpc(SCARD_CONNECT,
	    psContextMap[dwContextIndex].dwClientID,
	    &scConnectStruct, sizeof (scConnectStruct))) == -1) {
		    Log1(PCSC_LOG_INFO, "SCardConnect(): SHMrpc() returned error");
		    SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		    return SCARD_F_COMM_ERROR;
	}

	*phCard = scConnectStruct.phCard;
	*pdwActiveProtocol = scConnectStruct.pdwActiveProtocol;

	if (scConnectStruct.rv == SCARD_S_SUCCESS)
	{
		/*
		 * Keep track of the handle locally
		 */
		rv = SCardAddHandle(*phCard, dwContextIndex, (LPSTR) szReader);
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

		PROFILE_END
		DBGERR("SCardConnect(%lx)\n", rv);
		return rv;
	}

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardConnect(%lx)\n", rv);
	return scConnectStruct.rv;
}

/**
 * @brief This function reestablishes a connection to a reader that was previously
 * connected to using SCardConnect().
 *
 * In a multi application environment it is possible for an application to reset
 * the card in shared mode. When this occurs any other application trying to
 * access certain commands will be returned the value SCARD_W_RESET_CARD. When
 * this occurs SCardReconnect() must be called in order to acknowledge that
 * the card was reset and allow it to change it's state accordingly.
 *
 * @param[in] hCard Handle to a previous call to connect.
 * @param[in] dwShareMode Mode of connection type: exclusive/shared.
 * <ul>
 *   <li>SCARD_SHARE_SHARED - This application will allow others to share the reader.
 *   <li>SCARD_SHARE_EXCLUSIVE - This application will NOT allow others to share the reader.
 * </ul>
 * @param[in] dwPreferredProtocols Desired protocol use.
 * <ul>
 *   <li>SCARD_PROTOCOL_T0 - Use the T=0 protocol.
 *   <li>SCARD_PROTOCOL_T1 - Use the T=1 protocol.
 *   <li>SCARD_PROTOCOL_RAW - Use with memory type cards.
 * </ul>
 * \p dwPreferredProtocols is a bit mask of acceptable protocols for
 * the connection. You can use (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
 * if you do not have a preferred protocol.
 * @param[in] dwInitialization Desired action taken on the card/reader.
 * <ul>
 *   <li>SCARD_LEAVE_CARD - Do nothing.
 *   <li>SCARD_RESET_CARD - Reset the card (warm reset).
 *   <li>SCARD_UNPOWER_CARD - Unpower the card (cold reset).
 *   <li>SCARD_EJECT_CARD - Eject the card.
 * </ul>
 * @param[out] pdwActiveProtocol Established protocol to this connection.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid \p hCard handle.
 * @retval SCARD_E_NOT_READY Could not allocate the desired port.
 * @retval SCARD_E_INVALID_VALUE Invalid sharing mode, requested protocol, or reader name.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 * @retval SCARD_E_UNSUPPORTED_FEATURE Protocol not supported.
 * @retval SCARD_E_SHARING_VIOLATION Someone else has exclusive rights.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol, dwSendLength, dwRecvLength;
 * LONG rv;
 * BYTE pbRecvBuffer[10];
 * BYTE pbSendBuffer[] = {0xC0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * ...
 * dwSendLength = sizeof(pbSendBuffer);
 * dwRecvLength = sizeof(pbRecvBuffer);
 * rv = SCardTransmit(hCard, SCARD_PCI_T0, pbSendBuffer, dwSendLength, &pioRecvPci, pbRecvBuffer, &dwRecvLength);
 * / * Card has been reset by another application * /
 * if (rv == SCARD_W_RESET_CARD)
 * {
 *   rv = SCardReconnect(hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_RESET_CARD, &dwActiveProtocol);
 * }
 * @endcode
 */
LONG SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode,
	DWORD dwPreferredProtocols, DWORD dwInitialization,
	LPDWORD pdwActiveProtocol)
{
	LONG rv;
	reconnect_struct scReconnectStruct;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCardReconnect()/\n");

	if (dwInitialization != SCARD_LEAVE_CARD &&
		dwInitialization != SCARD_RESET_CARD &&
		dwInitialization != SCARD_UNPOWER_CARD &&
		dwInitialization != SCARD_EJECT_CARD)
	{
		DBGERR("SCardReconnect(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	if (!(dwPreferredProtocols & SCARD_PROTOCOL_T0) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_T1) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_RAW) &&
		!(dwPreferredProtocols & SCARD_PROTOCOL_ANY_OLD))
	{
		DBGERR("SCardReconnect(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	if (pdwActiveProtocol == NULL) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);


	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}
		/* by default r == NULL */
		if (r && strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardReconnect(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	scReconnectStruct.hCard = hCard;
	scReconnectStruct.dwShareMode = dwShareMode;
	scReconnectStruct.dwPreferredProtocols = dwPreferredProtocols;
	scReconnectStruct.dwInitialization = dwInitialization;
	scReconnectStruct.pdwActiveProtocol = *pdwActiveProtocol;

	if ((rv = SHMrpc(SCARD_RECONNECT,
			 psContextMap[dwContextIndex].dwClientID,
			 &scReconnectStruct, sizeof (scReconnectStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardRecoonnect(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}

	*pdwActiveProtocol = scReconnectStruct.pdwActiveProtocol;

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardReconnect(%lx)\n", scReconnectStruct.rv);
	return scReconnectStruct.rv;
}

/**
 * This function terminates a connection to the connection made through
 * SCardConnect(). dwDisposition can have the following values:
 *
 * @param[in] hCard Connection made from SCardConnect.
 * @param[in] dwDisposition Reader function to execute.
 * <ul>
 *   <li>SCARD_LEAVE_CARD - Do nothing.
 *   <li>SCARD_RESET_CARD - Reset the card (warm reset).
 *   <li>SCARD_UNPOWER_CARD - Unpower the card (cold reset).
 *   <li>SCARD_EJECT_CARD - Eject the card.
 * </ul>
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid \p hCard handle.
 * @retval SCARD_E_INVALID_VALUE - Invalid \p dwDisposition.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * rv = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
 * @endcode
 */
LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
	LONG rv;
	disconnect_struct scDisconnectStruct;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START
	DBG(NULL, hCard, "SCardDisconnect()/\n");

	if (dwDisposition != SCARD_LEAVE_CARD &&
		dwDisposition != SCARD_RESET_CARD &&
		dwDisposition != SCARD_UNPOWER_CARD &&
		dwDisposition != SCARD_EJECT_CARD)
	{
		DBGERR("SCardDisconnect(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardDisconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	scDisconnectStruct.hCard = hCard;
	scDisconnectStruct.dwDisposition = dwDisposition;

	if ((rv = SHMrpc(SCARD_DISCONNECT,
			psContextMap[dwContextIndex].dwClientID,
			&scDisconnectStruct, sizeof (scDisconnectStruct))) == -1 ) {
				Log1(PCSC_LOG_INFO, "SCardDisconnect(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}

	SCardRemoveHandle(hCard);

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardDisconnects(%lx)\n", scDisconnectStruct.rv);
	return scDisconnectStruct.rv;
}

/**
 * @brief This function establishes a temporary exclusive access mode for
 * doing a series of commands or transaction.
 *
 * You might want to use this when you are selecting a few files and then
 * writing a large file so you can make sure that another application will
 * not change the current file. If another application has a lock on this
 * reader or this application is in \c SCARD_SHARE_EXCLUSIVE there will be no
 * action taken.
 *
 * @param[in] hCard Connection made from SCardConnect.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hCard handle.
 * @retval SCARD_E_SHARING_VIOLATION Someone else has exclusive rights.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * rv = SCardBeginTransaction(hCard);
 * ...
 * / * Do some transmit commands * /
 * @endcode
 */
LONG SCardBeginTransaction(SCARDHANDLE hCard)
{

	LONG rv;
	begin_struct scBeginStruct;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCardBeginTransaction()/\n");
	SYS_MutexLock(&contextMutex);

	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		/* by default r == NULL */
		if (r &&
		    strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardBeginTransaction(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	scBeginStruct.hCard = hCard;
	/*
	 * Query the server every so often until the sharing violation ends
	 * and then hold the lock for yourself.
	 */
	do
	{
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		/*
		 * Look to see if it is locked before polling the server for
		 * admission to the readers resources
		 */
		if (prs->lockState != 0)
		{
			int randnum = 0;
			int j;

			for (j = 0; j < 100; j++)
			{
			       SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			       randnum = SYS_RandomInt(1000, 10000);
			       SYS_USleep(randnum);
			       SYS_MutexLock(&contextMutex);
			       /*
				* Make sure this handle has been opened
			       */
			       rv = SCardGetIndicesFromHandle(
				       hCard, &dwContextIndex,
				       &dwChannelIndex, &dwClientID);

			       if (rv == -1) {
				       DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
				       SYS_MutexUnLock(&contextMutex);
				       return SCARD_E_INVALID_HANDLE;
			       }

			       SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
			       SYS_MutexUnLock(&contextMutex);

			       if (prs->lockState == 0)
					break;
			}
		}

		if ((rv = SHMrpc(SCARD_BEGIN_TRANSACTION,
				psContextMap[dwContextIndex].dwClientID,
				&scBeginStruct, sizeof (scBeginStruct))) == -1) {
					Log1(PCSC_LOG_INFO, "SCardBeginTransaction(): SHMrpc() returned error");
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					return SCARD_F_COMM_ERROR;
		}
	}
	while (scBeginStruct.rv == SCARD_E_SHARING_VIOLATION);
	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
	PROFILE_END

	DBGERR("SCardBeginTransaction(%lx)\n", scBeginStruct.rv);
	return scBeginStruct.rv;
}

/**
 * @brief This function ends a previously begun transaction.
 *
 * The calling application must be the owner of the previously begun
 * transaction or an error will occur.
 *
 * @param[in] hCard Connection made from SCardConnect.
 * @param[in] dwDisposition Action to be taken on the reader.
 * The disposition action is not currently used in this release.
 * <ul>
 *   <li>SCARD_LEAVE_CARD - Do nothing.
 *   <li>SCARD_RESET_CARD - Reset the card.
 *   <li>SCARD_UNPOWER_CARD - Unpower the card.
 *   <li>SCARD_EJECT_CARD - Eject the card.
 * </ul>
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hCard handle.
 * @retval SCARD_E_SHARING_VIOLATION Someone else has exclusive rights.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * rv = SCardBeginTransaction(hCard);
 * ...
 * / * Do some transmit commands * /
 * ...
 * rv = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
 * @endcode
 */
LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
	LONG rv;
	end_struct scEndStruct;
	int randnum, i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCardEndTransaction()/\n");
	/*
	 * Zero out everything
	 */
	randnum = 0;

	if (dwDisposition != SCARD_LEAVE_CARD &&
		dwDisposition != SCARD_RESET_CARD &&
		dwDisposition != SCARD_UNPOWER_CARD &&
		dwDisposition != SCARD_EJECT_CARD)
	{
		DBGERR("SCardEndTransaction(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		/* by default r == NULL */
		if (r && strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardEndTransaction(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	scEndStruct.hCard = hCard;
	scEndStruct.dwDisposition = dwDisposition;

	if ((rv = SHMrpc(SCARD_END_TRANSACTION,
			psContextMap[dwContextIndex].dwClientID,
			&scEndStruct, sizeof (scEndStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardEndTransaction(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}
	/*
	 * This helps prevent starvation
	 */
	randnum = SYS_RandomInt(1000, 10000);
	SYS_USleep(randnum);

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardEndTransaction(%lx)\n", scEndStruct.rv);
	return scEndStruct.rv;
}

/**
 * @deprecated
 * This function is not in Microsoft(R) WinSCard API and is deprecated
 * in pcsc-lite API.
 */
LONG SCardCancelTransaction(SCARDHANDLE hCard)
{
	LONG rv;
	cancel_struct scCancelStruct;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCancelTransaction()/\n");
	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}
		/* by default r == NULL */
		if (r &&  strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardCancelTransaction(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	scCancelStruct.hCard = hCard;

	if ((rv = SHMrpc(SCARD_CANCEL_TRANSACTION,
			psContextMap[dwContextIndex].dwClientID,
			&scCancelStruct, sizeof (scCancelStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardCancelTransaction(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}
	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardCancelTransaction(%lx)\n", scCancelStruct.rv);
	return scCancelStruct.rv;
}

/**
 * @brief This function returns the current status of the reader connected to by hCard.
 *
 * It's friendly name will be stored in szReaderName. pcchReaderLen will be
 * the size of the allocated buffer for szReaderName, while pcbAtrLen will
 * be the size of the allocated buffer for pbAtr. If either of these is too
 * small, the function will return with SCARD_E_INSUFFICIENT_BUFFER and the
 * necessary size in pcchReaderLen and pcbAtrLen. The current state, and
 * protocol will be stored in pdwState and pdwProtocol respectively.
 *
 * @param[in] hCard Connection made from SCardConnect.
 * @param mszReaderNames [inout] Friendly name of this reader.
 * @param pcchReaderLen [inout] Size of the szReaderName multistring.
 * @param[out] pdwState Current state of this reader. pdwState
 * is a DWORD possibly OR'd with the following values:
 * <ul>
 *   <li>SCARD_ABSENT - There is no card in the reader.
 *   <li>SCARD_PRESENT - There is a card in the reader, but it has not been
 *                       moved into position for use.
 *   <li>SCARD_SWALLOWED - There is a card in the reader in position for use.
 *                         The card is not powered.
 *   <li>SCARD_POWERED - Power is being provided to the card, but the reader
 *                       driver is unaware of the mode of the card.
 *   <li>SCARD_NEGOTIABLE - The card has been reset and is awaiting PTS negotiation.
 *   <li>SCARD_SPECIFIC - The card has been reset and specific communication
 *                        protocols have been established.
 * </ul>
 * @param[out] pdwProtocol Current protocol of this reader.
 * <ul>
 *   <li>SCARD_PROTOCOL_T0 	Use the T=0 protocol.
 *   <li>SCARD_PROTOCOL_T1 	Use the T=1 protocol.
 * </ul>
 * @param[out] pbAtr Current ATR of a card in this reader.
 * @param[out] pcbAtrLen Length of ATR.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hCard handle.
 * @retval SCARD_E_INSUFFICIENT_BUFFER Not enough allocated memory for szReaderName or for pbAtr.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * DWORD dwState, dwProtocol, dwAtrLen, dwReaderLen;
 * BYTE pbAtr[MAX_ATR_SIZE];
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * ...
 * dwAtrLen = sizeof(pbAtr);
 * rv=SCardStatus(hCard, NULL, &dwReaderLen, &dwState, &dwProtocol, pbAtr, &dwAtrLen);
 * @endcode
 */
LONG SCardStatus(SCARDHANDLE hCard, LPSTR mszReaderNames,
	LPDWORD pcchReaderLen, LPDWORD pdwState,
	LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	DWORD dwReaderLen, dwAtrLen;
	LONG rv;
	int i;
	status_struct scStatusStruct;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCardStatus()\n");

	/*
	 * Check for NULL parameters
	 */

	if (pcchReaderLen == NULL || pcbAtrLen == NULL) {
		DBGERR("SCardStatus(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	/* length passed from caller */
	dwReaderLen = *pcchReaderLen;
	dwAtrLen = *pcbAtrLen;

	/* default output values */
	if (pdwState)
		*pdwState = 0;

	if (pdwProtocol)
		*pdwProtocol = 0;

	*pcchReaderLen = 0;
	*pcbAtrLen = 0;
	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}
		/* by default r == NULL */
		if (r && strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardStatus(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	/* initialise the structure */
	memset(&scStatusStruct, 0, sizeof(scStatusStruct));
	scStatusStruct.hCard = hCard;

	/* those sizes need to be initialised */
	scStatusStruct.pcchReaderLen = sizeof(scStatusStruct.mszReaderNames);
	scStatusStruct.pcbAtrLen = sizeof(scStatusStruct.pbAtr);

	if ((rv = SHMrpc(SCARD_STATUS,
			psContextMap[dwContextIndex].dwClientID,
			&scStatusStruct, sizeof (scStatusStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardStatus() :SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}

	rv = scStatusStruct.rv;
	if (rv != SCARD_S_SUCCESS && rv != SCARD_E_INSUFFICIENT_BUFFER)
	{
		/*
		 * An event must have occurred
		 */
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardStatus(%lx)\n", rv);
		return rv;
	}

	/*
	 * Now continue with the client side SCardStatus
	 */

	*pcchReaderLen = strlen(psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName) + 1;
	{
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		*pcbAtrLen = prs->cardAtrLength;
		if (pdwState) {
			*pdwState = prs->readerState;
#ifdef EXTRA_DEBUGGING
			CFGdumpReaderState(*pdwState);
#endif
		}
		if (pdwProtocol)
			*pdwProtocol = prs->cardProtocol;

	}
	/* return SCARD_E_INSUFFICIENT_BUFFER only if buffer pointer is non NULL */
	if (mszReaderNames)
	{
		if (*pcchReaderLen > dwReaderLen)
			rv = SCARD_E_INSUFFICIENT_BUFFER;

		strncpy(mszReaderNames,
			psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName,
			dwReaderLen);
	}

	if (pbAtr)
	{
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		if (*pcbAtrLen > dwAtrLen)
			rv = SCARD_E_INSUFFICIENT_BUFFER;

		memcpy(pbAtr, prs->cardAtr, min(*pcbAtrLen, dwAtrLen));
	}

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

#ifdef EXTRA_DEBUGGING
	CFGdumpEventState(*pdwState);
#endif
	DBGERR("SCardStatus(%lx)\n", rv);
	return rv;
}

/**
 * @brief This function receives a structure or list of structures containing
 * reader names. It then blocks for a change in state to occur on any of the
 * OR'd values contained in dwCurrentState for a maximum blocking time of
 * dwTimeout or forever if INFINITE is used.
 *
 * The new event state will be contained in dwEventState. A status change might
 * be a card insertion or removal event, a change in ATR, etc.
 *
 * This function will block for reader availability if cReaders is equal to
 * zero and rgReaderStates is NULL.
 *
 * @code
 * typedef struct {
 *   LPCSTR szReader;          // Reader name
 *   LPVOID pvUserData;         // User defined data
 *   DWORD dwCurrentState;      // Current state of reader
 *   DWORD dwEventState;        // Reader state after a state change
 *   DWORD cbAtr;               // ATR Length, usually MAX_ATR_SIZE
 *   BYTE rgbAtr[MAX_ATR_SIZE]; // ATR Value
 * } SCARD_READERSTATE;
 * ...
 * typedef SCARD_READERSTATE *PSCARD_READERSTATE, **LPSCARD_READERSTATE;
 * ...
 * @endcode
 *
 * Value of dwCurrentState and dwEventState:
 * <ul>
 *   <li>SCARD_STATE_UNAWARE The application is unaware of the current
 *       state, and would like to know. The use of this value results in an
 *       immediate return from state transition monitoring services. This is
 *       represented by all bits set to zero.
 *   <li>SCARD_STATE_IGNORE This reader should be ignored
 *   <li>SCARD_STATE_CHANGED There is a difference between the state believed
 *       by the application, and the state known by the resource manager.
 *       When this bit is set, the application may assume a significant state
 *       change has occurred on this reader.
 *   <li>SCARD_STATE_UNKNOWN The given reader name is not recognized by the
 *       resource manager. If this bit is set, then \c SCARD_STATE_CHANGED and
 *       \c SCARD_STATE_IGNORE will also be set
 *   <li>SCARD_STATE_UNAVAILABLE The actual state of this reader is not
 *       available. If this bit is set, then all the following bits are clear.
 *   <li>SCARD_STATE_EMPTY There is no card in the reader. If this bit is set,
 *       all the following bits will be clear
 *   <li>SCARD_STATE_PRESENT There is a card in the reader
 *   <li>SCARD_STATE_ATRMATCH There is a card in the reader with an ATR
 *       matching one of the target cards. If this bit is set,
 *       \c SCARD_STATE_PRESENT will also be set. This bit is only returned on
 *       the \c SCardLocateCards function.
 *   <li>SCARD_STATE_EXCLUSIVE The card in the reader is allocated for
 *       exclusive use by another application. If this bit is set,
 *       \c SCARD_STATE_PRESENT will also be set.
 *   <li>SCARD_STATE_INUSE The card in the reader is in use by one or more
 *       other applications, but may be connected to in shared mode. If this
 *       bit is set, \c SCARD_STATE_PRESENT will also be set.
 *   <li>SCARD_STATE_MUTE There is an unresponsive card in the reader.
 * </ul>
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 * @param[in] dwTimeout Maximum waiting time (in miliseconds) for status
 *            change, zero (or INFINITE) for infinite.
 * @param rgReaderStates [inout] Structures of readers with current states.
 * @param[in] cReaders Number of structures.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_VALUE Invalid States, reader name, etc.
 * @retval SCARD_E_INVALID_HANDLE Invalid hContext handle.
 * @retval SCARD_E_READER_UNAVAILABLE The reader is unavailable.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * SCARD_READERSTATE_A rgReaderStates[1];
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * ...
 * rgReaderStates[0].szReader = "Reader X";
 * rgReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
 * ...
 * rv = SCardGetStatusChange(hContext, INFINITE, rgReaderStates, 1);
 * printf("reader state: 0x%04X\n", rgReaderStates[0].dwEventState);
 * @endcode
 */


LONG SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
	LPSCARD_READERSTATE_A rgReaderStates, DWORD cReaders)
{
	PSCARD_READERSTATE_A currReader;
	PREADER_STATE rContext;
	DWORD dwTime = 0;
	DWORD dwState;
	DWORD dwBreakFlag = 0;
	int j;
	DWORD dwContextIndex, dwClientID;
	int currentReaderCount = 0;

	PROFILE_START
	DBG(hContext, NULL, "SCardGetStatusChange()/\n");

	if (rgReaderStates == NULL && cReaders > 0) {
		DBGERR("SCardGetStatusChange(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	if (cReaders < 0) {
		DBGERR("SCardGetStatusChange(SCARD_E_INVALID_VALUE)\n");
		return SCARD_E_INVALID_VALUE;
	}

	/*
	 * Make sure this context has been opened
	 */
	SYS_MutexLock(&contextMutex);

	dwContextIndex = SCardGetContextIndice(hContext);
	if (dwContextIndex == -1) {
		DBGERR("SCardGetStatusChange(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	if (SCardCheckDaemonAvailability(
	    psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardGetStatusChange(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	dwClientID = psContextMap[dwContextIndex].dwClientID;

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	/*
	 * Application is waiting for a reader - return the first available
	 * reader
	 */

	if (cReaders == 0)
	{
		psContextMap[dwContextIndex].contextBlockStatus = BLOCK_STATUS_BLOCKING;
		while (1)
		{
			int i;

			if (psContextMap[dwContextIndex].contextBlockStatus == BLOCK_STATUS_RESUME) {
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardGetStatusChange(SCARD_E_CANCELLED)\n");
				return SCARD_E_CANCELLED;
			}

			if (SCardCheckDaemonAvailability(
			    psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS)
			{
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardGetStatusChange(SCARD_E_NO_SERVICE)\n");
				return SCARD_E_NO_SERVICE;
			}

			for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
			{
				PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
				if (prs == NULL) {
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					return SCARD_E_READER_UNAVAILABLE;
				}
				if (prs->readerID != 0)
				{
					/*
					 * Reader was found
					 */
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

					PROFILE_END
					DBGERR("SCardGetStatusChange(SCARD_S_SUCCESS)\n");
					return SCARD_S_SUCCESS;
				}
			}

			if (dwTimeout == 0)
			{
				/*
				 * return immediately - no reader available
				 */
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardGetStatusChange(SCARD_E_READER_UNAVAILABLE)\n");
				return SCARD_E_READER_UNAVAILABLE;
			}

			SYS_USleep(PCSCLITE_STATUS_WAIT);


			if (dwTimeout != INFINITE)
			{
				dwTime += PCSCLITE_STATUS_WAIT;

				if (dwTime >= (dwTimeout * 1000))
				{
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

					PROFILE_END
					DBGERR("SCardGetStatusChange(SCARD_E_TIMEOUT)\n");
					return SCARD_E_TIMEOUT;
				}
			}
		}
	}
	else
		if (cReaders >= PCSCLITE_MAX_READERS_CONTEXTS)
		{
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			DBGERR("SCardGetStatusChange(SCARD_E_INVALID_VALUE)\n");
			return SCARD_E_INVALID_VALUE;
		}

	/*
	 * Check the integrity of the reader states structures
	 */

	for (j = 0; j < cReaders; j++)
	{
		currReader = &rgReaderStates[j];
		if (currReader->szReader == NULL)
		{
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_INVALID_VALUE;
		}
	}

	/*
	 * End of search for readers
	 */

	/*
	 * Clear the event state for all readers
	 */
	for (j = 0; j < cReaders; j++)
	{
		currReader = &rgReaderStates[j];
		currReader->dwEventState = 0;
	}

	/*
	 * Now is where we start our event checking loop
	 */

	Log1(PCSC_LOG_DEBUG, "Event Loop Start");

	psContextMap[dwContextIndex].contextBlockStatus = BLOCK_STATUS_BLOCKING;

	/* Get the initial reader count on the system */
	for (j=0; j < PCSCLITE_MAX_READERS_CONTEXTS; j++) {
		PREADER_STATE prs = FETCH(readerStates[j], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}
		if (prs->readerID != 0)
			currentReaderCount++;
	}

	j = 0;

	do
	{
		int newReaderCount = 0;
		char ReaderCountChanged = FALSE;

		if (SCardCheckDaemonAvailability(
			psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS)
		{
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

			PROFILE_END
			DBGERR("SCardGetStatusChange(SCARD_E_NO_SERVICE)\n");
			return SCARD_E_NO_SERVICE;
		}

		if (j == 0)
		{
			int i;
			for (i=0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++) {
				PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
				if (prs == NULL) {
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					return SCARD_E_READER_UNAVAILABLE;
				}
				if (prs->readerID != 0)
					newReaderCount++;
			}
			if (newReaderCount != currentReaderCount)
			{
				Log1(PCSC_LOG_DEBUG, "Reader list changed");
				ReaderCountChanged = TRUE;
				currentReaderCount = newReaderCount;
			}
		}
		currReader = &rgReaderStates[j];

	/************ Look for IGNORED readers ****************************/

		if (currReader->dwCurrentState & SCARD_STATE_IGNORE)
		{
			currReader->dwEventState = SCARD_STATE_IGNORE;
		} else
		{
			LPSTR lpcReaderName;
			int i;

	  /************ Looks for correct readernames *********************/

			lpcReaderName = (char *) currReader->szReader;

			for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
			{
				PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
				if (prs == NULL) {
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					return SCARD_E_READER_UNAVAILABLE;
				}
				if (strcmp(lpcReaderName, prs->readerName) == 0)
				{
					break;
				}
			}

			/*
			 * The requested reader name is not recognized
			 */
			if (i == PCSCLITE_MAX_READERS_CONTEXTS)
			{
				if (currReader->dwCurrentState & SCARD_STATE_UNKNOWN)
				{
					currReader->dwEventState = SCARD_STATE_UNKNOWN;
				} else
				{
					currReader->dwEventState =
						SCARD_STATE_UNKNOWN | SCARD_STATE_CHANGED;
					/*
					 * Spec says use SCARD_STATE_IGNORE but a removed USB
					 * reader with eventState fed into currentState will
					 * be ignored forever
					 */
					dwBreakFlag = 1;
				}
			} else
			{

				/*
				 * The reader has come back after being away
				 */
				if (currReader->dwCurrentState & SCARD_STATE_UNKNOWN)
				{
					currReader->dwEventState |= SCARD_STATE_CHANGED;
					currReader->dwEventState &= ~SCARD_STATE_UNKNOWN;
					dwBreakFlag = 1;
				}

	/*****************************************************************/

				/*
				 * Set the reader status structure
				 */
				rContext = FETCH(readerStates[i], dwClientID);
				if (rContext == NULL) {
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					return SCARD_E_READER_UNAVAILABLE;
				}
				/*
				 * Now we check all the Reader States
				 */
				dwState = rContext->readerState;

	/*********** Check if the reader is in the correct state ********/
				if (dwState & SCARD_UNKNOWN)
				{
					/*
					 * App thinks reader is in bad state and it is
					 */
					if (currReader->
						dwCurrentState & SCARD_STATE_UNAVAILABLE)
					{
						currReader->dwEventState = SCARD_STATE_UNAVAILABLE;
					} else
					{
						/*
						 * App thinks reader is in good state and it is
						 * not
						 */
						currReader->dwEventState = SCARD_STATE_CHANGED |
							SCARD_STATE_UNAVAILABLE;
						dwBreakFlag = 1;
					}
				} else
				{
					/*
					 * App thinks reader in bad state but it is not
					 */
					if (currReader->
						dwCurrentState & SCARD_STATE_UNAVAILABLE)
					{
						currReader->dwEventState &=
							~SCARD_STATE_UNAVAILABLE;
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					}
				}

	/********** Check for card presence in the reader **************/

				if (dwState & SCARD_PRESENT)
				{
					/* card present but not yet powered up */
					if (0 == rContext->cardAtrLength)
						/* Allow the status thread to convey information */
						SYS_USleep(PCSCLITE_STATUS_POLL_RATE + 10);

					currReader->cbAtr = rContext->cardAtrLength;
					memcpy(currReader->rgbAtr, rContext->cardAtr,
						currReader->cbAtr);
				} else
				{
					currReader->cbAtr = 0;
				}

				/*
				 * Card is now absent
				 */
				if (dwState & SCARD_ABSENT)
				{
					currReader->dwEventState |= SCARD_STATE_EMPTY;
					currReader->dwEventState &= ~SCARD_STATE_PRESENT;
					currReader->dwEventState &= ~SCARD_STATE_UNAWARE;
					currReader->dwEventState &= ~SCARD_STATE_IGNORE;
					currReader->dwEventState &= ~SCARD_STATE_UNKNOWN;
					currReader->dwEventState &= ~SCARD_STATE_UNAVAILABLE;
					currReader->dwEventState &= ~SCARD_STATE_ATRMATCH;
					currReader->dwEventState &= ~SCARD_STATE_MUTE;
					currReader->dwEventState &= ~SCARD_STATE_INUSE;

					/*
					 * After present the rest are assumed
					 */
					if (currReader->dwCurrentState & SCARD_STATE_PRESENT ||
						currReader->dwCurrentState & SCARD_STATE_ATRMATCH
						|| currReader->
						dwCurrentState & SCARD_STATE_EXCLUSIVE
						|| currReader->dwCurrentState & SCARD_STATE_INUSE)
					{
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					}

					/*
					 * Card is now present
					 */
				} else if (dwState & SCARD_PRESENT)
				{
					currReader->dwEventState |= SCARD_STATE_PRESENT;
					currReader->dwEventState &= ~SCARD_STATE_EMPTY;
					currReader->dwEventState &= ~SCARD_STATE_UNAWARE;
					currReader->dwEventState &= ~SCARD_STATE_IGNORE;
					currReader->dwEventState &= ~SCARD_STATE_UNKNOWN;
					currReader->dwEventState &= ~SCARD_STATE_UNAVAILABLE;
					currReader->dwEventState &= ~SCARD_STATE_MUTE;

					if (currReader->dwCurrentState & SCARD_STATE_EMPTY)
					{
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					}

					if (dwState & SCARD_SWALLOWED)
					{
						if (currReader->dwCurrentState & SCARD_STATE_MUTE)
						{
							currReader->dwEventState |= SCARD_STATE_MUTE;
						} else
						{
							currReader->dwEventState |= SCARD_STATE_MUTE;
							if (currReader->dwCurrentState !=
								SCARD_STATE_UNAWARE)
							{
								currReader->dwEventState |=
									SCARD_STATE_CHANGED;
							}
							dwBreakFlag = 1;
						}
					}
					{
						/*
						 * App thinks card is mute but it is not
						 */
						if (currReader->dwCurrentState & SCARD_STATE_MUTE)
						{
							currReader->dwEventState |=
								SCARD_STATE_CHANGED;
							dwBreakFlag = 1;
						}
					}
				}

				/*
				 * Now figure out sharing modes
				 */
				if (rContext->readerSharing == -1)
				{
					currReader->dwEventState |= SCARD_STATE_EXCLUSIVE;
					currReader->dwEventState &= ~SCARD_STATE_INUSE;
					if (currReader->dwCurrentState & SCARD_STATE_INUSE)
					{
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					}
				} else if (rContext->readerSharing >= 1)
				{
					/*
					 * A card must be inserted for it to be INUSE
					 */
					if (dwState & SCARD_PRESENT)
					{
						currReader->dwEventState |= SCARD_STATE_INUSE;
						currReader->dwEventState &= ~SCARD_STATE_EXCLUSIVE;
						if (currReader->
							dwCurrentState & SCARD_STATE_EXCLUSIVE)
						{
							currReader->dwEventState |=
								SCARD_STATE_CHANGED;
							dwBreakFlag = 1;
						}
					}
				} else if (rContext->readerSharing == 0)
				{
					currReader->dwEventState &= ~SCARD_STATE_INUSE;
					currReader->dwEventState &= ~SCARD_STATE_EXCLUSIVE;

					if (currReader->dwCurrentState & SCARD_STATE_INUSE)
					{
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					} else if (currReader->
						dwCurrentState & SCARD_STATE_EXCLUSIVE)
					{
						currReader->dwEventState |= SCARD_STATE_CHANGED;
						dwBreakFlag = 1;
					}
				}

				if (currReader->dwCurrentState == SCARD_STATE_UNAWARE)
				{
					/*
					 * Break out of the while .. loop and return status
					 * once all the status's for all readers is met
					 */
					currReader->dwEventState |= SCARD_STATE_CHANGED;
					dwBreakFlag = 1;
				}

			}	/* End of SCARD_STATE_UNKNOWN */

		}	/* End of SCARD_STATE_IGNORE */

		/*
		 * Counter and resetter
		 */
		j = j + 1;
		if (j == cReaders)
		{
			if (!dwBreakFlag)
			{
				/* break if the reader count changed,
				 * so that the calling application can update
				 * the reader list
				 */
				if (ReaderCountChanged)
					break;
			}
			j = 0;
		}

		/*
		 * Declare all the break conditions
		 */

		if (psContextMap[dwContextIndex].contextBlockStatus ==
		    BLOCK_STATUS_RESUME)
			break;

		/*
		 * Break if UNAWARE is set and all readers have been checked
		 */
		if ((dwBreakFlag == 1) && (j == 0))
			break;

		/*
		 * Timeout has occurred and all readers checked
		 */
		if ((dwTimeout == 0) && (j == 0))
			break;

		if (dwTimeout != INFINITE && dwTimeout != 0)
		{
			/*
			 * If time is greater than timeout and all readers have been
			 * checked
			 */
			if ((dwTime >= (dwTimeout * 1000)) && (j == 0))
			{
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardGetStatusChange(SCARD_E_TIMEOUT)\n");
				return SCARD_E_TIMEOUT;
			}
		}

		/*
		 * Only sleep once for each cycle of reader checks.
		 */
		if (j == 0)
		{
			SYS_USleep(PCSCLITE_STATUS_WAIT);
			dwTime += PCSCLITE_STATUS_WAIT;
		}
	}
	while (1);

	Log1(PCSC_LOG_DEBUG, "Event Loop End");

	if (psContextMap[dwContextIndex].contextBlockStatus ==
			BLOCK_STATUS_RESUME)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardGetStatusChange(SCARD_E_CANCELLED)\n");
		return SCARD_E_CANCELLED;
	}

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);


	PROFILE_END
#ifdef EXTRA_DEBUGGING
	CFGdumpEventState(currReader->dwEventState);
#endif
	DBGERR("SCardGetStatusChange(SCARD_S_SUCCESS)\n");
	return SCARD_S_SUCCESS;
}

/**
 * @brief This function sends a command directly to the IFD Handler to be
 * processed by the reader.
 *
 * This is useful for creating client side reader drivers for functions like
 * PIN pads, biometrics, or other extensions to the normal smart card reader
 * that are not normally handled by PC/SC.
 *
 * @note the API of this function changed. In pcsc-lite 1.2.0 and before the
 * API was not Windows(R) PC/SC compatible. This has been corrected.
 *
 * @param[in] hCard Connection made from SCardConnect.
 * @param[in] dwControlCode Control code for the operation.\n
 * <a href="http://pcsclite.alioth.debian.org/pcsc-lite/node26.html#Some_SCardControl_commands">
 * Click here</a> for a list of supported commands by some drivers.
 * @param[in] pbSendBuffer Command to send to the reader.
 * @param[in] cbSendLength Length of the command.
 * @param[out] pbRecvBuffer Response from the reader.
 * @param[in] cbRecvLength Length of the response buffer.
 * @param[out] lpBytesReturned Length of the response.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_NOT_TRANSACTED Data exchange not successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hCard handle.
 * @retval SCARD_E_INVALID_VALUE Invalid value was presented.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 * @retval SCARD_W_RESET_CARD The card has been reset by another application.
 * @retval SCARD_W_REMOVED_CARD The card has been removed from the reader.
 *
 * @test
 * @code
 * LONG rv;
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol, dwSendLength, dwRecvLength;
 * BYTE pbRecvBuffer[10];
 * BYTE pbSendBuffer[] = { 0x06, 0x00, 0x0A, 0x01, 0x01, 0x10 0x00 };
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_RAW &hCard, &dwActiveProtocol);
 * dwSendLength = sizeof(pbSendBuffer);
 * dwRecvLength = sizeof(pbRecvBuffer);
 * rv = SCardControl(hCard, 0x42000001, pbSendBuffer, dwSendLength, pbRecvBuffer, sizeof(pbRecvBuffer), &dwRecvLength);
 * @endcode
 */
LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer,
	DWORD cbSendLength, LPVOID pbRecvBuffer, DWORD cbRecvLength,
	LPDWORD lpBytesReturned)
{
	LONG rv;
	control_struct scControlStruct;
	sharedSegmentMsg msgStruct;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START
	DBG(NULL, hCard, "SCardControl()/\n");

	/* 0 bytes received by default */
	if (NULL != lpBytesReturned)
		*lpBytesReturned = 0;

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		/* by default r == NULL */
		if (r &&  strcmp(r, prs->readerName) != 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardControl(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	if (cbSendLength > MAX_BUFFER_SIZE)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardControl(SCARD_E_INSUFFICIENT_BUFFER)\n");
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	scControlStruct.hCard = hCard;
	scControlStruct.dwControlCode = dwControlCode;
	scControlStruct.cbSendLength = cbSendLength;
	scControlStruct.cbRecvLength = cbRecvLength;
	memcpy(scControlStruct.pbSendBuffer, pbSendBuffer, cbSendLength);


	memcpy(&scControlStruct, &msgStruct.data, sizeof(scControlStruct));

	if ((rv = SHMrpc(SCARD_CONTROL,
			psContextMap[dwContextIndex].dwClientID,
			&scControlStruct, sizeof (scControlStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardControl(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}

	if (NULL != lpBytesReturned)
		*lpBytesReturned = scControlStruct.dwBytesReturned;

	if (scControlStruct.rv == SCARD_S_SUCCESS)
	{
		/*
		 * Copy and zero it so any secret information is not leaked
		 */
		memcpy(pbRecvBuffer, scControlStruct.pbRecvBuffer,
			scControlStruct.cbRecvLength);
		memset(scControlStruct.pbRecvBuffer, 0x00,
			sizeof(scControlStruct.pbRecvBuffer));
	}

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardControl(%lx)\n", scControlStruct.rv);
	return scControlStruct.rv;
}

/**
 * This function get an attribute from the IFD Handler. The list of possible
 * attributes is available in the file \c pcsclite.h.
 *
 * @param[in] hCard Connection made from \c SCardConnect.
 * @param[in] dwAttrId Identifier for the attribute to get.
 * <ul>
 *   <li>SCARD_ATTR_ASYNC_PROTOCOL_TYPES
 *   <li>SCARD_ATTR_ATR_STRING
 *   <li>SCARD_ATTR_CHANNEL_ID
 *   <li>SCARD_ATTR_CHARACTERISTICS
 *   <li>SCARD_ATTR_CURRENT_BWT
 *   <li>SCARD_ATTR_CURRENT_CLK
 *   <li>SCARD_ATTR_CURRENT_CWT
 *   <li>SCARD_ATTR_CURRENT_D
 *   <li>SCARD_ATTR_CURRENT_EBC_ENCODING
 *   <li>SCARD_ATTR_CURRENT_F
 *   <li>SCARD_ATTR_CURRENT_IFSC
 *   <li>SCARD_ATTR_CURRENT_IFSD
 *   <li>SCARD_ATTR_CURRENT_IO_STATE
 *   <li>SCARD_ATTR_CURRENT_N
 *   <li>SCARD_ATTR_CURRENT_PROTOCOL_TYPE
 *   <li>SCARD_ATTR_CURRENT_W
 *   <li>SCARD_ATTR_DEFAULT_CLK
 *   <li>SCARD_ATTR_DEFAULT_DATA_RATE
 *   <li>SCARD_ATTR_DEVICE_FRIENDLY_NAME_A
 *   <li>SCARD_ATTR_DEVICE_FRIENDLY_NAME_W
 *   <li>SCARD_ATTR_DEVICE_IN_USE
 *   <li>SCARD_ATTR_DEVICE_SYSTEM_NAME_A
 *   <li>SCARD_ATTR_DEVICE_SYSTEM_NAME_W
 *   <li>SCARD_ATTR_DEVICE_UNIT
 *   <li>SCARD_ATTR_ESC_AUTHREQUEST
 *   <li>SCARD_ATTR_ESC_CANCEL
 *   <li>SCARD_ATTR_ESC_RESET
 *   <li>SCARD_ATTR_EXTENDED_BWT
 *   <li>SCARD_ATTR_ICC_INTERFACE_STATUS
 *   <li>SCARD_ATTR_ICC_PRESENCE
 *   <li>SCARD_ATTR_ICC_TYPE_PER_ATR
 *   <li>SCARD_ATTR_MAX_CLK
 *   <li>SCARD_ATTR_MAX_DATA_RATE
 *   <li>SCARD_ATTR_MAX_IFSD
 *   <li>SCARD_ATTR_MAXINPUT
 *   <li>SCARD_ATTR_POWER_MGMT_SUPPORT
 *   <li>SCARD_ATTR_SUPRESS_T1_IFS_REQUEST
 *   <li>SCARD_ATTR_SYNC_PROTOCOL_TYPES
 *   <li>SCARD_ATTR_USER_AUTH_INPUT_DEVICE
 *   <li>SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE
 *   <li>SCARD_ATTR_VENDOR_IFD_SERIAL_NO
 *   <li>SCARD_ATTR_VENDOR_IFD_TYPE
 *   <li>SCARD_ATTR_VENDOR_IFD_VERSION
 *   <li>SCARD_ATTR_VENDOR_NAME
 * </ul>
 *
 * Not all the dwAttrId values listed above may be implemented in the IFD
 * Handler you are using. And some dwAttrId values not listed here may be
 * implemented.
 *
 * @param[out] pbAttr Pointer to a buffer that receives the attribute.
 * @param pcbAttrLen [inout] Length of the \p pbAttr buffer in bytes.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_NOT_TRANSACTED Data exchange not successful.
 * @retval SCARD_E_INSUFFICIENT_BUFFER Reader buffer not large enough.
 *
 * @test
 * @code
 * LONG rv;
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * unsigned char pbAtr[MAX_ATR_SIZE];
 * DWORD dwAtrLen;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED,
 *                           SCARD_PROTOCOL_RAW &hCard, &dwActiveProtocol);
 * rv = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, pbAtr, &dwAtrLen);
 * @endcode
 */
LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr,
	LPDWORD pcbAttrLen)
{
	LONG rv;
	PROFILE_START

	DBG(NULL, hCard, "SCardGetAttrib()/\n");

	if (NULL == pcbAttrLen) {
		DBGERR("SCardGetAttrib(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	/* if only get the length */
	if (NULL == pbAttr)
		/* this variable may not be set by the caller. use a reasonable size */
		*pcbAttrLen = MAX_BUFFER_SIZE;

	PROFILE_END

	rv = SCardGetSetAttrib(hCard, SCARD_GET_ATTRIB, dwAttrId, pbAttr,
		pcbAttrLen);

	DBGERR("SCardGetAttrib(%lx)\n", rv);

	return rv;

}

/**
 * @brief This function set an attribute of the IFD Handler.
 *
 * The list of attributes you can set is dependent on the IFD Handler you are
 * using.
 *
 * @param[in] hCard Connection made from \c SCardConnect.
 * @param[in] dwAttrId Identifier for the attribute to set.
 * @param[in] pbAttr Pointer to a buffer that receives the attribute.
 * @param[in] cbAttrLen Length of the \p pbAttr buffer in bytes.
 *
 * @return Error code
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_NOT_TRANSACTED Data exchange not successful.
 *
 * @test
 * @code
 * LONG rv;
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol;
 * unsigned char pbAtr[MAX_ATR_SIZE];
 * DWORD dwAtrLen;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED,
 *                   SCARD_PROTOCOL_RAW &hCard, &dwActiveProtocol);
 * rv = SCardSetAttrib(hCard, 0x42000001, "\x12\x34\x56", 3);
 * @endcode
 */
LONG SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPCBYTE pbAttr,
	DWORD cbAttrLen)
{
	PROFILE_START
	LONG rv;
	DBG(NULL, hCard, "SCardSetAttrib()/\n");
	if (NULL == pbAttr || 0 == cbAttrLen)
		return SCARD_E_INVALID_PARAMETER;

	PROFILE_END

	rv = SCardGetSetAttrib(hCard, SCARD_SET_ATTRIB, dwAttrId, (LPBYTE)pbAttr,
		&cbAttrLen);
	DBGERR("SCardSetAttrib(%lx)\n", rv);
	return rv;
}

static LONG SCardGetSetAttrib(SCARDHANDLE hCard, int command, DWORD dwAttrId,
	LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
	PROFILE_START

	LONG rv;
	getset_struct scGetSetStruct;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	DBG(NULL, hCard, "SCardGetSetAttrib()/\n");

	SYS_MutexLock(&contextMutex);

	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}
		/* by default r == NULL */
		if (r &&  strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardGetSetAttrib(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	if (*pcbAttrLen > MAX_BUFFER_SIZE)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardGetSetAttrib(SCARD_E_INSUFFICIENT_BUFFER)\n");
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	scGetSetStruct.hCard = hCard;
	scGetSetStruct.dwAttrId = dwAttrId;
	scGetSetStruct.cbAttrLen = *pcbAttrLen;
	scGetSetStruct.rv = SCARD_E_NO_SERVICE;
	if (SCARD_SET_ATTRIB == command)
		memcpy(scGetSetStruct.pbAttr, pbAttr, *pcbAttrLen);


	if ((rv = SHMrpc(command,
			psContextMap[dwContextIndex].dwClientID,
			&scGetSetStruct, sizeof (scGetSetStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardGetSetAttrib(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
	}

	if ((SCARD_S_SUCCESS == scGetSetStruct.rv) && (SCARD_GET_ATTRIB == command))
	{
		/*
		 * Copy and zero it so any secret information is not leaked
		 */
		if (*pcbAttrLen < scGetSetStruct.cbAttrLen)
		{
			scGetSetStruct.cbAttrLen = *pcbAttrLen;
			scGetSetStruct.rv = SCARD_E_INSUFFICIENT_BUFFER;
		}
		else
			*pcbAttrLen = scGetSetStruct.cbAttrLen;

		if (pbAttr)
			memcpy(pbAttr, scGetSetStruct.pbAttr, scGetSetStruct.cbAttrLen);

		memset(scGetSetStruct.pbAttr, 0x00, sizeof(scGetSetStruct.pbAttr));
	}

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END
	DBGERR("SCardGetSetAttrib(%lx)\n",scGetSetStruct.rv);
	return scGetSetStruct.rv;
}

/**
 * @brief This function sends an APDU to the smart card contained in the reader
 * connected to by SCardConnect().
 *
 * The card responds from the APDU and stores this response in pbRecvBuffer
 * and it's length in SpcbRecvLength.
 * SSendPci and SRecvPci are structures containing the following:
 * @code
 * typedef struct {
 *    DWORD dwProtocol;    // SCARD_PROTOCOL_T0 or SCARD_PROTOCOL_T1
 *    DWORD cbPciLength;   // Length of this structure - not used
 * } SCARD_IO_REQUEST;
 * @endcode
 *
 * @param[in] hCard Connection made from SCardConnect().
 * @param pioSendPci [inout] Structure of protocol information.
 * <ul>
 *   <li>SCARD_PCI_T0 - Pre-defined T=0 PCI structure.
 *   <li>SCARD_PCI_T1 - Pre-defined T=1 PCI structure.
 * </ul>
 * @param[in] pbSendBuffer APDU to send to the card.
 * @param[in] cbSendLength Length of the APDU.
 * @param pioRecvPci [inout] Structure of protocol information.
 * @param[out] pbRecvBuffer Response from the card.
 * @param pcbRecvLength [inout] Length of the response.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid hCard handle.
 * @retval SCARD_E_NOT_TRANSACTED APDU exchange not successful.
 * @retval SCARD_E_PROTO_MISMATCH Connect protocol is different than desired.
 * @retval SCARD_E_INVALID_VALUE Invalid Protocol, reader name, etc.
 * @retval SCARD_E_READER_UNAVAILABLE The reader has been removed.
 * @retval SCARD_W_RESET_CARD The card has been reset by another application.
 * @retval SCARD_W_REMOVED_CARD The card has been removed from the reader.
 *
 * @test
 * @code
 * LONG rv;
 * SCARDCONTEXT hContext;
 * SCARDHANDLE hCard;
 * DWORD dwActiveProtocol, dwSendLength, dwRecvLength;
 * SCARD_IO_REQUEST pioRecvPci;
 * BYTE pbRecvBuffer[10];
 * BYTE pbSendBuffer[] = { 0xC0, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 };
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardConnect(hContext, "Reader X", SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
 * dwSendLength = sizeof(pbSendBuffer);
 * dwRecvLength = sizeof(pbRecvBuffer);
 * rv = SCardTransmit(hCard, SCARD_PCI_T0, pbSendBuffer, dwSendLength, &pioRecvPci, pbRecvBuffer, &dwRecvLength);
 * @endcode
 */
LONG SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
	LPCBYTE pbSendBuffer, DWORD cbSendLength,
	LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer,
	LPDWORD pcbRecvLength)
{
	LONG rv;
	int i;
	DWORD dwContextIndex, dwChannelIndex, dwClientID;

	PROFILE_START

	DBG(NULL, hCard, "SCartTransmit()/\n");

	if (pbSendBuffer == NULL || pbRecvBuffer == NULL ||
			pcbRecvLength == NULL || pioSendPci == NULL) {
		DBGERR("SCardTransmit(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this handle has been opened
	 */
	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardReconnect(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	if (rv == -1) {
		DBGERR("SCardReconnect(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++)
	{
		char *r = psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName;
		PREADER_STATE prs = FETCH(readerStates[i], dwClientID);
		if (prs == NULL) {
			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_E_READER_UNAVAILABLE;
		}

		/* by default r == NULL */
		if (r && strcmp(r, prs->readerName) == 0)
			break;
	}

	if (i == PCSCLITE_MAX_READERS_CONTEXTS)
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardTransmit(SCARD_E_READER_UNAVAILABLE)\n");
		return SCARD_E_READER_UNAVAILABLE;
	}

	if ((cbSendLength > MAX_BUFFER_SIZE_EXTENDED)
		|| (*pcbRecvLength > MAX_BUFFER_SIZE_EXTENDED))
	{
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardTransmit(SCARD_E_INSUFFICIENT_BUFFER)\n");
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	if ((cbSendLength > MAX_BUFFER_SIZE) || (*pcbRecvLength > MAX_BUFFER_SIZE))
	{
		/* extended APDU */
		long buffer0[(sizeof(sharedSegmentMsg) + MAX_BUFFER_SIZE_EXTENDED)/sizeof(long)+1];
		// unsigned char buffer[sizeof(sharedSegmentMsg) + MAX_BUFFER_SIZE_EXTENDED];
		unsigned char* buffer = &buffer0[0];
		transmit_struct_extended *scTransmitStructExtended = (transmit_struct_extended *)buffer;
		sharedSegmentMsg *pmsgStruct = (psharedSegmentMsg)buffer;

		scTransmitStructExtended->hCard = hCard;
		scTransmitStructExtended->cbSendLength = cbSendLength;
		scTransmitStructExtended->pcbRecvLength = *pcbRecvLength;
		scTransmitStructExtended->size = sizeof(*scTransmitStructExtended) + cbSendLength;
		memcpy(&scTransmitStructExtended->pioSendPci, pioSendPci,
			sizeof(SCARD_IO_REQUEST));
		memcpy(scTransmitStructExtended->data, pbSendBuffer, cbSendLength);

		if (pioRecvPci)
		{
			memcpy(&scTransmitStructExtended->pioRecvPci, pioRecvPci,
				sizeof(SCARD_IO_REQUEST));
		}
		else
			scTransmitStructExtended->pioRecvPci.dwProtocol = SCARD_PROTOCOL_ANY;

		switch(pcscCfg.transportType) {
		case SOCKET_UNIX:
		case SOCKET_INETV4:
			rv = WrapSHMWrite(SCARD_TRANSMIT_EXTENDED,
				psContextMap[dwContextIndex].dwClientID,
				scTransmitStructExtended->size,
				PCSCLITE_CLIENT_ATTEMPTS, buffer);

			if (rv == -1)
			{
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardTransmit(SCARD_E_NO_SERVICE)\n");
				return SCARD_E_NO_SERVICE;
			}

			/*
			* Read a message from the server
			*/
			/* read the first block */
			rv = SHMMessageReceive(buffer, sizeof(sharedSegmentMsg),
			psContextMap[dwContextIndex].dwClientID, PCSCLITE_CLIENT_ATTEMPTS);
			if (rv == -1)
			{
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				DBGERR("SCardTransmit(SCARD_F_COMM_ERROR)\n");
				return SCARD_F_COMM_ERROR;
			}

			/* we receive a sharedSegmentMsg and not a transmit_struct_extended */
			scTransmitStructExtended = (transmit_struct_extended *)&(pmsgStruct -> data);

			/* a second block is present */
			if (scTransmitStructExtended->size > PCSCLITE_MAX_MESSAGE_SIZE)
			{
				rv = SHMMessageReceive(buffer + sizeof(sharedSegmentMsg),
					scTransmitStructExtended->size-PCSCLITE_MAX_MESSAGE_SIZE,
					psContextMap[dwContextIndex].dwClientID,
					PCSCLITE_CLIENT_ATTEMPTS);
				if (rv == -1)
				{
					SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
					DBGERR("SCardTransmit(SCARD_F_COMM_ERROR)\n");
					return SCARD_F_COMM_ERROR;
				}
			}
			break;
		}

		if (scTransmitStructExtended -> rv == SCARD_S_SUCCESS)
		{
			/*
			 * Copy and zero it so any secret information is not leaked
			 */
			memcpy(pbRecvBuffer, scTransmitStructExtended -> data,
				scTransmitStructExtended -> pcbRecvLength);
			memset(scTransmitStructExtended -> data, 0x00,
				scTransmitStructExtended -> pcbRecvLength);

			if (pioRecvPci)
				memcpy(pioRecvPci, &scTransmitStructExtended -> pioRecvPci,
					sizeof(SCARD_IO_REQUEST));
		}

		*pcbRecvLength = scTransmitStructExtended -> pcbRecvLength;
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

		rv = scTransmitStructExtended -> rv;
	}
	else
	{
		/* short APDU */
		transmit_struct scTransmitStruct;

		scTransmitStruct.hCard = hCard;
		scTransmitStruct.cbSendLength = cbSendLength;
		scTransmitStruct.pcbRecvLength = *pcbRecvLength;
		memcpy(&scTransmitStruct.pioSendPci, pioSendPci,
			sizeof(SCARD_IO_REQUEST));
		memcpy(scTransmitStruct.pbSendBuffer, pbSendBuffer, cbSendLength);

		if (pioRecvPci)
		{
			memcpy(&scTransmitStruct.pioRecvPci, pioRecvPci,
				sizeof(SCARD_IO_REQUEST));
		}
		else
			scTransmitStruct.pioRecvPci.dwProtocol = SCARD_PROTOCOL_ANY;


		if ((rv = SHMrpc(SCARD_TRANSMIT, dwClientID,
			(void *) &scTransmitStruct, sizeof (scTransmitStruct))) == -1) {
				Log1(PCSC_LOG_INFO, "SCardTransmit(): SHMrpc() returned error");
				SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
				return SCARD_F_COMM_ERROR;
		}

		/*
		 * Zero it and free it so any secret information cannot be leaked
		 */
		memset(scTransmitStruct.pbSendBuffer, 0x00, cbSendLength);

		if (scTransmitStruct.rv == SCARD_S_SUCCESS)
		{
			/*
			 * Copy and zero it so any secret information is not leaked
			 */
			memcpy(pbRecvBuffer, scTransmitStruct.pbRecvBuffer,
				scTransmitStruct.pcbRecvLength);
			memset(scTransmitStruct.pbRecvBuffer, 0x00,
				scTransmitStruct.pcbRecvLength);

			if (pioRecvPci)
				memcpy(pioRecvPci, &scTransmitStruct.pioRecvPci,
					sizeof(SCARD_IO_REQUEST));
		}

		*pcbRecvLength = scTransmitStruct.pcbRecvLength;
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

		rv = scTransmitStruct.rv;
	}

	PROFILE_END

	DBGERR("SCardTransmit(%lx)\n", rv);
	return rv;
}

/**
 * This function returns a list of currently available readers on the system.
 * \p mszReaders is a pointer to a character string that is allocated by the application.
 * If the application sends mszGroups and mszReaders as NULL then this function will
 * return the size of the buffer needed to allocate in pcchReaders.
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 * @param[in] mszGroups List of groups to list readers (not used).
 * @param[out] mszReaders Multi-string with list of readers.
 * @param pcchReaders [inout] Size of multi-string buffer including NULL's.
 *
 * @return Connection status.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid Scope Handle.
 * @retval SCARD_E_INSUFFICIENT_BUFFER Reader buffer not large enough.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * LPSTR mszReaders;
 * DWORD dwReaders;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
 * mszReaders = malloc(sizeof(char)*dwReaders);
 * rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
 * @endcode
 */
LONG SCardListReaders(SCARDCONTEXT hContext, LPCSTR mszGroups,
	LPSTR mszReaders, LPDWORD pcchReaders)
{
	DWORD dwReadersLen;
	int i, lastChrPtr;
	DWORD dwContextIndex, dwClientID;
	void *dummy;

	PROFILE_START

	DBG(hContext, NULL, "SCardListReaders()/\n");

	/* * Check for NULL parameters */
	if (pcchReaders == NULL) {
		DBGERR("SCardListReaders(SCARD_E_INVALID_PARAMETER)\n");
		return SCARD_E_INVALID_PARAMETER;
	}

	SYS_MutexLock(&contextMutex);

	dwContextIndex = SCardGetContextIndice(hContext);

	if (SCardCheckDaemonAvailability(dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardListReaders(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE; /* * Make sure this context has been opened */
	}

	if (dwContextIndex == -1)   {
		DBGERR("SCardListReaders(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}
	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	dwClientID = psContextMap[dwContextIndex].dwClientID;

	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++) {
		dummy = FETCH(readerStates[i], dwClientID);
		/*
		 * If this fails, there is no appropriate error code
		 * to return so we adjust the returned reader list
		 * and length to reflect no readers found, accordingly.
		 */
		if (dummy == NULL) {
			if (mszReaders != NULL) {
				if (*pcchReaders > 0)
					mszReaders[0] = '\0';
				if (*pcchReaders > 1)
					mszReaders[1] = '\0';
			} else
				*pcchReaders = 0;

			SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
			return SCARD_S_SUCCESS;
		}
	}

	dwReadersLen = 0;
	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++) {
		if (readerStates[i]->readerID != 0) {
			dwReadersLen += strlen(readerStates[i]->readerName) + 1;
		}
	}
	/* for the last NULL byte */
	dwReadersLen += 1;

	if ((mszReaders == NULL) || (*pcchReaders == 0)) {
		*pcchReaders = dwReadersLen;
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		return SCARD_S_SUCCESS;
	}

	if (*pcchReaders < dwReadersLen){
		*pcchReaders = dwReadersLen;
		SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);
		DBGERR("SCardListReaders(SCARD_E_INSUFFICIENT_BUFFER)\n");
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	lastChrPtr = 0;
	for (i = 0; i < PCSCLITE_MAX_READERS_CONTEXTS; i++) {
		if (readerStates[i]->readerID != 0) {
			/*
			 * Build the multi-string
			 */
			strcpy(&mszReaders[lastChrPtr],
			   readerStates[i]->readerName);
			lastChrPtr += strlen(&mszReaders[lastChrPtr]) + 1;
		}
	}

	mszReaders[lastChrPtr] = '\0';
	mszReaders[lastChrPtr + 1] = '\0'; /* Add the dbl termination null */

	*pcchReaders = dwReadersLen;
	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END
	return SCARD_S_SUCCESS;
}

/**
 * @brief This function returns a list of currently available reader groups on the system.
 * \p mszGroups is a pointer to a character string that is allocated by the
 * application.  If the application sends mszGroups as NULL then this function
 * will return the size of the buffer needed to allocate in pcchGroups.
 *
 * The group names is a multi-string and separated by a nul character ('\\0') and ended by
 * a double nul character. "SCard$DefaultReaders\\0Group 2\\0\\0".
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 * @param[out] mszGroups List of groups to list readers.
 * @param pcchGroups [inout] Size of multi-string buffer including NULL's.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid Scope Handle.
 * @retval SCARD_E_INSUFFICIENT_BUFFER Reader buffer not large enough.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * LPSTR mszGroups;
 * DWORD dwGroups;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rv = SCardListReaderGroups(hContext, NULL, &dwGroups);
 * mszGroups = malloc(sizeof(char)*dwGroups);
 * rv = SCardListReaderGroups(hContext, mszGroups, &dwGroups);
 * @endcode
 */
LONG SCardListReaderGroups(SCARDCONTEXT hContext, LPSTR mszGroups,
	LPDWORD pcchGroups)
{
	LONG rv = SCARD_S_SUCCESS;
	DWORD dwContextIndex;

	PROFILE_START

	const char ReaderGroup[] = "SCard$DefaultReaders";
	const int dwGroups = strlen(ReaderGroup) + 2;

	DBG(hContext, NULL, "SCarListReaderGroups()/\n");

	SYS_MutexLock(&contextMutex);
	/*
	 * Make sure this context has been opened
	 */
	dwContextIndex = SCardGetContextIndice(hContext);
	if (dwContextIndex == -1) {
		DBGERR("SCardListReaderGroups(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}

	if (SCardCheckDaemonAvailability(
	    psContextMap[dwContextIndex].dwClientID) != SCARD_S_SUCCESS) {
		DBGERR("SCardListReaderGroups(SCARD_E_NO_SERVICE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_NO_SERVICE;
	}

	SYS_MutexLock(psContextMap[dwContextIndex].mMutex);
	SYS_MutexUnLock(&contextMutex);

	if (mszGroups)
	{

		if (*pcchGroups < dwGroups)
			rv = SCARD_E_INSUFFICIENT_BUFFER;
		else
		{
			memset(mszGroups, 0, dwGroups);
			memcpy(mszGroups, ReaderGroup, strlen(ReaderGroup));
		}
	}

	*pcchGroups = dwGroups;

	SYS_MutexUnLock(psContextMap[dwContextIndex].mMutex);

	PROFILE_END

	DBGERR("SCardListReaderGroups(%lx)\n", rv);
	return rv;
}

/**
 * This function cancels all pending blocking requests on the
 * \c SCardGetStatusChange() function.
 *
 * @param[in] hContext Connection context to the PC/SC Resource Manager.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Successful.
 * @retval SCARD_E_INVALID_HANDLE Invalid \p hContext handle.
 *
 * @test
 * @code
 * SCARDCONTEXT hContext;
 * DWORD cReaders;
 * SCARD_READERSTATE rgReaderStates;
 * LONG rv;
 * ...
 * rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
 * rgReaderStates.szReader = strdup("Reader X");
 * rgReaderStates.dwCurrentState = SCARD_STATE_EMPTY;
 * ...
 * / * Spawn off thread for following function * /
 * ...
 * rv = SCardGetStatusChange(hContext, 0, rgReaderStates, cReaders);
 * rv = SCardCancel(hContext);
 * @endcode
 */
LONG SCardCancel(SCARDCONTEXT hContext)
{
	DWORD dwContextIndex;

	PROFILE_START
	SYS_MutexLock(&contextMutex);

	DBG(hContext, NULL, "SCardCancel()/\n");
	dwContextIndex = SCardGetContextIndice(hContext);

	if (dwContextIndex == -1) {
		DBGERR("SCardCancel(SCARD_E_INVALID_HANDLE)\n");
		SYS_MutexUnLock(&contextMutex);
		return SCARD_E_INVALID_HANDLE;
	}
	/*
	 * Set the block status for this Context so blocking calls will
	 * complete
	 */
	psContextMap[dwContextIndex].contextBlockStatus = BLOCK_STATUS_RESUME;

	PROFILE_END
	SYS_MutexUnLock(&contextMutex);

	DBGERR("SCardCancel(SCARD_S_SUCCESS)\n");
	return SCARD_S_SUCCESS;
}

/**
 * @brief Get the index from the Application Context vector \c psContextMap
 * for the passed context.
 *
 * This function is a thread-safe wrapper to the function
 * \c SCardGetContextIndiceTH().
 *
 * @param[in] hContext Application Context whose index will be find.
 *
 * @return Index corresponding to the Application Context or -1 if it is
 * not found.
 */
static LONG SCardGetContextIndice(SCARDCONTEXT hContext)
{
	LONG rv;

	rv = SCardGetContextIndiceTH(hContext);

	return rv;
}

/**
 * @brief Get the index from the Application Context vector \c psContextMap
 * for the passed context.
 *
 * This functions is not thread-safe and should not be called. Instead, call
 * the function \c SCardGetContextIndice().
 *
 * @param[in] hContext Application Context whose index will be find.
 *
 * @return Index corresponding to the Application Context or -1 if it is
 * not found.
 */
static LONG SCardGetContextIndiceTH(SCARDCONTEXT hContext)
{
	int i;

	/*
	 * Find this context and return it's spot in the array
	 */
	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++)
	{
		if ((hContext == psContextMap[i].hContext) && (hContext != 0))
			return i;
	}

	return -1;
}

/**
 * Functions for managing instances of SCardEstablishContext These functions
 * keep track of Context handles and associate the blocking
 * variable contextBlockStatus to an hContext
 */

/**
 * @brief Adds an Application Context to the vector \c psContextMap.
 *
 * @param[in] hContext Application Context ID.
 * @param[in] dwClientID Client connection ID.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Success.
 * @retval SCARD_E_NO_MEMORY There is no free slot to store \p hContext.
 */
static LONG SCardAddContext(SCARDCONTEXT hContext, DWORD dwClientID)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++)
	{
		if (psContextMap[i].hContext == 0)
		{
			psContextMap[i].hContext = hContext;
			psContextMap[i].dwClientID = dwClientID;
			psContextMap[i].contextBlockStatus = BLOCK_STATUS_RESUME;
			if (psContextMap[i].mMutex == NULL) {
				psContextMap[i].mMutex = malloc(sizeof(PCSCLITE_MUTEX));
				SYS_MutexInit(psContextMap[i].mMutex);
			}
			return SCARD_S_SUCCESS;
		}
	}

	return SCARD_E_NO_MEMORY;
}

/**
 * @brief Removes an Application Context from a control vector.
 *
 * @param[in] hContext Application Context to be removed.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Success.
 * @retval SCARD_E_INVALID_HANDLE The context \p hContext was not found.
 */
static LONG SCardRemoveContext(SCARDCONTEXT hContext)
{
	LONG  retIndice;

	retIndice = SCardGetContextIndiceTH(hContext);

	if (retIndice == -1)
		return SCARD_E_INVALID_HANDLE;
	else
	{
		int i;

		psContextMap[retIndice].hContext = 0;
		SHMClientCloseSession(psContextMap[retIndice].dwClientID);
		psContextMap[retIndice].dwClientID = 0;
		psContextMap[retIndice].contextBlockStatus = BLOCK_STATUS_RESUME;

		for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
		{
			/*
			 * Reset the \c hCard structs to zero
			 */
			psContextMap[retIndice].psChannelMap[i].hCard = 0;
			free(psContextMap[retIndice].psChannelMap[i].readerName);
			psContextMap[retIndice].psChannelMap[i].readerName = NULL;
		}

		return SCARD_S_SUCCESS;
	}
}

static LONG SCardGetIndicesFromHandle(
	SCARDHANDLE hCard, PDWORD pdwContextIndice, PDWORD pdwChannelIndice,
	PDWORD pdwClientID)
{
	LONG rv;

	rv = SCardGetIndicesFromHandleTH(hCard, pdwContextIndice, pdwChannelIndice);
	if (rv >= 0)
		*pdwClientID = psContextMap[*pdwContextIndice].dwClientID;
	return rv;
}

static LONG SCardGetIndicesFromHandleTH(
	SCARDHANDLE hCard, PDWORD pdwContextIndice, PDWORD pdwChannelIndice)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXTS; i++)
	{
		if (psContextMap[i].hContext != 0)
		{
			int j;

			for (j = 0; j < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; j++)
			{
				if (psContextMap[i].psChannelMap[j].hCard == hCard)
				{
					*pdwContextIndice = i;
					*pdwChannelIndice = j;

					return SCARD_S_SUCCESS;
				}
			}

		}
	}
	return -1;
}


/*
 * Functions for managing hCard values returned from SCardConnect.
 */

static LONG SCardAddHandle(SCARDHANDLE hCard, DWORD dwContextIndex,
	LPSTR readerName)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
	{
		if (psContextMap[dwContextIndex].psChannelMap[i].hCard == 0)
		{
			psContextMap[dwContextIndex].psChannelMap[i].hCard = hCard;
			psContextMap[dwContextIndex].psChannelMap[i].readerName = strdup(readerName);
			return SCARD_S_SUCCESS;
		}
	}

	return SCARD_E_NO_MEMORY;
}

static LONG SCardRemoveHandle(SCARDHANDLE hCard)
{
	DWORD dwContextIndex, dwChannelIndex, dwClientID;
	LONG rv;

	rv = SCardGetIndicesFromHandle(
		hCard, &dwContextIndex, &dwChannelIndex, &dwClientID);
	if (rv == -1)
		return SCARD_E_INVALID_HANDLE;

	else
	{
		psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].hCard = 0;
		free(psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName);
		psContextMap[dwContextIndex].psChannelMap[dwChannelIndex].readerName = NULL;
		return SCARD_S_SUCCESS;
	}
}



/**
 * @brief Checks if the Server is running.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Server is running.
 * @retval SCARD_E_NO_SERVICE Server is not running.
 */
static LONG SCardCheckDaemonAvailability(DWORD dwClientID)
{
	int fd;
	struct stat statBuffer;


	if (pcscCfg.useMappedMemory) {
		if (SYS_Stat(pcscCfg.pcscdMemMappedFile, &statBuffer) != 0) {
			Log1(PCSC_LOG_ERROR, "PCSC Not Running");
			return SCARD_E_NO_SERVICE;
		}
	} else {
		int rv, pingRetry = 0;
		while((rv = SHMping()) != 0) {
			usleep(50000);
			if (++pingRetry > 10)
				break;
		}
		if (rv != 0) {
			Log1(PCSC_LOG_ERROR,
				"SCardCheckDaemonAvailability(): PCSC Not Running");
			return SCARD_E_NO_SERVICE;
		}
		return SCARD_S_SUCCESS;
	}
	return SCARD_S_SUCCESS;
}

/**
 * free resources allocated by the library
 * You _shall_ call this function if you use dlopen/dlclose to load/unload the
 * library. Otherwise you will exhaust the ressources available.
 */
#ifdef __SUNPRO_C
#pragma fini (SCardUnload)
#endif

void DESTRUCTOR SCardUnload(void)
{
	int i;

	if (!isExecuted)
		return;

	// unmap public shared file from memory
	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
	{
		if (readerStates[i] != NULL)
		{
			if (pcscCfg.useMappedMemory) {
				SYS_PublicMemoryUnmap(
					readerStates[i], sizeof(READER_STATE));
				readerStates[i] = NULL;
			}
		} else {
			      free(readerStates[i]);
			       readerStates[i] = NULL;
		}
	}
	if (pcscCfg.useMappedMemory)
		SYS_CloseFile(mapAddr);
	isExecuted = 0;
}

