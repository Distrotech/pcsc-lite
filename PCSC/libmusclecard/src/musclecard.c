/******************************************************************
 
        MUSCLE SmartCard Development ( http://www.linuxnet.com )
            Title  : musclecard.c
            Package: MuscleCard Framework
            Author : David Corcoran
            Date   : 09/26/01
            License: Copyright (C) 2001-2002 David Corcoran
                     <corcoran@linuxnet.com>
            Purpose: This loads MuscleCard plug-ins and provides
	    functions for applications.

	    You may not remove this header from this file without 
	    prior permission from the author.
  
********************************************************************/

#include "config.h"
#include "musclecard.h"
#include "tokenfactory.h"
#include "debuglog.h"

#ifdef USE_THREAD_SAFETY
#include "wintypes.h"
#include "thread_generic.h"
#include "sys_generic.h"
#endif

#ifdef USE_THREAD_SAFETY
static PCSCLITE_MUTEX mcardMutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static SCARDCONTEXT localHContext = 0;

/*
 * internal function 
 */
MSC_RV pcscToMSC(MSCLong32);
MSC_RV MSCReEstablishConnection(MSCLPTokenConnection);

void mscLockThread()
{
#ifdef USE_THREAD_SAFETY
	SYS_MutexLock(&mcardMutex);
#endif
}

void mscUnLockThread()
{
#ifdef USE_THREAD_SAFETY
	SYS_MutexUnLock(&mcardMutex);
#endif
}

/**************** MSC Connection Functions **************************/

MSC_RV MSCListTokens(MSCULong32 listScope, MSCLPTokenInfo tokenArray,
	MSCPULong32 arrayLength)
{

	MSCLong32 rv;
	SCARD_READERSTATE_A rgReaderStates;
	MSCTokenInfo tokenInfo;
	MSCLPTokenInfo currentToken;
	MSCULong32 tokensFound;
	MSCULong32 readerLength;
	char *readerList;
	int i, strLoc;

	readerLength = 0;
	tokensFound = 0;
	readerList = 0;
	strLoc = 0;
	i = 0;

	if (arrayLength == 0)
		return MSC_INVALID_PARAMETER;
	if (listScope != MSC_LIST_KNOWN &&
		listScope != MSC_LIST_ALL && listScope != MSC_LIST_SLOTS)
	{
		return MSC_INVALID_PARAMETER;
	}

	mscLockThread();
	if (localHContext == 0)
	{
		rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0,
			&localHContext);
		if (pcscToMSC(rv) != MSC_SUCCESS)
		{
			localHContext = 0;
			mscUnLockThread();
			return pcscToMSC(rv);
		}
	}
	mscUnLockThread();

	/*
	 * Get the reader list size 
	 */
	rv = SCardListReaders(localHContext, 0, readerList, &readerLength);

	if (pcscToMSC(rv) != MSC_SUCCESS)
	{
		return pcscToMSC(rv);
	}

	readerList = (char *) malloc(sizeof(char) * readerLength);

	if (readerList == 0)
	{
		return MSC_INTERNAL_ERROR;
	}

	rv = SCardListReaders(localHContext, 0, readerList, &readerLength);

	/*
	 * Now that we have the readers, lets check their status 
	 */
	for (i = 0; i < readerLength - 1; i++)
	{
		rgReaderStates.szReader = &readerList[i];
		rgReaderStates.dwCurrentState = SCARD_STATE_UNAWARE;

		rv = SCardGetStatusChange(localHContext, INFINITE, &rgReaderStates,
			1);

		if (pcscToMSC(rv) != MSC_SUCCESS)
		{
			if (readerList)
				free(readerList);
			return pcscToMSC(rv);
		}

		/*
		 * We only care about slots with a token unless stated 
		 */
		if ((rgReaderStates.dwEventState & SCARD_STATE_PRESENT) ||
			(listScope == MSC_LIST_SLOTS))
		{

			if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT)
			{
				/*
				 * We only care about supported tokens 
				 */
				rv = TPSearchBundlesForAtr(rgReaderStates.rgbAtr,
					rgReaderStates.cbAtr, &tokenInfo);
			}

			/*
			 * Success for this function 
			 */
			if ((rv == 0) || (listScope == MSC_LIST_SLOTS) ||
				(listScope == MSC_LIST_ALL))
			{

				/*
				 * We found something interesting to the application 
				 */
				tokensFound += 1;

				if ((tokensFound <= *arrayLength) && (tokenArray != 0))
				{
					currentToken = &tokenArray[tokensFound - 1];

					if (rgReaderStates.dwEventState & SCARD_STATE_EMPTY)
					{
						currentToken->tokenType |= MSC_TOKEN_TYPE_REMOVED;
						strncpy(currentToken->tokenName,
							MSC_TOKEN_EMPTY_STR, MSC_MAXSIZE_TOKENAME);
					} else if (rv == 0)
					{
						currentToken->tokenType |= MSC_TOKEN_TYPE_KNOWN;
						strncpy(currentToken->tokenName,
							tokenInfo.tokenName, MSC_MAXSIZE_TOKENAME);
					} else
					{
						currentToken->tokenType |= MSC_TOKEN_TYPE_UNKNOWN;
						strncpy(currentToken->tokenName,
							MSC_TOKEN_UNKNOWN_STR, MSC_MAXSIZE_TOKENAME);
					}

					strncpy(currentToken->slotName,
						rgReaderStates.szReader, MAX_READERNAME);

					if (rgReaderStates.dwEventState & SCARD_STATE_PRESENT)
					{
						memcpy(currentToken->tokenId,
							rgReaderStates.rgbAtr, rgReaderStates.cbAtr);
						currentToken->tokenIdLength = rgReaderStates.cbAtr;
					} else
					{
						memset(currentToken->tokenId, 0x00, MAX_ATR_SIZE);
						currentToken->tokenIdLength = 0x00;
					}

					currentToken->tokenState = rgReaderStates.dwEventState;

				}
			}
			/*
			 * End of TPSearch success 
			 */
		}
		/*
		 * End of if token present 
		 */
		while (readerList[++i] != 0) ;
	}	/* End of for .. readers */

	if (readerList)
		free(readerList);

	/*
	 * Application provides null requesting length 
	 */
	if (tokenArray == 0)
	{
		*arrayLength = tokensFound;
		return MSC_SUCCESS;
	}

	/*
	 * Provided length is too small 
	 */
	if (*arrayLength < tokensFound)
	{
		*arrayLength = tokensFound;
		return MSC_INSUFFICIENT_BUFFER;
	}

	*arrayLength = tokensFound;
	return MSC_SUCCESS;
}

MSC_RV MSCEstablishConnection(MSCLPTokenInfo tokenStruct,
	MSCULong32 sharingMode,
	MSCPUChar8 applicationName,
	MSCULong32 nameSize, MSCLPTokenConnection pConnection)
{
	MSCLong32 rv;
	MSCULong32 tokenSize;
	MSCLPTokenInfo tokenList;
	MSCPVoid32 vInitFunction;
	MSCPVoid32 vIdFunction;
	MSCLong32(*libPL_MSCInitializePlugin) (MSCLPTokenConnection);
	MSCLong32(*libPL_MSCIdentifyToken) (MSCLPTokenConnection);
	MSCULong32 dwActiveProtocol;
	int selectedIFD;
	char slotName[MAX_READERNAME];
	MSCULong32 slotNameSize, slotState, slotProtocol;
	MSCUChar8 tokenId[MAX_ATR_SIZE];
	MSCULong32 tokenIdLength;

	tokenSize = 0;
	tokenList = 0;
	tokenSize = 0;
	selectedIFD = -1;
	tokenIdLength = 0;
	slotState = 0;
	slotProtocol = 0;
	slotNameSize = sizeof(slotName);
	vIdFunction = 0;
	vInitFunction = 0;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (tokenStruct == NULL)
		return MSC_INVALID_PARAMETER;
	if (nameSize > MSC_MAXSIZE_AID)
		return MSC_INVALID_PARAMETER;

	pConnection->tokenLibHandle = 0;
	pConnection->hContext = 0;
	pConnection->tokenInfo.tokenIdLength = 0;
	pConnection->shareMode = 0;

	/*
	 * Check the token name strings 
	 */
	if (sharingMode != MSC_SHARE_DIRECT)
	{
		if (strcmp(tokenStruct->tokenName, MSC_TOKEN_EMPTY_STR) == 0)
		{
			return MSC_TOKEN_REMOVED;
		} else if (strcmp(tokenStruct->tokenName,
				MSC_TOKEN_UNKNOWN_STR) == 0)
		{
			return MSC_UNRECOGNIZED_TOKEN;
		}
	}

	/*
	 * Set up the initial connection to the resource manager 
	 */

	mscLockThread();
	if (localHContext == 0)
	{
		rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0,
			&localHContext);
#ifdef MSC_DEBUG
		DebugLogC("SCardEstablishContext returns %s\n",
			pcsc_stringify_error(rv));
#endif
		if (pcscToMSC(rv) != MSC_SUCCESS)
		{
			localHContext = 0;
			mscUnLockThread();
			return pcscToMSC(rv);
		}

		pConnection->hContext = localHContext;
	} else
	{
		pConnection->hContext = localHContext;
	}
	mscUnLockThread();

	rv = SCardConnect(pConnection->hContext, tokenStruct->slotName,
		sharingMode, SCARD_PROTOCOL_ANY,
		&pConnection->hCard, &dwActiveProtocol);

#ifdef MSC_DEBUG
	DebugLogC("SCardConnect returns %s\n", pcsc_stringify_error(rv));
#endif

	if (pcscToMSC(rv) != MSC_SUCCESS)
	{
		return pcscToMSC(rv);
	}

	/*
	 * Set the sendPCI value based on the ActiveProtocol 
	 */
	switch (dwActiveProtocol)
	{
	case SCARD_PROTOCOL_T0:
		pConnection->ioType = SCARD_PCI_T0;
		break;
	case SCARD_PROTOCOL_T1:
		pConnection->ioType = SCARD_PCI_T1;
		break;
	default:
		pConnection->ioType = SCARD_PCI_RAW;
		break;
	}

	/*
	 * Call SCardStatus, make sure the card information matches if it does 
	 * not return an error.  If it does, copy it 
	 */

	rv = SCardStatus(pConnection->hCard, slotName,
		&slotNameSize, &slotState, &slotProtocol, tokenId, &tokenIdLength);

#ifdef MSC_DEBUG
	DebugLogC("SCardStatus returns %s\n", pcsc_stringify_error(rv));
#endif

	if (pcscToMSC(rv) != MSC_SUCCESS)
	{
		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		pConnection->hCard = 0;
		return pcscToMSC(rv);
	}

	if ((sharingMode == MSC_SHARE_DIRECT) && (slotState & SCARD_ABSENT))
	{

		/*
		 * They asked for direct mode and no card is inserted so we are
		 * done with this 
		 */
		pConnection->shareMode = sharingMode;
		return MSC_SUCCESS;
	}

	if ((tokenIdLength != tokenStruct->tokenIdLength) ||
		(strcmp(slotName, tokenStruct->slotName) != 0) ||
		(memcmp(tokenId, tokenStruct->tokenId, tokenIdLength) != 0))
	{

		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		pConnection->hCard = 0;
		return MSC_INCONSISTENT_STATUS;
	}

	memcpy(pConnection->tokenInfo.tokenId, tokenId, tokenIdLength);
	pConnection->tokenInfo.tokenIdLength = tokenIdLength;
	strncpy(pConnection->tokenInfo.slotName, tokenStruct->slotName,
		MAX_READERNAME);
	strncpy(pConnection->tokenInfo.tokenName, tokenStruct->tokenName,
		MSC_MAXSIZE_TOKENAME);

	/*
	 * Load the library for the token 
	 */
	rv = TPLoadToken(pConnection);

#ifdef MSC_DEBUG
	DebugLogC("TPLoadToken returns %s\n", pcsc_stringify_error(rv));
#endif

	if (rv != SCARD_S_SUCCESS)
	{
		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		pConnection->hCard = 0;
		return pcscToMSC(rv);
	}

	/*
	 * Select the AID or initialization routine for the card 
	 */
	vInitFunction = pConnection->libPointers.pvfInitializePlugin;
	vIdFunction = pConnection->libPointers.pvfIdentifyToken;

	if (vInitFunction == 0)
	{
		DebugLogC("Error: Card service failure: %s\n",
			"InitializePlugin function missing");
		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		pConnection->hCard = 0;
		return MSC_UNSUPPORTED_FEATURE;
	}

	if (vIdFunction == 0)
	{
		DebugLogC("Error: Card service failure: %s\n",
			"IdentifyToken function missing");
		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		pConnection->hCard = 0;
		return MSC_UNSUPPORTED_FEATURE;
	}

	libPL_MSCInitializePlugin = (MSCLong32(*)(MSCLPTokenConnection))
		vInitFunction;

	libPL_MSCIdentifyToken = (MSCLong32(*)(MSCLPTokenConnection))
		vIdFunction;

	rv = (*libPL_MSCInitializePlugin) (pConnection);

	if (rv != MSC_SUCCESS)
	{
		SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
		if (pConnection->tokenLibHandle != 0)
		{
			TPUnloadToken(pConnection);
			pConnection->tokenLibHandle = 0;
		}
		pConnection->hCard = 0;
	}

	if ((applicationName == 0) || (nameSize == 0))
	{
		/*
		 * Use the default AID given by the Info.plist 
		 */
		rv = (*libPL_MSCIdentifyToken) (pConnection);
	} else
	{
		pConnection->tokenInfo.tokenAppLen = nameSize;
		memcpy(pConnection->tokenInfo.tokenApp, applicationName, nameSize);
		rv = (*libPL_MSCIdentifyToken) (pConnection);
	}

#ifdef MSC_DEBUG
	DebugLogC("MSCIdentifyToken returns %s\n", msc_error(rv));
#endif

	if (sharingMode != MSC_SHARE_DIRECT)
	{
		if (rv != MSC_SUCCESS)
		{
			SCardDisconnect(pConnection->hCard, SCARD_LEAVE_CARD);
			if (pConnection->tokenLibHandle != 0)
			{
				TPUnloadToken(pConnection);
				pConnection->tokenLibHandle = 0;
			}
			pConnection->hCard = 0;

			if (rv == MSC_SHARING_VIOLATION)
			{
				return rv;
			} else
			{
				return MSC_UNRECOGNIZED_TOKEN;
			}
		}
	}

	pConnection->shareMode = sharingMode;
	return MSC_SUCCESS;
}

MSC_RV MSCReleaseConnection(MSCLPTokenConnection pConnection,
	MSCULong32 endAction)
{

	MSCLong32 rv = SCARD_S_SUCCESS;
	MSCLong32(*libPL_MSCFinalizePlugin) (MSCLPTokenConnection);
	MSCPVoid32 vFunction;

	vFunction = 0;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (pConnection->tokenLibHandle == 0 ||
		pConnection->hContext == 0 || pConnection->hCard == 0)
	{
		return MSC_INVALID_HANDLE;
	}

	/*
	 * Select finalization routine for the token plugin 
	 */
	vFunction = pConnection->libPointers.pvfFinalizePlugin;

	if (vFunction == 0)
	{
		DebugLogC("Error: Card service failure: %s\n",
			"FinalizePlugin function missing");
		return MSC_INTERNAL_ERROR;
	}

	libPL_MSCFinalizePlugin = (MSCLong32(*)(MSCLPTokenConnection))
		vFunction;

	/*
	 * Stop and clean up the plugin 
	 */
	rv = (*libPL_MSCFinalizePlugin) (pConnection);

	/*
	 * Disconnect from the token 
	 */
	if (pConnection->hCard != 0)
	{
		rv = SCardDisconnect(pConnection->hCard, endAction);
		if (pcscToMSC(rv) != MSC_SUCCESS)
		{
			return pcscToMSC(rv);
		}
	}

	/*
	 * Unload the token driver 
	 */
	if (pConnection->tokenLibHandle != 0)
	{
		rv = TPUnloadToken(pConnection);
		pConnection->tokenLibHandle = 0;
	}

	pConnection->tokenLibHandle = 0;
	pConnection->hCard = 0;
	pConnection->hContext = 0;
	pConnection->shareMode = 0;

	return MSC_SUCCESS;
}

MSC_RV MSCWaitForTokenEvent(MSCLPTokenInfo tokenArray,
	MSCULong32 arraySize, MSCULong32 timeoutValue)
{

	MSCLong32 rv, rt;
	LPSCARD_READERSTATE_A rgReaderStates;
	MSCTokenInfo tokenInfo;
	int i;

	rgReaderStates = 0;

	/*
	 * Allocate array of SCARD_READERSTATE_A structures, set UNAWARE on
	 * all of the structures to get the current status and then send them
	 * to GetStatusChange for blocking event 
	 */

	if (arraySize == 0)
	{
		return MSC_SUCCESS;
	} else if (arraySize > MSC_MAXSIZE_TOKENARRAY)
	{
		return MSC_INSUFFICIENT_BUFFER;
	}

	/*
	 * Set up the initial connection to the resource manager 
	 */

	mscLockThread();
	if (localHContext == 0)
	{
		rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0, 0,
			&localHContext);
		if (pcscToMSC(rv) != MSC_SUCCESS)
		{
			localHContext = 0;
			mscUnLockThread();
			return pcscToMSC(rv);
		}
	}
	mscUnLockThread();

	rgReaderStates = (LPSCARD_READERSTATE_A)
		malloc(sizeof(SCARD_READERSTATE_A) * arraySize);

	if (rgReaderStates == 0)
	{
		return MSC_INTERNAL_ERROR;
	}

	for (i = 0; i < arraySize; i++)
	{
		/*
		 * Make sure they don't pass an empty structure 
		 */
		if (strlen(tokenArray[i].slotName) == 0)
		{
			free(rgReaderStates);
			return MSC_INVALID_PARAMETER;
		}

		rgReaderStates[i].szReader = tokenArray[i].slotName;
		rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
		rgReaderStates[i].dwEventState = 0;
	}

	rv = SCardGetStatusChange(localHContext, timeoutValue,
		rgReaderStates, arraySize);

	if (rv != SCARD_S_SUCCESS)
	{
		free(rgReaderStates);
		return pcscToMSC(rv);
	}

	for (i = 0; i < arraySize; i++)
	{
		if (tokenArray[i].tokenState == 0)
		{
			rgReaderStates[i].dwCurrentState =
				rgReaderStates[i].dwEventState;
		} else if (tokenArray[i].tokenState == MSC_STATE_UNAWARE)
		{
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
		} else
		{
			rgReaderStates[i].dwCurrentState = tokenArray[i].tokenState;
		}
		rgReaderStates[i].dwEventState = 0;
	}

	rv = SCardGetStatusChange(localHContext, timeoutValue,
		rgReaderStates, arraySize);

	for (i = 0; i < arraySize; i++)
	{
		tokenArray[i].tokenState = rgReaderStates[i].dwEventState;

		if (tokenArray[i].tokenState & MSC_STATE_CHANGED)
		{
			/*
			 * If it is removed, we need to update the names/etc 
			 */
			if (tokenArray[i].tokenState & MSC_STATE_EMPTY)
			{
				memset(tokenArray[i].tokenId, 0x00, MAX_ATR_SIZE);
				tokenArray[i].tokenIdLength = 0;
				tokenArray[i].tokenType = MSC_TOKEN_TYPE_REMOVED;
				strncpy(tokenArray[i].tokenName, MSC_TOKEN_EMPTY_STR,
					MSC_MAXSIZE_TOKENAME);
			} else if (tokenArray[i].tokenState & MSC_STATE_PRESENT)
			{
				memcpy(tokenArray[i].tokenId, rgReaderStates[i].rgbAtr,
					rgReaderStates[i].cbAtr);
				tokenArray[i].tokenIdLength = rgReaderStates[i].cbAtr;

				rt = TPSearchBundlesForAtr(rgReaderStates[i].rgbAtr,
					rgReaderStates[i].cbAtr, &tokenInfo);
				/*
				 * Successfully found 
				 */
				if (rt == 0)
				{
					tokenArray[i].tokenType = MSC_TOKEN_TYPE_KNOWN;
					strncpy(tokenArray[i].tokenName, tokenInfo.tokenName,
						MSC_MAXSIZE_TOKENAME);
				} else
				{
					tokenArray[i].tokenType = MSC_TOKEN_TYPE_UNKNOWN;
					strncpy(tokenArray[i].tokenName, MSC_TOKEN_UNKNOWN_STR,
						MSC_MAXSIZE_TOKENAME);
				}
			}
		}
	}

	free(rgReaderStates);
	return pcscToMSC(rv);
}

MSC_RV MSCCancelEventWait(void)
{

	MSCLong32 rv;

	rv = SCardCancel(localHContext);

	return pcscToMSC(rv);
}

/************************ Start of Callbacks ****************************/
#ifdef USE_THREAD_SAFETY
void *_MSCEventThread(void *arg)
{

	MSCLong32 rv;
	MSCLPEventWaitInfo evlist;
	MSCLong32 curToken;

	if (arg == NULL)
	{
		pthread_exit(NULL);
	}

	evlist = (MSCLPEventWaitInfo) arg;

	while (1)
	{
		rv = MSCWaitForTokenEvent(evlist->tokenArray, evlist->arraySize,
			MSC_NO_TIMEOUT);

		if (rv == MSC_SUCCESS)
		{
			(evlist->callBack) (evlist->tokenArray, evlist->arraySize,
				evlist->appData);
		} else
		{
			for (curToken = 0; curToken < evlist->arraySize; curToken++)
			{
				if (evlist->tokenArray[curToken].addParams)
				{
					free(evlist->tokenArray[curToken].addParams);
				}
			}

			free(evlist);
			pthread_exit(&rv);

		}
	}
}

MSC_RV MSCCallbackForTokenEvent(MSCLPTokenInfo tokenArray,
	MSCULong32 arraySize, MSCCallBack callBack, MSCPVoid32 appData)
{
	MSCLPEventWaitInfo evlist;
	MSCULong32 curToken;
	pthread_t newThread;

	/*
	 * Create the event wait list 
	 */
	evlist = (MSCLPEventWaitInfo) malloc(sizeof(MSCEventWaitInfo));

	if (evlist == NULL)
	{
		return MSC_INTERNAL_ERROR;
	}

	evlist->arraySize = arraySize;
	evlist->tokenArray = malloc(sizeof(MSCTokenInfo) * arraySize);
	evlist->appData = appData;
	evlist->callBack = callBack;

	if (evlist->tokenArray == NULL)
	{
		free(evlist);
		return MSC_INTERNAL_ERROR;
	}

	mscLockThread();
	memcpy(evlist->tokenArray, tokenArray,
		sizeof(MSCTokenInfo) * arraySize);

	/*
	 * Copy the "extra" data 
	 */
	for (curToken = 0; curToken < arraySize; curToken++)
	{
		if (tokenArray[curToken].addParams != NULL)
		{
			evlist->tokenArray[curToken].addParams =
				malloc(evlist->tokenArray[curToken].addParamsSize);
			memcpy((void *) (evlist->tokenArray[curToken].addParams),
				&tokenArray[curToken],
				evlist->tokenArray[curToken].addParamsSize);

		}
	}
	mscUnLockThread();

	if (pthread_create(&newThread, NULL, _MSCEventThread, (void *) evlist))
	{
		return MSC_INTERNAL_ERROR;
	}

	return MSC_SUCCESS;
}

MSC_RV MSCCallbackCancelEvent()
{

	return MSCCancelEventWait();
}

#endif
/************************** End of Callbacks *****************************/

MSC_RV MSCBeginTransaction(MSCLPTokenConnection pConnection)
{

	MSCLong32 rv;
	MSCLong32 ret;

	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	while (1)
	{
		rv = SCardBeginTransaction(pConnection->hCard);
		ret = pcscToMSC(rv);

		if (ret == MSC_SUCCESS)
			break;
		if (ret == MSC_TOKEN_RESET)
		{
		        pConnection->tokenInfo.tokenType |= 
			  MSC_TOKEN_TYPE_RESET;
			ret = MSCReEstablishConnection(pConnection);
			if (ret != MSC_SUCCESS)
				break;
			continue;
		} else if (ret == MSC_TOKEN_REMOVED)
		{
			return ret;
		}
	}

	return ret;
}

MSC_RV MSCEndTransaction(MSCLPTokenConnection pConnection,
	MSCULong32 endAction)
{

	MSCLong32 rv;
	MSCLong32 ret;

	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	while (1)
	{
		rv = SCardEndTransaction(pConnection->hCard, endAction);
		ret = pcscToMSC(rv);

		if (ret == MSC_SUCCESS)
			break;
		if (ret == MSC_TOKEN_RESET)
		{
		        pConnection->tokenInfo.tokenType |= 
			  MSC_TOKEN_TYPE_RESET;
			ret = MSCReEstablishConnection(pConnection);
			if (ret != MSC_SUCCESS)
				break;
			continue;
		} else if (ret == MSC_TOKEN_REMOVED)
		{
			return ret;
		}
	}

	return ret;
}

MSC_RV MSCWriteFramework(MSCLPTokenConnection pConnection,
	MSCLPInitTokenParams pInitParams)
{

	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCWriteFramework) (MSCLPTokenConnection,
		MSCLPInitTokenParams);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfWriteFramework;

	if (vFunction != 0)
	{
		libMSCWriteFramework = (MSCLong32(*)(MSCLPTokenConnection,
				MSCLPInitTokenParams)) vFunction;
		rv = (*libMSCWriteFramework) (pConnection, pInitParams);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

/*
 * Real MSC functions 
 */

MSC_RV MSCGetStatus(MSCLPTokenConnection pConnection,
	MSCLPStatusInfo pStatusInfo)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCGetStatus) (MSCLPTokenConnection, MSCLPStatusInfo);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfGetStatus;

	if (vFunction != 0)
	{
		libMSCGetStatus = (MSCLong32(*)(MSCLPTokenConnection,
				MSCLPStatusInfo)) vFunction;
		rv = (*libMSCGetStatus) (pConnection, pStatusInfo);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCGetCapabilities(MSCLPTokenConnection pConnection, MSCULong32 Tag,
	MSCPUChar8 Value, MSCPULong32 Length)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCGetCapabilities) (MSCLPTokenConnection, MSCULong32,
		MSCPUChar8, MSCPULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfGetCapabilities;

	if (vFunction != 0)
	{
		libMSCGetCapabilities =
			(MSCLong32(*)(MSCLPTokenConnection, MSCULong32, MSCPUChar8,
				MSCPULong32)) vFunction;
		rv = (*libMSCGetCapabilities) (pConnection, Tag, Value, Length);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCExtendedFeature(MSCLPTokenConnection pConnection,
	MSCULong32 extFeature, MSCPUChar8 outData,
	MSCULong32 outLength, MSCPUChar8 inData, MSCPULong32 inLength)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCExtendedFeature) (MSCLPTokenConnection, MSCULong32,
		MSCPUChar8, MSCULong32, MSCPUChar8, MSCPULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfExtendedFeature;

	if (vFunction != 0)
	{
		libMSCExtendedFeature =
			(MSCLong32(*)(MSCLPTokenConnection, MSCULong32, MSCPUChar8,
				MSCULong32, MSCPUChar8, MSCPULong32)) vFunction;
		rv = (*libMSCExtendedFeature) (pConnection, extFeature, outData,
			outLength, inData, inLength);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCGenerateKeys(MSCLPTokenConnection pConnection,
	MSCUChar8 prvKeyNum, MSCUChar8 pubKeyNum, MSCLPGenKeyParams pParams)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCGenerateKeys) (MSCLPTokenConnection, MSCUChar8,
		MSCUChar8, MSCLPGenKeyParams);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfGenerateKeys;

	if (vFunction != 0)
	{
		libMSCGenerateKeys = (MSCLong32(*)(MSCLPTokenConnection,
				MSCUChar8, MSCUChar8, MSCLPGenKeyParams)) vFunction;
		rv = (*libMSCGenerateKeys) (pConnection, prvKeyNum, pubKeyNum,
			pParams);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCImportKey(MSCLPTokenConnection pConnection, MSCUChar8 keyNum,
		    MSCUChar8 keyPartner, MSCLPKeyACL pKeyACL, 
		    MSCPUChar8 pKeyBlob,MSCULong32 keyBlobSize, 
		    MSCLPKeyPolicy keyPolicy, MSCPVoid32 pAddParams, 
		    MSCUChar8 addParamsSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCImportKey) (MSCLPTokenConnection, MSCUChar8, 
				     MSCUChar8, MSCLPKeyACL, MSCPUChar8, 
				     MSCULong32, MSCLPKeyPolicy, MSCPVoid32,
				     MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfImportKey;

	if (vFunction != 0)
	{
		libMSCImportKey = (MSCLong32(*)(MSCLPTokenConnection, 
						MSCUChar8, MSCUChar8,
						MSCLPKeyACL, MSCPUChar8, 
						MSCULong32, MSCLPKeyPolicy, 
						MSCPVoid32, MSCUChar8)) 
		  vFunction;

		rv = (*libMSCImportKey) (pConnection, keyNum, keyPartner, 
					 pKeyACL, pKeyBlob, keyBlobSize, 
					 keyPolicy, pAddParams, addParamsSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCExportKey(MSCLPTokenConnection pConnection, MSCUChar8 keyNum,
		    MSCPUChar8 pKeyBlob, MSCPULong32 keyBlobSize,
		    MSCPVoid32 pAddParams, MSCUChar8 addParamsSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCExportKey) (MSCLPTokenConnection, MSCUChar8,
		MSCPUChar8, MSCPULong32, MSCPVoid32, MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfExportKey;

	if (vFunction != 0)
	{
		libMSCExportKey = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCPUChar8, MSCPULong32, MSCPVoid32, MSCUChar8)) vFunction;
		rv = (*libMSCExportKey) (pConnection, keyNum, pKeyBlob,
			keyBlobSize, pAddParams, addParamsSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCComputeCrypt(MSCLPTokenConnection pConnection,
	MSCLPCryptInit cryptInit, MSCPUChar8 pInputData,
	MSCULong32 inputDataSize, MSCPUChar8 pOutputData,
	MSCPULong32 outputDataSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCComputeCrypt) (MSCLPTokenConnection, MSCLPCryptInit,
		MSCPUChar8, MSCULong32, MSCPUChar8, MSCPULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfComputeCrypt;

	if (vFunction != 0)
	{
		libMSCComputeCrypt =
			(MSCLong32(*)(MSCLPTokenConnection, MSCLPCryptInit, MSCPUChar8,
				MSCULong32, MSCPUChar8, MSCPULong32)) vFunction;
		rv = (*libMSCComputeCrypt) (pConnection, cryptInit, pInputData,
			inputDataSize, pOutputData, outputDataSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCExtAuthenticate(MSCLPTokenConnection pConnection,
	MSCUChar8 keyNum, MSCUChar8 cipherMode, MSCUChar8 cipherDirection,
	MSCPUChar8 pData, MSCULong32 dataSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCExtAuthenticate) (MSCLPTokenConnection, MSCUChar8,
		MSCUChar8, MSCUChar8, MSCPUChar8, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfExtAuthenticate;

	if (vFunction != 0)
	{
		libMSCExtAuthenticate =
			(MSCLong32(*)(MSCLPTokenConnection, MSCUChar8, MSCUChar8,
				MSCUChar8, MSCPUChar8, MSCULong32)) vFunction;
		rv = (*libMSCExtAuthenticate) (pConnection, keyNum, cipherMode,
			cipherDirection, pData, dataSize);
	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCListKeys(MSCLPTokenConnection pConnection, MSCUChar8 seqOption,
	MSCLPKeyInfo pKeyInfo)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCListKeys) (MSCLPTokenConnection, MSCUChar8,
		MSCLPKeyInfo);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfListKeys;

	if (vFunction != 0)
	{
		libMSCListKeys = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCLPKeyInfo)) vFunction;
		rv = (*libMSCListKeys) (pConnection, seqOption, pKeyInfo);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCImportCertificate(MSCLPTokenConnection pConnection,
	MSCULong32 certNumber, MSCLPCertInfo certInfo,
	MSCPUChar8 certBlob, MSCULong32 certBlobSize,
	MSCPVoid32 pAddParams, MSCULong32 addParamsSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCImportCertificate) (MSCLPTokenConnection, MSCULong32,
		MSCLPCertInfo, MSCPUChar8, MSCULong32, MSCPVoid32, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfImportCertificate;

	if (vFunction != 0)
	{
		libMSCImportCertificate = (MSCLong32(*)
			(MSCLPTokenConnection, MSCULong32,
				MSCLPCertInfo, MSCPUChar8,
				MSCULong32, MSCPVoid32, MSCULong32)) vFunction;
		rv = (*libMSCImportCertificate) (pConnection, certNumber, certInfo,
			certBlob, certBlobSize, pAddParams, addParamsSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCExportCertificate(MSCLPTokenConnection pConnection,
	MSCULong32 certNumber, MSCPUChar8 certBlob,
	MSCPULong32 certBlobSize, MSCPVoid32 pAddParams,
	MSCULong32 addParamsSize)
{

	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCExportCertificate) (MSCLPTokenConnection, MSCULong32,
		MSCPUChar8, MSCPULong32, MSCPVoid32, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfExportCertificate;

	if (vFunction != 0)
	{
		libMSCExportCertificate = (MSCLong32(*)
			(MSCLPTokenConnection, MSCULong32,
				MSCPUChar8, MSCPULong32, MSCPVoid32,
				MSCULong32)) vFunction;
		rv = (*libMSCExportCertificate) (pConnection, certNumber, certBlob,
			certBlobSize, pAddParams, addParamsSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCDeleteCertificate(MSCLPTokenConnection pConnection,
	MSCULong32 certNumber)
{

	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCDeleteCertificate) (MSCLPTokenConnection, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfDeleteCertificate;

	if (vFunction != 0)
	{
		libMSCDeleteCertificate = (MSCLong32(*)
			(MSCLPTokenConnection, MSCULong32)) vFunction;
		rv = (*libMSCDeleteCertificate) (pConnection, certNumber);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCListCertificates(MSCLPTokenConnection pConnection,
	MSCUChar8 seqOption, MSCLPCertInfo pCertInfo)
{

	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCListCertificates) (MSCLPTokenConnection, MSCUChar8,
		MSCLPCertInfo);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfListCertificates;

	if (vFunction != 0)
	{
		libMSCListCertificates = (MSCLong32(*)
			(MSCLPTokenConnection, MSCUChar8, MSCLPCertInfo)) vFunction;
		rv = (*libMSCListCertificates) (pConnection, seqOption, pCertInfo);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCCreatePIN(MSCLPTokenConnection pConnection, MSCUChar8 pinNum,
	MSCUChar8 pinAttempts, MSCPUChar8 pPinCode,
	MSCULong32 pinCodeSize, MSCPUChar8 pUnblockCode,
	MSCUChar8 unblockCodeSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCCreatePIN) (MSCLPTokenConnection, MSCUChar8,
		MSCUChar8, MSCPUChar8, MSCULong32, MSCPUChar8, MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfCreatePIN;

	if (vFunction != 0)
	{
		libMSCCreatePIN = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCUChar8, MSCPUChar8,
				MSCULong32, MSCPUChar8, MSCUChar8)) vFunction;
		rv = (*libMSCCreatePIN) (pConnection, pinNum, pinAttempts,
			pPinCode, pinCodeSize, pUnblockCode, unblockCodeSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCVerifyPIN(MSCLPTokenConnection pConnection, MSCUChar8 pinNum,
	MSCPUChar8 pPinCode, MSCULong32 pinCodeSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCVerifyPIN) (MSCLPTokenConnection, MSCUChar8,
		MSCPUChar8, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfVerifyPIN;

	if (vFunction != 0)
	{
		libMSCVerifyPIN = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCPUChar8, MSCULong32)) vFunction;
		rv = (*libMSCVerifyPIN) (pConnection, pinNum, pPinCode,
			pinCodeSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCChangePIN(MSCLPTokenConnection pConnection, MSCUChar8 pinNum,
	MSCPUChar8 pOldPinCode, MSCUChar8 oldPinCodeSize,
	MSCPUChar8 pNewPinCode, MSCUChar8 newPinCodeSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCChangePIN) (MSCLPTokenConnection, MSCUChar8,
		MSCPUChar8, MSCUChar8, MSCPUChar8, MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfChangePIN;

	if (vFunction != 0)
	{
		libMSCChangePIN = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCPUChar8, MSCUChar8, MSCPUChar8, MSCUChar8)) vFunction;
		rv = (*libMSCChangePIN) (pConnection, pinNum, pOldPinCode,
			oldPinCodeSize, pNewPinCode, newPinCodeSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCUnblockPIN(MSCLPTokenConnection pConnection, MSCUChar8 pinNum,
	MSCPUChar8 pUnblockCode, MSCULong32 unblockCodeSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCUnblockPIN) (MSCLPTokenConnection, MSCUChar8,
		MSCPUChar8, MSCULong32);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfUnblockPIN;

	if (vFunction != 0)
	{
		libMSCUnblockPIN = (MSCLong32(*)(MSCLPTokenConnection,
				MSCUChar8, MSCPUChar8, MSCULong32)) vFunction;
		rv = (*libMSCUnblockPIN) (pConnection, pinNum, pUnblockCode,
			unblockCodeSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCListPINs(MSCLPTokenConnection pConnection,
	MSCPUShort16 pPinBitMask)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCListPINs) (MSCLPTokenConnection, MSCPUShort16);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfListPINs;

	if (vFunction != 0)
	{
		libMSCListPINs = (MSCLong32(*)(MSCLPTokenConnection,
				MSCPUShort16)) vFunction;
		rv = (*libMSCListPINs) (pConnection, pPinBitMask);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCCreateObject(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCULong32 objectSize, MSCLPObjectACL pObjectACL)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCCreateObject) (MSCLPTokenConnection, MSCString,
		MSCULong32, MSCLPObjectACL);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfCreateObject;

	if (vFunction != 0)
	{
		libMSCCreateObject = (MSCLong32(*)(MSCLPTokenConnection, MSCString,
				MSCULong32, MSCLPObjectACL)) vFunction;
		rv = (*libMSCCreateObject) (pConnection, objectID, objectSize,
			pObjectACL);
	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCDeleteObject(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCUChar8 zeroFlag)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCDeleteObject) (MSCLPTokenConnection, MSCString,
		MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfDeleteObject;

	if (vFunction != 0)
	{
		libMSCDeleteObject = (MSCLong32(*)(MSCLPTokenConnection, MSCString,
				MSCUChar8)) vFunction;
		rv = (*libMSCDeleteObject) (pConnection, objectID, zeroFlag);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCWriteObject(MSCLPTokenConnection pConnection, MSCString objectID,
	MSCULong32 offset, MSCPUChar8 pInputData, MSCUChar8 dataSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCWriteObject) (MSCLPTokenConnection, MSCString,
		MSCULong32, MSCPUChar8, MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfWriteObject;

	if (vFunction != 0)
	{
		libMSCWriteObject = (MSCLong32(*)(MSCLPTokenConnection, MSCString,
				MSCULong32, MSCPUChar8, MSCUChar8)) vFunction;
		rv = (*libMSCWriteObject) (pConnection, objectID, offset,
			pInputData, dataSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCReadObject(MSCLPTokenConnection pConnection, MSCString objectID,
	MSCULong32 offset, MSCPUChar8 pOutputData, MSCUChar8 dataSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCReadObject) (MSCLPTokenConnection, MSCString,
		MSCULong32, MSCPUChar8, MSCUChar8);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfReadObject;

	if (vFunction != 0)
	{
		libMSCReadObject = (MSCLong32(*)(MSCLPTokenConnection, MSCString,
				MSCULong32, MSCPUChar8, MSCUChar8)) vFunction;
		rv = (*libMSCReadObject) (pConnection, objectID, offset,
			pOutputData, dataSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCListObjects(MSCLPTokenConnection pConnection,
	MSCUChar8 seqOption, MSCLPObjectInfo pObjectInfo)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCListObjects) (MSCLPTokenConnection, MSCUChar8,
		MSCLPObjectInfo);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfListObjects;

	if (vFunction != 0)
	{
		libMSCListObjects = (MSCLong32(*)(MSCLPTokenConnection, MSCUChar8,
				MSCLPObjectInfo)) vFunction;
		rv = (*libMSCListObjects) (pConnection, seqOption, pObjectInfo);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCLogoutAll(MSCLPTokenConnection pConnection)
{

	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCLogoutAll) (MSCLPTokenConnection);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfLogoutAll;

	if (vFunction != 0)
	{
		libMSCLogoutAll = (MSCLong32(*)(MSCLPTokenConnection)) vFunction;
		rv = (*libMSCLogoutAll) (pConnection);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCGetChallenge(MSCLPTokenConnection pConnection, MSCPUChar8 pSeed,
	MSCUShort16 seedSize, MSCPUChar8 pRandomData,
	MSCUShort16 randomDataSize)
{
	MSCLong32 rv;
	MSCPVoid32 vFunction;
	MSCLong32(*libMSCGetChallenge) (MSCLPTokenConnection, MSCPUChar8,
		MSCUShort16, MSCPUChar8, MSCUShort16);

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	vFunction = pConnection->libPointers.pvfGetChallenge;

	if (vFunction != 0)
	{
		libMSCGetChallenge = (MSCLong32(*)(MSCLPTokenConnection,
				MSCPUChar8, MSCUShort16,
				MSCPUChar8, MSCUShort16)) vFunction;
		rv = (*libMSCGetChallenge) (pConnection, pSeed, seedSize,
			pRandomData, randomDataSize);

	} else
	{
		return MSC_UNSUPPORTED_FEATURE;
	}

	return rv;
}

MSC_RV MSCGetKeyAttributes(MSCLPTokenConnection pConnection,
	MSCUChar8 keyNumber, MSCLPKeyInfo pKeyInfo)
{

	MSC_RV rv;
	MSCKeyInfo keyInfo;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	rv = MSCListKeys(pConnection, MSC_SEQUENCE_RESET, &keyInfo);

	if (rv != MSC_SEQUENCE_END && rv != MSC_SUCCESS)
	{
		return rv;
	}

	if (rv == MSC_SEQUENCE_END)
	{
		return MSC_INVALID_PARAMETER;
	}

	if (keyNumber == keyInfo.keyNum)
	{
		pKeyInfo->keyNum = keyInfo.keyNum;
		pKeyInfo->keyType = keyInfo.keyType;
		pKeyInfo->keyPartner = keyInfo.keyPartner;
		pKeyInfo->keySize = keyInfo.keySize;

		pKeyInfo->keyPolicy.cipherMode = keyInfo.keyPolicy.cipherMode;
		pKeyInfo->keyPolicy.cipherDirection =
			keyInfo.keyPolicy.cipherDirection;

		pKeyInfo->keyACL.readPermission = keyInfo.keyACL.readPermission;
		pKeyInfo->keyACL.writePermission = keyInfo.keyACL.writePermission;
		pKeyInfo->keyACL.usePermission = keyInfo.keyACL.usePermission;

		return MSC_SUCCESS;
	}

	do
	{
		rv = MSCListKeys(pConnection, MSC_SEQUENCE_NEXT, &keyInfo);
		if (keyNumber == keyInfo.keyNum)
			break;
	}
	while (rv == MSC_SUCCESS);

	if (rv != MSC_SEQUENCE_END && rv != MSC_SUCCESS)
	{
		return rv;
	}

	if (rv == MSC_SEQUENCE_END)
	{
		return MSC_INVALID_PARAMETER;
	}

	pKeyInfo->keyNum = keyInfo.keyNum;
	pKeyInfo->keyType = keyInfo.keyType;
	pKeyInfo->keyPartner = keyInfo.keyPartner;
	pKeyInfo->keySize = keyInfo.keySize;

	pKeyInfo->keyPolicy.cipherMode = keyInfo.keyPolicy.cipherMode;
	pKeyInfo->keyPolicy.cipherDirection =
		keyInfo.keyPolicy.cipherDirection;

	pKeyInfo->keyACL.readPermission = keyInfo.keyACL.readPermission;
	pKeyInfo->keyACL.writePermission = keyInfo.keyACL.writePermission;
	pKeyInfo->keyACL.usePermission = keyInfo.keyACL.usePermission;

	return MSC_SUCCESS;
}

MSC_RV MSCGetObjectAttributes(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCLPObjectInfo pObjectInfo)
{

	MSC_RV rv;
	MSCObjectInfo objInfo;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	rv = MSCListObjects(pConnection, MSC_SEQUENCE_RESET, &objInfo);

	if (rv != MSC_SEQUENCE_END && rv != MSC_SUCCESS)
	{
		return rv;
	}

	if (rv == MSC_SEQUENCE_END)
	{
		return MSC_OBJECT_NOT_FOUND;
	}

	if (strncmp(objectID, objInfo.objectID, MSC_MAXSIZE_OBJID) == 0)
	{
		pObjectInfo->objectSize = objInfo.objectSize;
		pObjectInfo->objectACL.readPermission =
			objInfo.objectACL.readPermission;
		pObjectInfo->objectACL.writePermission =
			objInfo.objectACL.writePermission;
		pObjectInfo->objectACL.deletePermission =
			objInfo.objectACL.deletePermission;
		strncpy(pObjectInfo->objectID, objectID, MSC_MAXSIZE_OBJID);
		return MSC_SUCCESS;
	}

	do
	{
		rv = MSCListObjects(pConnection, MSC_SEQUENCE_NEXT, &objInfo);
		if (strncmp(objectID, objInfo.objectID, MSC_MAXSIZE_OBJID) == 0)
			break;
	}
	while (rv == MSC_SUCCESS);

	if (rv != MSC_SEQUENCE_END && rv != MSC_SUCCESS)
	{
		return rv;
	}

	if (rv == MSC_SEQUENCE_END)
	{
		return MSC_OBJECT_NOT_FOUND;
	}

	pObjectInfo->objectSize = objInfo.objectSize;
	pObjectInfo->objectACL.readPermission =
		objInfo.objectACL.readPermission;
	pObjectInfo->objectACL.writePermission =
		objInfo.objectACL.writePermission;
	pObjectInfo->objectACL.deletePermission =
		objInfo.objectACL.deletePermission;
	strncpy(pObjectInfo->objectID, objectID, MSC_MAXSIZE_OBJID);

	return MSC_SUCCESS;
}

MSC_RV MSCReadAllocateObject(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 * pOutputData, MSCPULong32 dataSize)
{

	MSC_RV rv;
	MSCObjectInfo objInfo;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	if (pOutputData == 0)
	{
		return MSC_INVALID_PARAMETER;
	}

	rv = MSCGetObjectAttributes(pConnection, objectID, &objInfo);

	if (rv != MSC_SUCCESS)
	{
		*dataSize = 0;
		*pOutputData = 0;
		return rv;
	}

	*pOutputData =
		(MSCPUChar8) malloc(sizeof(MSCUChar8) * objInfo.objectSize);
	*dataSize = objInfo.objectSize;

	return MSCReadLargeObject(pConnection, objectID, *pOutputData,
		objInfo.objectSize);

}

MSC_RV MSCReadLargeObject(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 pOutputData, MSCULong32 dataSize)
{

	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int i;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	objectSize = dataSize;

	/*
	 * Read the key from the default object 
	 */
	for (i = 0; i < objectSize / MSC_SINGLE_READ_PACKET; i++)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SINGLE_READ_PACKET,
			&pOutputData[i * MSC_SINGLE_READ_PACKET],
			MSC_SINGLE_READ_PACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	if (objectSize % MSC_SINGLE_READ_PACKET)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SINGLE_READ_PACKET,
			&pOutputData[i * MSC_SINGLE_READ_PACKET],
			objectSize % MSC_SINGLE_READ_PACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	return rv;
}

MSC_RV MSCWriteLargeObject(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 pInputData, MSCULong32 dataSize)
{

	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int i;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	objectSize = dataSize;

	for (i = 0; i < objectSize / MSC_SINGLE_READ_PACKET; i++)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SINGLE_READ_PACKET,
			&pInputData[i * MSC_SINGLE_READ_PACKET],
			MSC_SINGLE_READ_PACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	if (objectSize % MSC_SINGLE_READ_PACKET)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SINGLE_READ_PACKET,
			&pInputData[i * MSC_SINGLE_READ_PACKET],
			objectSize % MSC_SINGLE_READ_PACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	return rv;
}

MSC_RV MSCWriteLargeObjectCB(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 pInputData,
	MSCULong32 dataSize,
	LPRWEventCallback rwCallback, MSCPVoid32 addParams)
{
	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int totalSteps, stepInterval;
	MSC_RV(*callBackFunction) (void *, int);
	int i;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	callBackFunction = (MSC_RV(*)(void *, int)) rwCallback;
	objectSize = dataSize;

	/*
	 * Figure out the number of steps total and present this in a percent
	 * step basis 
	 */

	totalSteps = objectSize / MSC_SIZEOF_KEYPACKET + 1;
	stepInterval = MSC_PERCENT_STEPSIZE / totalSteps;

	for (i = 0; i < objectSize / MSC_SIZEOF_KEYPACKET; i++)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET,
			&pInputData[i * MSC_SIZEOF_KEYPACKET], MSC_SIZEOF_KEYPACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}

		if ((*callBackFunction) (addParams,
				stepInterval * i) == MSC_CANCELLED)
		{
			return MSC_CANCELLED;
		}

	}

	if (objectSize % MSC_SIZEOF_KEYPACKET)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET,
			&pInputData[i * MSC_SIZEOF_KEYPACKET],
			objectSize % MSC_SIZEOF_KEYPACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	(*callBackFunction) (addParams, MSC_PERCENT_STEPSIZE);

	return rv;
}

MSC_RV MSCReadLargeObjectCB(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 pOutputData,
	MSCULong32 dataSize,
	LPRWEventCallback rwCallback, MSCPVoid32 addParams)
{

	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int totalSteps, stepInterval;
	MSC_RV(*callBackFunction) (void *, int);
	int i;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	callBackFunction = (MSC_RV(*)(void *, int)) rwCallback;
	objectSize = dataSize;

	/*
	 * Figure out the number of steps total and present this in a percent
	 * step basis 
	 */

	totalSteps = objectSize / MSC_SIZEOF_KEYPACKET + 1;
	stepInterval = MSC_PERCENT_STEPSIZE / totalSteps;

	for (i = 0; i < objectSize / MSC_SIZEOF_KEYPACKET; i++)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET,
			&pOutputData[i * MSC_SIZEOF_KEYPACKET], MSC_SIZEOF_KEYPACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}

		if ((*callBackFunction) (addParams,
				stepInterval * i) == MSC_CANCELLED)
		{
			return MSC_CANCELLED;
		}
	}

	if (objectSize % MSC_SIZEOF_KEYPACKET)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET,
			&pOutputData[i * MSC_SIZEOF_KEYPACKET],
			objectSize % MSC_SIZEOF_KEYPACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	(*callBackFunction) (addParams, MSC_PERCENT_STEPSIZE);

	return rv;
}

MSC_RV MSCReadAllocateObjectCB(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCPUChar8 * pOutputData,
	MSCPULong32 dataSize,
	LPRWEventCallback rwCallback, MSCPVoid32 addParams)
{

	MSC_RV rv;
	MSCObjectInfo objInfo;
	MSCULong32 objectSize;

	if (pConnection == NULL)
		return MSC_INVALID_PARAMETER;
	if (localHContext == 0)
		return MSC_INTERNAL_ERROR;

	if (pOutputData == 0)
	{
		return MSC_INVALID_PARAMETER;
	}

	rv = MSCGetObjectAttributes(pConnection, objectID, &objInfo);

	if (rv != MSC_SUCCESS)
	{
		*dataSize = 0;
		*pOutputData = 0;
		return rv;
	}

	objectSize = objInfo.objectSize;
	*dataSize = objectSize;
	*pOutputData = (MSCPUChar8) malloc(sizeof(MSCUChar8) * objectSize);

	return MSCReadLargeObjectCB(pConnection, objectID, *pOutputData,
		objectSize, rwCallback, addParams);

}

MSC_RV MSCWriteLargeObjectOffCB(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCULong32 offSet,
	MSCPUChar8 pInputData, MSCULong32 dataSize,
	LPRWEventCallback rwCallback, MSCPVoid32 addParams)
{
	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int totalSteps, stepInterval;
	MSC_RV(*callBackFunction) (void *, int);
	int i;

	callBackFunction = (MSC_RV(*)(void *, int)) rwCallback;
	objectSize = dataSize;

	/*
	 * Figure out the number of steps total and present this in a percent
	 * step basis 
	 */

	totalSteps = objectSize / MSC_SIZEOF_KEYPACKET + 1;
	stepInterval = MSC_PERCENT_STEPSIZE / totalSteps;

	for (i = 0; i < objectSize / MSC_SIZEOF_KEYPACKET; i++)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET + offSet,
			&pInputData[i * MSC_SIZEOF_KEYPACKET], MSC_SIZEOF_KEYPACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}

		if (rwCallback)
		{
			if ((*callBackFunction) (addParams,
					stepInterval * i) == MSC_CANCELLED)
			{
				return MSC_CANCELLED;
			}
		}
	}

	if (objectSize % MSC_SIZEOF_KEYPACKET)
	{
		rv = MSCWriteObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET + offSet,
			&pInputData[i * MSC_SIZEOF_KEYPACKET],
			objectSize % MSC_SIZEOF_KEYPACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	if (rwCallback)
	{
		(*callBackFunction) (addParams, MSC_PERCENT_STEPSIZE);
	}
	return rv;
}

MSC_RV MSCReadLargeObjectOffCB(MSCLPTokenConnection pConnection,
	MSCString objectID, MSCULong32 offSet,
	MSCPUChar8 pOutputData, MSCULong32 dataSize,
	LPRWEventCallback rwCallback, MSCPVoid32 addParams)
{

	MSC_RV rv = MSC_UNSPECIFIED_ERROR;
	MSCULong32 objectSize;
	int totalSteps, stepInterval;
	MSC_RV(*callBackFunction) (void *, int);
	int i;

	callBackFunction = (MSC_RV(*)(void *, int)) rwCallback;
	objectSize = dataSize;

	/*
	 * Figure out the number of steps total and present this in a percent
	 * step basis 
	 */

	totalSteps = objectSize / MSC_SIZEOF_KEYPACKET + 1;
	stepInterval = MSC_PERCENT_STEPSIZE / totalSteps;

	for (i = 0; i < objectSize / MSC_SIZEOF_KEYPACKET; i++)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET + offSet,
			&pOutputData[i * MSC_SIZEOF_KEYPACKET], MSC_SIZEOF_KEYPACKET);
		if (rv != MSC_SUCCESS)
		{
			return rv;
		}

		if (rwCallback)
		{
			if ((*callBackFunction) (addParams,
					stepInterval * i) == MSC_CANCELLED)
			{
				return MSC_CANCELLED;
			}
		}
	}

	if (objectSize % MSC_SIZEOF_KEYPACKET)
	{
		rv = MSCReadObject(pConnection, objectID,
			i * MSC_SIZEOF_KEYPACKET + offSet,
			&pOutputData[i * MSC_SIZEOF_KEYPACKET],
			objectSize % MSC_SIZEOF_KEYPACKET);

		if (rv != MSC_SUCCESS)
		{
			return rv;
		}
	}

	if (rwCallback)
	{
		(*callBackFunction) (addParams, MSC_PERCENT_STEPSIZE);
	}

	return rv;
}

MSC_RV pcscToMSC(MSCLong32 pcscCode)
{

	switch (pcscCode)
	{
	case SCARD_S_SUCCESS:
		return MSC_SUCCESS;
	case SCARD_E_INVALID_HANDLE:
		return MSC_INVALID_HANDLE;
	case SCARD_E_SHARING_VIOLATION:
		return MSC_SHARING_VIOLATION;
	case SCARD_W_REMOVED_CARD:
		return MSC_TOKEN_REMOVED;
	case SCARD_E_NO_SMARTCARD:
		return MSC_TOKEN_REMOVED;
	case SCARD_W_RESET_CARD:
		return MSC_TOKEN_RESET;
	case SCARD_W_INSERTED_CARD:
		return MSC_TOKEN_INSERTED;
	case SCARD_E_NO_SERVICE:
		return MSC_SERVICE_UNRESPONSIVE;
	case SCARD_E_UNKNOWN_CARD:
	case SCARD_W_UNSUPPORTED_CARD:
	case SCARD_E_CARD_UNSUPPORTED:
		return MSC_UNRECOGNIZED_TOKEN;
	case SCARD_E_INVALID_PARAMETER:
	case SCARD_E_INVALID_VALUE:
	case SCARD_E_UNKNOWN_READER:
	case SCARD_E_PROTO_MISMATCH:
	case SCARD_E_READER_UNAVAILABLE:
		return MSC_INVALID_PARAMETER;
	case SCARD_E_CANCELLED:
		return MSC_CANCELLED;
	case SCARD_E_TIMEOUT:
		return MSC_TIMEOUT_OCCURRED;

	default:
		return MSC_INTERNAL_ERROR;
	}
}

char *msc_error(MSC_RV errorCode)
{

	static char message[500];

	switch (errorCode)
	{
	case MSC_SUCCESS:
		strncpy(message, "Successful", sizeof(message));
		break;
	case MSC_NO_MEMORY_LEFT:
		strncpy(message, "No more memory", sizeof(message));
		break;
	case MSC_AUTH_FAILED:
		strncpy(message, "Authentication failed", sizeof(message));
		break;
	case MSC_OPERATION_NOT_ALLOWED:
		strncpy(message, "Operation not allowed", sizeof(message));
		break;
	case MSC_INCONSISTENT_STATUS:
		strncpy(message, "Inconsistent status", sizeof(message));
		break;
	case MSC_UNSUPPORTED_FEATURE:
		strncpy(message, "Feature unsupported", sizeof(message));
		break;
	case MSC_UNAUTHORIZED:
		strncpy(message, "Unauthorized usage", sizeof(message));
		break;
	case MSC_OBJECT_NOT_FOUND:
		strncpy(message, "Object not found", sizeof(message));
		break;
	case MSC_OBJECT_EXISTS:
		strncpy(message, "Object already exists", sizeof(message));
		break;
	case MSC_INCORRECT_ALG:
		strncpy(message, "Incorrect algorithm", sizeof(message));
		break;
	case MSC_SIGNATURE_INVALID:
		strncpy(message, "Invalid signature", sizeof(message));
		break;
	case MSC_IDENTITY_BLOCKED:
		strncpy(message, "Identity is blocked", sizeof(message));
		break;
	case MSC_UNSPECIFIED_ERROR:
		strncpy(message, "Unspecified error", sizeof(message));
		break;
	case MSC_TRANSPORT_ERROR:
		strncpy(message, "Transport error", sizeof(message));
		break;
	case MSC_INVALID_PARAMETER:
		strncpy(message, "Invalid parameter", sizeof(message));
		break;
	case MSC_SEQUENCE_END:
		strncpy(message, "End of sequence", sizeof(message));
		break;
	case MSC_INTERNAL_ERROR:
		strncpy(message, "Internal Error", sizeof(message));
		break;
	case MSC_CANCELLED:
		strncpy(message, "Operation Cancelled", sizeof(message));
		break;
	case MSC_INSUFFICIENT_BUFFER:
		strncpy(message, "Buffer is too small", sizeof(message));
		break;
	case MSC_UNRECOGNIZED_TOKEN:
		strncpy(message, "Token is unsupported", sizeof(message));
		break;
	case MSC_SERVICE_UNRESPONSIVE:
		strncpy(message, "Service is not running", sizeof(message));
		break;
	case MSC_TIMEOUT_OCCURRED:
		strncpy(message, "Timeout has occurred", sizeof(message));
		break;
	case MSC_TOKEN_REMOVED:
		strncpy(message, "Token was removed", sizeof(message));
		break;
	case MSC_TOKEN_RESET:
		strncpy(message, "Token was reset", sizeof(message));
		break;
	case MSC_TOKEN_INSERTED:
		strncpy(message, "Token was inserted", sizeof(message));
		break;
	case MSC_TOKEN_UNRESPONSIVE:
		strncpy(message, "Token is unresponsive", sizeof(message));
		break;
	case MSC_INVALID_HANDLE:
		strncpy(message, "Handle is invalid", sizeof(message));
		break;
	case MSC_SHARING_VIOLATION:
		strncpy(message, "Sharing violation", sizeof(message));
		break;

	default:
		sprintf(message, "Unknown SW: %04ld", errorCode);
		break;
	}

	return message;
}

MSC_RV MSCReEstablishConnection(MSCLPTokenConnection pConnection)
{

	MSC_RV rv;
	MSCPVoid32 vInitFunction, vFinFunction, vIdFunction;
	MSCULong32 dwActiveProtocol;
	MSCLong32(*libPL_MSCInitializePlugin) (MSCLPTokenConnection);
	MSCLong32(*libPL_MSCFinalizePlugin) (MSCLPTokenConnection);
        MSCLong32 (*libPL_MSCIdentifyToken)(MSCLPTokenConnection);

	vInitFunction = 0;
	vFinFunction  = 0;
	vIdFunction   = 0;

	/*
	 * Select the AID or initialization routine for the card 
	 */
	vInitFunction = pConnection->libPointers.pvfInitializePlugin;
	vFinFunction  = pConnection->libPointers.pvfFinalizePlugin;
	vIdFunction   = pConnection->libPointers.pvfIdentifyToken;

	if (vInitFunction == 0)
	{
		DebugLogC("Error: Card service failure: %s\n",
			"InitializePlugin function missing");
		return MSC_INTERNAL_ERROR;
	}

	if (vFinFunction == 0)
	{
		DebugLogC("Error: Card service failure: %s\n",
			"FinalizePlugin function missing");
		return MSC_INTERNAL_ERROR;
	}

	if ( vIdFunction == 0 ) 
	{
	        DebugLogC("Error: Card service failure: %s\n", 
			  "IdentifyToken function missing");
		return MSC_INTERNAL_ERROR;
	}

	libPL_MSCInitializePlugin = (MSCLong32(*)(MSCLPTokenConnection))
		vInitFunction;

	libPL_MSCFinalizePlugin = (MSCLong32(*)(MSCLPTokenConnection))
		vFinFunction;

	libPL_MSCIdentifyToken = (MSCLong32 (*)(MSCLPTokenConnection))
	        vIdFunction;

	rv = SCardReconnect(pConnection->hCard, pConnection->shareMode,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		SCARD_LEAVE_CARD, &dwActiveProtocol);

	if (rv != SCARD_S_SUCCESS)
		return pcscToMSC(rv);

	/*
	 * Stop the plugin and start it up again 
	 */
	rv = (*libPL_MSCFinalizePlugin) (pConnection);

	/*
	 * Use the default AID given by the Info.plist 
	 */
	rv = (*libPL_MSCInitializePlugin) (pConnection);

	/* 
	 * Use the default AID given by the Info.plist 
	 */
	rv = (*libPL_MSCIdentifyToken)(pConnection);

	if (rv != MSC_SUCCESS)
		return rv;

	return MSC_SUCCESS;
}

MSCUChar8 MSCIsTokenReset(MSCLPTokenConnection pConnection)
{
	if (pConnection->tokenInfo.tokenType & MSC_TOKEN_TYPE_RESET)
	{
		return 1;
	} else
	{
		return 0;
	}
}

MSCUChar8 MSCClearReset(MSCLPTokenConnection pConnection)
{
	pConnection->tokenInfo.tokenType &= ~MSC_TOKEN_TYPE_RESET;
	return 1;
}

MSCUChar8 MSCIsTokenMoved(MSCLPTokenConnection pConnection)
{
	if (pConnection->tokenInfo.tokenType & MSC_TOKEN_TYPE_REMOVED)
	{
		return 1;
	} else
	{
		return 0;
	}
}

MSCUChar8 MSCIsTokenChanged(MSCLPTokenConnection pConnection)
{
	if ((pConnection->tokenInfo.tokenType & MSC_TOKEN_TYPE_REMOVED) ||
		(pConnection->tokenInfo.tokenType & MSC_TOKEN_TYPE_RESET))
	{
		return 1;
	} else
	{
		return 0;
	}
}

MSCUChar8 MSCIsTokenKnown(MSCLPTokenConnection pConnection)
{
	if (pConnection->tokenInfo.tokenType & MSC_TOKEN_TYPE_KNOWN)
	{
		return 1;
	} else
	{
		return 0;
	}
}
