/*
 * This handles smartcard reader communications.
 * This is the heart of the M$ smartcard API.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

#include "config.h"
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "wintypes.h"
#include "pcsclite.h"
#include "winscard.h"
#include "readerfactory.h"
#include "prothandler.h"
#include "ifdhandler.h"
#include "ifdwrapper.h"
#include "atrhandler.h"
#include "debuglog.h"
#include "configfile.h"
#include "sys_generic.h"

/*
 * Some defines for context stack
 */
#define SCARD_LAST_CONTEXT       1
#define SCARD_NO_CONTEXT         0
#define SCARD_EXCLUSIVE_CONTEXT -1
#define SCARD_NO_LOCK            0

SCARD_IO_REQUEST g_rgSCardT0Pci = { SCARD_PROTOCOL_T0, 8 };
SCARD_IO_REQUEST g_rgSCardT1Pci = { SCARD_PROTOCOL_T1, 8 };
SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, 8 };

LONG SCardEstablishContext(DWORD dwScope, LPCVOID pvReserved1,
	LPCVOID pvReserved2, LPSCARDCONTEXT phContext)
{
	LONG rv;

	/*
	 * Zero out everything
	 */
	rv = 0;

	/*
	 * Check for NULL pointer
	 */
	if (phContext == 0)
		return SCARD_E_INVALID_PARAMETER;

	if (dwScope != SCARD_SCOPE_USER && dwScope != SCARD_SCOPE_TERMINAL &&
		dwScope != SCARD_SCOPE_SYSTEM && dwScope != SCARD_SCOPE_GLOBAL)
	{

		*phContext = 0;
		return SCARD_E_INVALID_VALUE;
	}

	/*
	 * Unique identifier for this server so that it can uniquely be
	 * identified by clients and distinguished from others
	 */

	*phContext = (PCSCLITE_SVC_IDENTITY + SYS_Random(SYS_GetSeed(),
			1.0, 65535.0));

	DebugLogB("Establishing Context: %d", *phContext);

	return SCARD_S_SUCCESS;
}

LONG SCardReleaseContext(SCARDCONTEXT hContext)
{
	/*
	 * Nothing to do here RPC layer will handle this
	 */

	DebugLogB("Releasing Context: %d", hContext);

	return SCARD_S_SUCCESS;
}

LONG SCardSetTimeout(SCARDCONTEXT hContext, DWORD dwTimeout)
{
	/*
	 * This is only used at the client side of an RPC call but just in
	 * case someone calls it here
	 */

	return SCARD_E_UNSUPPORTED_FEATURE;
}

LONG SCardConnect(SCARDCONTEXT hContext, LPCTSTR szReader,
	DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard,
	LPDWORD pdwActiveProtocol)
{
	LONG rv;
	PREADER_CONTEXT rContext;
	UCHAR pucAtr[MAX_ATR_SIZE], ucAvailable;
	DWORD dwAtrLength, dwState, dwStatus;
	DWORD dwReaderLen, dwProtocol;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;
	ucAvailable = 0;
	dwAtrLength = 0;
	dwState = 0;
	dwStatus = 0;
	dwReaderLen = 0;
	dwProtocol = 0;
	memset(pucAtr, 0x00, MAX_ATR_SIZE);

	/*
	 * Check for NULL parameters
	 */
	if (szReader == 0 || phCard == 0 || pdwActiveProtocol == 0)
		return SCARD_E_INVALID_PARAMETER;
	else
		*phCard = 0;

	if (!(dwPreferredProtocols & SCARD_PROTOCOL_T0) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_T1) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_RAW) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_ANY))
		return SCARD_E_PROTO_MISMATCH;

	if (dwShareMode != SCARD_SHARE_EXCLUSIVE &&
			dwShareMode != SCARD_SHARE_SHARED &&
			dwShareMode != SCARD_SHARE_DIRECT)
		return SCARD_E_INVALID_VALUE;

	DebugLogB("Attempting Connect to %s", szReader);

	rv = RFReaderInfo((LPTSTR) szReader, &rContext);

	if (rv != SCARD_S_SUCCESS)
	{
		DebugLogB("Reader %s Not Found", szReader);
		return rv;
	}

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*******************************************
	 *
	 * This section checks for simple errors
	 *
	 *******************************************/

	/*
	 * Connect if not exclusive mode
	 */
	if (rContext->dwContexts == SCARD_EXCLUSIVE_CONTEXT)
	{
		DebugLogA("Error Reader Exclusive");
		return SCARD_E_SHARING_VIOLATION;
	}

	/*******************************************
	 *
	 * This section tries to determine the
	 * presence of a card or not
	 *
	 *******************************************/
	dwStatus = rContext->dwStatus;

	if (dwShareMode != SCARD_SHARE_DIRECT)
	{
		if (!(dwStatus & SCARD_PRESENT))
		{
			DebugLogA("Card Not Inserted");
			return SCARD_E_NO_SMARTCARD;
		}
	}

	/*******************************************
	 *
	 * This section tries to decode the ATR
	 * and set up which protocol to use
	 *
	 *******************************************/
	if (dwPreferredProtocols & SCARD_PROTOCOL_RAW)
		rContext->dwProtocol = -1;
	else
	{
		if (dwShareMode != SCARD_SHARE_DIRECT)
		{
			memcpy(pucAtr, rContext->ucAtr, rContext->dwAtrLen);
			dwAtrLength = rContext->dwAtrLen;
			if (rContext->dwAtrLen > 0)
				DebugXxd("Card ATR: ", rContext->ucAtr, rContext->dwAtrLen);

			rContext->dwProtocol =
				PHGetDefaultProtocol(pucAtr, dwAtrLength);
			ucAvailable = PHGetAvailableProtocols(pucAtr, dwAtrLength);

			/*
			 * If it is set to any let it do any of the protocols
			 */
			if (dwPreferredProtocols & SCARD_PROTOCOL_ANY)
			{
				rContext->dwProtocol = PHSetProtocol(rContext, ucAvailable,
					ucAvailable);
			}
			else
			{
				rContext->dwProtocol =
					PHSetProtocol(rContext, dwPreferredProtocols,
					ucAvailable);
				if (rContext->dwProtocol == -1)
				{
					return SCARD_E_PROTO_MISMATCH;
				}
			}
		}
	}

	*pdwActiveProtocol = rContext->dwProtocol;

	DebugLogB("Active Protocol: %d", *pdwActiveProtocol);

	/*
	 * Prepare the SCARDHANDLE identity
	 */
	*phCard = RFCreateReaderHandle(rContext);

	DebugLogB("hCard Identity: %x", *phCard);

	/*******************************************
	 *
	 * This section tries to set up the
	 * exclusivity modes. -1 is exclusive
	 *
	 *******************************************/

	if (dwShareMode == SCARD_SHARE_EXCLUSIVE)
	{
		if (rContext->dwContexts == SCARD_NO_CONTEXT)
		{
			rContext->dwContexts = SCARD_EXCLUSIVE_CONTEXT;
			RFLockSharing(*phCard);
		}
		else
		{
			RFDestroyReaderHandle(*phCard);
			*phCard = 0;
			return SCARD_E_SHARING_VIOLATION;
		}
	}
	else
	{
		/*
		 * Add a connection to the context stack
		 */
		rContext->dwContexts += 1;
	}

	/*
	 * Add this handle to the handle list
	 */
	rv = RFAddReaderHandle(rContext, *phCard);

	if (rv != SCARD_S_SUCCESS)
	{
		/*
		 * Clean up - there is no more room
		 */
		RFDestroyReaderHandle(*phCard);
		if (rContext->dwContexts == SCARD_EXCLUSIVE_CONTEXT)
			rContext->dwContexts = SCARD_NO_CONTEXT;
		else
			if (rContext->dwContexts > SCARD_NO_CONTEXT)
				rContext->dwContexts -= 1;

		*phCard = 0;
		return SCARD_F_INTERNAL_ERROR;
	}

	/*
	 * Allow the status thread to convey information
	 */
	SYS_USleep(PCSCLITE_STATUS_POLL_RATE + 10);

	return SCARD_S_SUCCESS;
}

LONG SCardReconnect(SCARDHANDLE hCard, DWORD dwShareMode,
	DWORD dwPreferredProtocols, DWORD dwInitialization,
	LPDWORD pdwActiveProtocol)
{
	LONG rv;
	PREADER_CONTEXT rContext;
	UCHAR pucAtr[MAX_ATR_SIZE], ucAvailable;
	DWORD dwAtrLength;

	DebugLogA("Attempting reconnect to token.");

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;
	ucAvailable = 0;
	dwAtrLength = 0;
	memset(pucAtr, 0x00, MAX_ATR_SIZE);

	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	if (dwInitialization != SCARD_LEAVE_CARD &&
			dwInitialization != SCARD_RESET_CARD &&
			dwInitialization != SCARD_UNPOWER_CARD)
		return SCARD_E_INVALID_VALUE;

	if (dwShareMode != SCARD_SHARE_SHARED &&
			dwShareMode != SCARD_SHARE_EXCLUSIVE &&
			dwShareMode != SCARD_SHARE_DIRECT)
		return SCARD_E_INVALID_VALUE;

	if (!(dwPreferredProtocols & SCARD_PROTOCOL_T0) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_T1) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_RAW) &&
			!(dwPreferredProtocols & SCARD_PROTOCOL_ANY))
		return SCARD_E_PROTO_MISMATCH;

	if (pdwActiveProtocol == 0)
		return SCARD_E_INVALID_PARAMETER;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure no one has a lock on this reader
	 */
	if ((rv = RFCheckSharing(hCard)) != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Handle the dwInitialization
	 */
	if ((dwInitialization != SCARD_LEAVE_CARD)
		&& (dwInitialization != SCARD_UNPOWER_CARD)
		&& (dwInitialization != SCARD_RESET_CARD))
		return SCARD_E_INVALID_VALUE;

	/*
	 * RFUnblockReader( rContext ); FIX - this doesn't work
	 */

	if (dwInitialization == SCARD_RESET_CARD ||
		dwInitialization == SCARD_UNPOWER_CARD)
	{
		/*
		 * Currently pcsc-lite keeps the card powered constantly
		 */
		if (SCARD_RESET_CARD == dwInitialization)
			rv = IFDPowerICC(rContext, IFD_RESET, rContext->ucAtr,
				&rContext->dwAtrLen);
		else
		{
			rv = IFDPowerICC(rContext, IFD_POWER_DOWN, rContext->ucAtr,
				&rContext->dwAtrLen);
			rv = IFDPowerICC(rContext, IFD_POWER_UP, rContext->ucAtr,
				&rContext->dwAtrLen);
		}

		/*
		 * Notify the card has been reset
		 * Not doing this could result in deadlock
		 */
		rv = RFCheckReaderEventState(rContext, hCard);
		switch(rv)
		{
			/* avoid deadlock */
			case SCARD_W_RESET_CARD:
				break;

			case SCARD_W_REMOVED_CARD:
				DebugLogA("card removed");
				return SCARD_W_REMOVED_CARD;

			/* invalid EventStatus */
			case SCARD_E_INVALID_VALUE:
				DebugLogA("invalid EventStatus");
				return SCARD_F_INTERNAL_ERROR;

			/* invalid hCard, but hCard was widely used some lines above :( */
			case SCARD_E_INVALID_HANDLE:
				DebugLogA("invalid handle");
				return SCARD_F_INTERNAL_ERROR;

			case SCARD_S_SUCCESS:
				/*
				 * Notify the card has been reset
				 */
				RFSetReaderEventState(rContext, SCARD_RESET);

				/*
				 * Set up the status bit masks on dwStatus
				 */
				if (rv == SCARD_S_SUCCESS)
				{
					rContext->dwStatus |= SCARD_PRESENT;
					rContext->dwStatus &= ~SCARD_ABSENT;
					rContext->dwStatus |= SCARD_POWERED;
					rContext->dwStatus |= SCARD_NEGOTIABLE;
					rContext->dwStatus &= ~SCARD_SPECIFIC;
					rContext->dwStatus &= ~SCARD_SWALLOWED;
					rContext->dwStatus &= ~SCARD_UNKNOWN;
				}
				else
				{
					rContext->dwStatus |= SCARD_PRESENT;
					rContext->dwStatus &= ~SCARD_ABSENT;
					rContext->dwStatus |= SCARD_SWALLOWED;
					rContext->dwStatus &= ~SCARD_POWERED;
					rContext->dwStatus &= ~SCARD_NEGOTIABLE;
					rContext->dwStatus &= ~SCARD_SPECIFIC;
					rContext->dwStatus &= ~SCARD_UNKNOWN;
					rContext->dwProtocol = 0;
					rContext->dwAtrLen = 0;
				}

				if (rContext->dwAtrLen > 0)
				{
					DebugLogA("Reset complete.");
					DebugXxd("Card ATR: ", rContext->ucAtr, rContext->dwAtrLen);
				}
				else
					DebugLogA("Error resetting card.");
				break;

			default:
				DebugLogB("invalid retcode from RFCheckReaderEventState (%X)", rv);
				return SCARD_F_INTERNAL_ERROR;
				break;
		}

	}
	else
		if (dwInitialization == SCARD_LEAVE_CARD)
		{
			/*
			 * Do nothing
			 */
		}

	/*
	 * Handle the dwActive/Preferred Protocols
	 */
	if (dwPreferredProtocols & SCARD_PROTOCOL_RAW)
	{
		rContext->dwProtocol = -1;
	}
	else
	{
		if (dwShareMode != SCARD_SHARE_DIRECT)
		{
			memcpy(pucAtr, rContext->ucAtr, rContext->dwAtrLen);
			dwAtrLength = rContext->dwAtrLen;

			rContext->dwProtocol =
				PHGetDefaultProtocol(pucAtr, dwAtrLength);
			ucAvailable = PHGetAvailableProtocols(pucAtr, dwAtrLength);

			/*
			 * If it is set to any let it do any of the protocols
			 */
			if (dwPreferredProtocols & SCARD_PROTOCOL_ANY)
			{
				rContext->dwProtocol =
					PHSetProtocol(rContext,
					SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, ucAvailable);
			}
			else
			{
				rContext->dwProtocol =
					PHSetProtocol(rContext, dwPreferredProtocols,
					ucAvailable);

				if (rContext->dwProtocol == -1)
				{
					return SCARD_E_PROTO_MISMATCH;
				}
			}
		}
	}

	*pdwActiveProtocol = rContext->dwProtocol;

	if (dwShareMode == SCARD_SHARE_EXCLUSIVE)
	{
		if (rContext->dwContexts == SCARD_EXCLUSIVE_CONTEXT)
		{
			/*
			 * Do nothing - we are already exclusive
			 */
		} else
		{
			if (rContext->dwContexts == SCARD_LAST_CONTEXT)
			{
				rContext->dwContexts = SCARD_EXCLUSIVE_CONTEXT;
				RFLockSharing(hCard);
			} else
			{
				return SCARD_E_SHARING_VIOLATION;
			}
		}
	} else if (dwShareMode == SCARD_SHARE_SHARED)
	{
		if (rContext->dwContexts != SCARD_EXCLUSIVE_CONTEXT)
		{
			/*
			 * Do nothing - in sharing mode already
			 */
		} else
		{
			/*
			 * We are in exclusive mode but want to share now
			 */
			RFUnlockSharing(hCard);
			rContext->dwContexts = SCARD_LAST_CONTEXT;
		}
	} else if (dwShareMode == SCARD_SHARE_DIRECT)
	{
		if (rContext->dwContexts != SCARD_EXCLUSIVE_CONTEXT)
		{
			/*
			 * Do nothing - in sharing mode already
			 */
		} else
		{
			/*
			 * We are in exclusive mode but want to share now
			 */
			RFUnlockSharing(hCard);
			rContext->dwContexts = SCARD_LAST_CONTEXT;
		}
	} else
		return SCARD_E_INVALID_VALUE;

	/*
	 * Clear a previous event to the application
	 */
	RFClearReaderEventState(rContext, hCard);

	/*
	 * Allow the status thread to convey information
	 */
	SYS_USleep(PCSCLITE_STATUS_POLL_RATE + 10);

	return SCARD_S_SUCCESS;
}

LONG SCardDisconnect(SCARDHANDLE hCard, DWORD dwDisposition)
{
	LONG rv;
	UCHAR controlBuffer[5];
	UCHAR receiveBuffer[MAX_BUFFER_SIZE];
	PREADER_CONTEXT rContext;
	DWORD dwAtrLen, receiveLength;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;
	dwAtrLen = 0;
	receiveLength = 0;

	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	if ((dwDisposition != SCARD_LEAVE_CARD)
		&& (dwDisposition != SCARD_UNPOWER_CARD)
		&& (dwDisposition != SCARD_RESET_CARD)
		&& (dwDisposition != SCARD_EJECT_CARD))
		return SCARD_E_INVALID_VALUE;

	/*
	 * Unlock any blocks on this context
	 */
	RFUnlockSharing(hCard);

	DebugLogB("Active Contexts: %d", rContext->dwContexts);

	if (dwDisposition == SCARD_RESET_CARD ||
		dwDisposition == SCARD_UNPOWER_CARD)
	{

		/*
		 * Currently pcsc-lite keeps the card powered constantly
		 */
		if (SCARD_RESET_CARD == dwDisposition)
			rv = IFDPowerICC(rContext, IFD_RESET, rContext->ucAtr,
				&rContext->dwAtrLen);
		else
		{
			rv = IFDPowerICC(rContext, IFD_POWER_DOWN, rContext->ucAtr,
				&rContext->dwAtrLen);
			rv = IFDPowerICC(rContext, IFD_POWER_UP, rContext->ucAtr,
				&rContext->dwAtrLen);
		}

		/*
		 * Notify the card has been reset
		 */
		RFSetReaderEventState(rContext, SCARD_RESET);

		/*
		 * Set up the status bit masks on dwStatus
		 */
		if (rv == SCARD_S_SUCCESS)
		{
			rContext->dwStatus |= SCARD_PRESENT;
			rContext->dwStatus &= ~SCARD_ABSENT;
			rContext->dwStatus |= SCARD_POWERED;
			rContext->dwStatus |= SCARD_NEGOTIABLE;
			rContext->dwStatus &= ~SCARD_SPECIFIC;
			rContext->dwStatus &= ~SCARD_SWALLOWED;
			rContext->dwStatus &= ~SCARD_UNKNOWN;
		}
		else
		{
			if (rContext->dwStatus & SCARD_ABSENT)
				rContext->dwStatus &= ~SCARD_PRESENT;
			else
				rContext->dwStatus |= SCARD_PRESENT;
			/* SCARD_ABSENT flag is already set */
			rContext->dwStatus |= SCARD_SWALLOWED;
			rContext->dwStatus &= ~SCARD_POWERED;
			rContext->dwStatus &= ~SCARD_NEGOTIABLE;
			rContext->dwStatus &= ~SCARD_SPECIFIC;
			rContext->dwStatus &= ~SCARD_UNKNOWN;
			rContext->dwProtocol = 0;
			rContext->dwAtrLen = 0;
		}

		if (rContext->dwAtrLen > 0)
			DebugLogA("Reset complete.");
		else
			DebugLogA("Error resetting card.");

	}
	else if (dwDisposition == SCARD_EJECT_CARD)
	{
		/*
		 * Set up the CTBCS command for Eject ICC
		 */
		controlBuffer[0] = 0x20;
		controlBuffer[1] = 0x15;
		controlBuffer[2] = (rContext->dwSlot & 0x0000FFFF) + 1;
		controlBuffer[3] = 0x00;
		controlBuffer[4] = 0x00;
		receiveLength = 2;
		rv = IFDControl_v2(rContext, controlBuffer, 5, receiveBuffer,
			&receiveLength);

		if (rv == SCARD_S_SUCCESS)
		{
			if (receiveLength == 2 && receiveBuffer[0] == 0x90)
			{
				DebugLogA("Card ejected successfully.");
				/*
				 * Successful
				 */
			}
			else
				DebugLogA("Error ejecting card.");
		}
		else
			DebugLogA("Error ejecting card.");

	}
	else if (dwDisposition == SCARD_LEAVE_CARD)
	{
		/*
		 * Do nothing
		 */
	}

	/*
	 * Remove and destroy this handle
	 */
	RFRemoveReaderHandle(rContext, hCard);
	RFDestroyReaderHandle(hCard);

	/*
	 * For exclusive connection reset it to no connections
	 */
	if (rContext->dwContexts == SCARD_EXCLUSIVE_CONTEXT)
	{
		rContext->dwContexts = SCARD_NO_CONTEXT;
		return SCARD_S_SUCCESS;
	}

	/*
	 * Remove a connection from the context stack
	 */
	rContext->dwContexts -= 1;

	if (rContext->dwContexts < 0)
		rContext->dwContexts = 0;

	/*
	 * Allow the status thread to convey information
	 */
	SYS_USleep(PCSCLITE_STATUS_POLL_RATE + 10);

	return SCARD_S_SUCCESS;
}

LONG SCardBeginTransaction(SCARDHANDLE hCard)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rv = 0;

	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	rv = RFReaderInfoById(hCard, &rContext);

	/*
	 * Cannot find the hCard in this context
	 */
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFLockSharing(hCard);

	DebugLogB("Status: %d.", rv);

	return rv;
}

LONG SCardEndTransaction(SCARDHANDLE hCard, DWORD dwDisposition)
{
	LONG rv;
	PREADER_CONTEXT rContext;
	UCHAR controlBuffer[5];
	UCHAR receiveBuffer[MAX_BUFFER_SIZE];
	DWORD receiveLength;

	/*
	 * Zero out everything
	 */
	rContext = 0;
	rv = 0;
	receiveLength = 0;

	/*
	 * Ignoring dwDisposition for now
	 */
	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	if ((dwDisposition != SCARD_LEAVE_CARD)
		&& (dwDisposition != SCARD_UNPOWER_CARD)
		&& (dwDisposition != SCARD_RESET_CARD)
		&& (dwDisposition != SCARD_EJECT_CARD))
	return SCARD_E_INVALID_VALUE;

	rv = RFReaderInfoById(hCard, &rContext);

	/*
	 * Cannot find the hCard in this context
	 */
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	if (dwDisposition == SCARD_RESET_CARD ||
		dwDisposition == SCARD_UNPOWER_CARD)
	{
		/*
		 * Currently pcsc-lite keeps the card always powered
		 */
		if (SCARD_RESET_CARD == dwDisposition)
			rv = IFDPowerICC(rContext, IFD_RESET, rContext->ucAtr,
				&rContext->dwAtrLen);
		else
		{
			rv = IFDPowerICC(rContext, IFD_POWER_DOWN, rContext->ucAtr,
				&rContext->dwAtrLen);
			rv = IFDPowerICC(rContext, IFD_POWER_UP, rContext->ucAtr,
				&rContext->dwAtrLen);
		}

		/*
		 * Notify the card has been reset
		 */
		RFSetReaderEventState(rContext, SCARD_RESET);

		/*
		 * Set up the status bit masks on dwStatus
		 */
		if (rv == SCARD_S_SUCCESS)
		{
			rContext->dwStatus |= SCARD_PRESENT;
			rContext->dwStatus &= ~SCARD_ABSENT;
			rContext->dwStatus |= SCARD_POWERED;
			rContext->dwStatus |= SCARD_NEGOTIABLE;
			rContext->dwStatus &= ~SCARD_SPECIFIC;
			rContext->dwStatus &= ~SCARD_SWALLOWED;
			rContext->dwStatus &= ~SCARD_UNKNOWN;
		}
		else
		{
			if (rContext->dwStatus & SCARD_ABSENT)
				rContext->dwStatus &= ~SCARD_PRESENT;
			else
				rContext->dwStatus |= SCARD_PRESENT;
			/* SCARD_ABSENT flag is already set */
			rContext->dwStatus |= SCARD_SWALLOWED;
			rContext->dwStatus &= ~SCARD_POWERED;
			rContext->dwStatus &= ~SCARD_NEGOTIABLE;
			rContext->dwStatus &= ~SCARD_SPECIFIC;
			rContext->dwStatus &= ~SCARD_UNKNOWN;
			rContext->dwProtocol = 0;
			rContext->dwAtrLen = 0;
		}

		if (rContext->dwAtrLen > 0)
			DebugLogA("Reset complete.");
		else
			DebugLogA("Error resetting card.");

	}
	else if (dwDisposition == SCARD_EJECT_CARD)
	{
		/*
		 * Set up the CTBCS command for Eject ICC
		 */
		controlBuffer[0] = 0x20;
		controlBuffer[1] = 0x15;
		controlBuffer[2] = (rContext->dwSlot & 0x0000FFFF) + 1;
		controlBuffer[3] = 0x00;
		controlBuffer[4] = 0x00;
		receiveLength = 2;
		rv = IFDControl_v2(rContext, controlBuffer, 5, receiveBuffer,
			&receiveLength);

		if (rv == SCARD_S_SUCCESS)
		{
			if (receiveLength == 2 && receiveBuffer[0] == 0x90)
			{
				DebugLogA("Card ejected successfully.");
				/*
				 * Successful
				 */
			}
			else
				DebugLogA("Error ejecting card.");
		}
		else
			DebugLogA("Error ejecting card.");

	}
	else if (dwDisposition == SCARD_LEAVE_CARD)
	{
		/*
		 * Do nothing
		 */
	}

	/*
	 * Unlock any blocks on this context
	 */
	RFUnlockSharing(hCard);

	DebugLogB("Status: %d.", rv);

	return rv;
}

LONG SCardCancelTransaction(SCARDHANDLE hCard)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rContext = 0;
	rv = 0;

	/*
	 * Ignoring dwDisposition for now
	 */
	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	rv = RFReaderInfoById(hCard, &rContext);

	/*
	 * Cannot find the hCard in this context
	 */
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFUnlockSharing(hCard);

	DebugLogB("Status: %d.", rv);

	return rv;
}

LONG SCardStatus(SCARDHANDLE hCard, LPTSTR mszReaderNames,
	LPDWORD pcchReaderLen, LPDWORD pdwState,
	LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rContext = 0;
	rv = 0;

	rv = RFReaderInfoById(hCard, &rContext);

	/*
	 * Cannot find the hCard in this context
	 */
	if (rv != SCARD_S_SUCCESS)
		return rv;

	if (strlen(rContext->lpcReader) > MAX_BUFFER_SIZE
			|| rContext->dwAtrLen > MAX_ATR_SIZE || rContext->dwAtrLen < 0)
		return SCARD_F_INTERNAL_ERROR;

	/*
	 * This is a client side function however the server maintains the
	 * list of events between applications so it must be passed through to
	 * obtain this event if it has occurred
	 */

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	if (mszReaderNames)
	{  /* want reader name */
		if (pcchReaderLen)
		{ /* & present reader name length */
			if (*pcchReaderLen >= strlen(rContext->lpcReader))
			{ /* & enough room */
				*pcchReaderLen = strlen(rContext->lpcReader);
				strncpy(mszReaderNames, rContext->lpcReader, MAX_READERNAME);
			}
			else
			{        /* may report only reader name len */
				*pcchReaderLen = strlen(rContext->lpcReader);
				rv = SCARD_E_INSUFFICIENT_BUFFER;
			}
		}
		else
		{            /* present buf & no buflen */
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	else
	{
		if (pcchReaderLen)
		{ /* want reader len only */
			*pcchReaderLen = strlen(rContext->lpcReader);
		}
		else
		{
		/* nothing todo */
		}
	}

	if (pdwState)
		*pdwState = rContext->dwStatus;

	if (pdwProtocol)
		*pdwProtocol = rContext->dwProtocol;

	if (pbAtr)
	{  /* want ATR */
		if (pcbAtrLen)
		{ /* & present ATR length */
			if (*pcbAtrLen >= rContext->dwAtrLen)
			{ /* & enough room */
				*pcbAtrLen = rContext->dwAtrLen;
				memcpy(pbAtr, rContext->ucAtr, rContext->dwAtrLen);
			}
			else
			{ /* may report only ATR len */
				*pcbAtrLen = rContext->dwAtrLen;
				rv = SCARD_E_INSUFFICIENT_BUFFER;
			}
		}
		else
		{ /* present buf & no buflen */
			return SCARD_E_INVALID_PARAMETER;
		}
	}
	else
	{
		if (pcbAtrLen)
		{ /* want ATR len only */
			*pcbAtrLen = rContext->dwAtrLen;
		}
		else
		{
			/* nothing todo */
		}
	}

	return rv;
}

LONG SCardGetStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout,
	LPSCARD_READERSTATE_A rgReaderStates, DWORD cReaders)
{
	/*
	 * Client side function
	 */
	return SCARD_S_SUCCESS;
}

LONG SCardControl(SCARDHANDLE hCard, DWORD dwControlCode,
	LPCVOID pbSendBuffer, DWORD cbSendLength,
	LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;

	/* 0 bytes returned by default */
	*lpBytesReturned = 0;

	if (0 == hCard)
		return SCARD_E_INVALID_HANDLE;

	if (NULL == pbSendBuffer || 0 == cbSendLength)
		return SCARD_E_INVALID_PARAMETER;

	/*
	 * Make sure no one has a lock on this reader
	 */
	if ((rv = RFCheckSharing(hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	if (cbSendLength > MAX_BUFFER_SIZE)
		return SCARD_E_INSUFFICIENT_BUFFER;

	return IFDControl(rContext, dwControlCode, pbSendBuffer, cbSendLength,
			pbRecvBuffer, cbRecvLength, lpBytesReturned);
}

LONG SCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;

	if (0 == hCard)
		return SCARD_E_INVALID_HANDLE;

	/*
	 * Make sure no one has a lock on this reader
	 */
	if ((rv = RFCheckSharing(hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = IFDGetCapabilities(rContext, dwAttrId, pcbAttrLen, pbAttr);
	if (rv == IFD_SUCCESS)
		return SCARD_S_SUCCESS;
	else
		return SCARD_E_NOT_TRANSACTED;
}

LONG SCardSetAttrib(SCARDHANDLE hCard, DWORD dwAttrId,
	LPCBYTE pbAttr, DWORD cbAttrLen)
{
	LONG rv;
	PREADER_CONTEXT rContext;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;

	if (0 == hCard)
		return SCARD_E_INVALID_HANDLE;

	/*
	 * Make sure no one has a lock on this reader
	 */
	if ((rv = RFCheckSharing(hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = IFDSetCapabilities(rContext, dwAttrId, cbAttrLen, (PUCHAR)pbAttr);
	if (rv == IFD_SUCCESS)
		return SCARD_S_SUCCESS;
	else
		return SCARD_E_NOT_TRANSACTED;
}

LONG SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
	LPCBYTE pbSendBuffer, DWORD cbSendLength,
	LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer,
	LPDWORD pcbRecvLength)
{
	LONG rv;
	PREADER_CONTEXT rContext;
	SCARD_IO_HEADER sSendPci, sRecvPci;
	DWORD dwRxLength, tempRxLength;

	/*
	 * Zero out everything
	 */
	rv = 0;
	rContext = 0;
	dwRxLength = 0;
	tempRxLength = 0;

	if (pcbRecvLength == 0)
		return SCARD_E_INVALID_PARAMETER;

	dwRxLength = *pcbRecvLength;
	*pcbRecvLength = 0;

	if (hCard == 0)
		return SCARD_E_INVALID_HANDLE;

	if (pbSendBuffer == NULL || pbRecvBuffer == NULL || pioSendPci == NULL)
		return SCARD_E_INVALID_PARAMETER;

	/*
	 * Must at least send a 4 bytes APDU
	 */
	if (cbSendLength < 4)
		return SCARD_E_INVALID_PARAMETER;

	/*
	 * Must at least have 2 status words even for SCardControl
	 */
	if (dwRxLength < 2)
		return SCARD_E_INSUFFICIENT_BUFFER;

	/*
	 * Make sure no one has a lock on this reader
	 */
	if ((rv = RFCheckSharing(hCard)) != SCARD_S_SUCCESS)
		return rv;

	rv = RFReaderInfoById(hCard, &rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure the reader is working properly
	 */
	rv = RFCheckReaderStatus(rContext);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	rv = RFFindReaderHandle(hCard);
	if (rv != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Make sure some event has not occurred
	 */
	if ((rv = RFCheckReaderEventState(rContext, hCard)) != SCARD_S_SUCCESS)
		return rv;

	/*
	 * Check for some common errors
	 */
	if (pioSendPci->dwProtocol != SCARD_PROTOCOL_RAW)
	{
		if (rContext->dwStatus & SCARD_ABSENT)
		{
			return SCARD_E_NO_SMARTCARD;
		}
	}

	if (pioSendPci->dwProtocol != SCARD_PROTOCOL_RAW)
	{
		if (pioSendPci->dwProtocol != SCARD_PROTOCOL_ANY)
		{
			if (pioSendPci->dwProtocol != rContext->dwProtocol)
			{
				return SCARD_E_PROTO_MISMATCH;
			}
		}
	}

	if (cbSendLength > MAX_BUFFER_SIZE)
	{
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	/*
	 * Removed - a user may allocate a larger buffer if ( dwRxLength >
	 * MAX_BUFFER_SIZE ) { return SCARD_E_INSUFFICIENT_BUFFER; }
	 */

	/*
	 * Quick fix: PC/SC starts at 1 for bit masking but the IFD_Handler
	 * just wants 0 or 1
	 */

	if (pioSendPci->dwProtocol == SCARD_PROTOCOL_T0)
	{
		sSendPci.Protocol = 0;
	} else if (pioSendPci->dwProtocol == SCARD_PROTOCOL_T1)
	{
		sSendPci.Protocol = 1;
	} else if (pioSendPci->dwProtocol == SCARD_PROTOCOL_RAW)
	{
		/*
		 * This is temporary ......
		 */
		sSendPci.Protocol = SCARD_PROTOCOL_RAW;
	} else if (pioSendPci->dwProtocol == SCARD_PROTOCOL_ANY)
	{
	  /* Fix by Amira (Athena) */
		unsigned long i;
		unsigned long prot = rContext->dwProtocol;

		for (i = 0 ; prot != 1 ; i++)
			prot >>= 1;

		sSendPci.Protocol = i;
	}

	sSendPci.Length = pioSendPci->cbPciLength;

	DebugLogB("Send Protocol: %d", sSendPci.Protocol);

	tempRxLength = dwRxLength;

	if (pioSendPci->dwProtocol == SCARD_PROTOCOL_RAW)
	{
		rv = IFDControl_v2(rContext, (PUCHAR) pbSendBuffer, cbSendLength,
			pbRecvBuffer, &dwRxLength);
	} else
	{
		rv = IFDTransmit(rContext, sSendPci, (PUCHAR) pbSendBuffer,
			cbSendLength, pbRecvBuffer, &dwRxLength, &sRecvPci);
	}

	if (pioRecvPci)
	{
		pioRecvPci->dwProtocol = sRecvPci.Protocol;
		pioRecvPci->cbPciLength = sRecvPci.Length;
	}

	/*
	 * Check for any errors that might have occurred
	 */

	if (rv != SCARD_S_SUCCESS)
	{
		*pcbRecvLength = 0;
		return SCARD_E_NOT_TRANSACTED;
	}

	/*
	 * Available is less than received
	 */
	if (tempRxLength < dwRxLength)
	{
		*pcbRecvLength = 0;
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	if (dwRxLength > MAX_BUFFER_SIZE)
	{
		*pcbRecvLength = 0;
		return SCARD_E_INSUFFICIENT_BUFFER;
	}

	/*
	 * Successful return
	 */
	*pcbRecvLength = dwRxLength;
	return SCARD_S_SUCCESS;
}

LONG SCardListReaders(SCARDCONTEXT hContext, LPCTSTR mszGroups,
	LPTSTR mszReaders, LPDWORD pcchReaders)
{
	/*
	 * Client side function
	 */
	return SCARD_S_SUCCESS;
}

LONG SCardCancel(SCARDCONTEXT hContext)
{
	/*
	 * Client side function
	 */
	return SCARD_S_SUCCESS;
}

