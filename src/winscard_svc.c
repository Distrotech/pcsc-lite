/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2001-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This demarshalls functions over the message queue and keeps
 * track of clients and their handles.
 *
 * Each Client message is deald by creating a thread (\c CreateContextThread).
 * The thread establishes reands and demarshalls the message and calls the
 * appropriate function to threat it.
 */

#include "config.h"
#include <time.h>
#include <stdio.h>
#include <string.h>

#include "pcsclite.h"
#include "winscard.h"
#include "debuglog.h"
#include "winscard_msg.h"
#include "winscard_svc.h"
#include "sys_generic.h"
#include "thread_generic.h"

/**
 * @brief Represents the an Application Context on the Server side.
 *
 * An Application Context contains Channels (\c hCard).
 */
static struct _psContext
{
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard[PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS];
	DWORD dwClientID;			/* Connection ID used to reference the Client. */
	PCSCLITE_THREAD_T pthThread;		/* Event polling thread's ID */
	sharedSegmentMsg msgStruct;		/* Msg sent by the Client */
	int protocol_major, protocol_minor;	/* Protocol number agreed between client and server*/
} psContext[PCSCLITE_MAX_APPLICATIONS_CONTEXTS];

LONG MSGCheckHandleAssociation(SCARDHANDLE, DWORD);
LONG MSGFunctionDemarshall(psharedSegmentMsg, DWORD);
LONG MSGAddContext(SCARDCONTEXT, DWORD);
LONG MSGRemoveContext(SCARDCONTEXT, DWORD);
LONG MSGAddHandle(SCARDCONTEXT, SCARDHANDLE, DWORD);
LONG MSGRemoveHandle(SCARDHANDLE, DWORD);
LONG MSGCleanupClient(DWORD);

static void ContextThread(LPVOID pdwIndex);

LONG ContextsInitialize(void)
{
	memset(psContext, 0, sizeof(struct _psContext)*PCSCLITE_MAX_APPLICATIONS_CONTEXTS);
	return 1;
}

/**
 * @brief Creates threads to handle messages received from Clients.
 *
 * @param[in] pdwClientID Connection ID used to reference the Client.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Success.
 * @retval SCARD_F_INTERNAL_ERROR Exceded the maximum number of simultaneous Application Contexts.
 * @retval SCARD_E_NO_MEMORY Error creating the Context Thread.
 */
LONG CreateContextThread(PDWORD pdwClientID)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATIONS_CONTEXTS; i++)
	{
		if (psContext[i].dwClientID == 0)
		{
			psContext[i].dwClientID = *pdwClientID;
			*pdwClientID = 0;
			break;
		}
	}

	if (i == PCSCLITE_MAX_APPLICATIONS_CONTEXTS)
	{
		SYS_CloseFile(psContext[i].dwClientID);
		psContext[i].dwClientID = 0; 
		return SCARD_F_INTERNAL_ERROR;
	}
	
	if (SYS_ThreadCreate(&psContext[i].pthThread, THREAD_ATTR_DETACHED,
		(PCSCLITE_THREAD_FUNCTION( )) ContextThread,
		(LPVOID) i) != 1)
	{
		SYS_CloseFile(psContext[i].dwClientID);
		psContext[i].dwClientID = 0; 
		return SCARD_E_NO_MEMORY;
	}

	return SCARD_S_SUCCESS;
}

/*
 * A list of local functions used to keep track of clients and their
 * connections 
 */

/**
 * @brief Handles messages received from Clients.
 *
 * For each Client message a new instance of this thread is created.
 *
 * @param[in] dwIndex Index of an avaiable Application Context slot in 
 * \c psContext.
 */
static void ContextThread(LPVOID dwIndex)
{
	LONG rv;
	sharedSegmentMsg msgStruct;
	DWORD dwContextIndex = (DWORD)dwIndex;

	Log2(PCSC_LOG_DEBUG, "Thread is started: %d",
		psContext[dwContextIndex].dwClientID);
	
	while (1)
	{
		switch (rv = SHMProcessEventsContext(&psContext[dwContextIndex].dwClientID, &msgStruct, 0))
		{
		case 0:
			if (msgStruct.mtype == CMD_CLIENT_DIED)
			{
				/*
				 * Clean up the dead client
				 */
				Log2(PCSC_LOG_DEBUG, "Client die: %d",
					psContext[dwContextIndex].dwClientID);
				MSGCleanupClient(dwContextIndex);
				SYS_ThreadExit((LPVOID) NULL);
			} 
			break;

		case 1:
			if (msgStruct.mtype == CMD_FUNCTION)
			{
				/*
				 * Command must be found
				 */
				MSGFunctionDemarshall(&msgStruct, dwContextIndex);

				/* the SCARD_TRANSMIT_EXTENDED anwser is already sent by
				 * MSGFunctionDemarshall */
				if (msgStruct.command != SCARD_TRANSMIT_EXTENDED)
					rv = SHMMessageSend(&msgStruct, sizeof(msgStruct),
						psContext[dwContextIndex].dwClientID,
						PCSCLITE_SERVER_ATTEMPTS);
			}
			else
				/* pcsc-lite client/server protocol version */
				if (msgStruct.mtype == CMD_VERSION)
				{
					version_struct *veStr;
					veStr = (version_struct *) msgStruct.data;

					/* get the client protocol version */
					psContext[dwContextIndex].protocol_major = veStr->major;
					psContext[dwContextIndex].protocol_minor = veStr->minor;

					Log3(PCSC_LOG_DEBUG,
						"Client is protocol version %d:%d",
						veStr->major, veStr->minor);

					/* set the server protocol version */
					veStr->major = PROTOCOL_VERSION_MAJOR;
					veStr->minor = PROTOCOL_VERSION_MINOR;
					veStr->rv = SCARD_S_SUCCESS;

					/* send back the response */
					rv = SHMMessageSend(&msgStruct, sizeof(msgStruct),
						psContext[dwContextIndex].dwClientID,
					    PCSCLITE_SERVER_ATTEMPTS);
				}
				else
					continue;

			break;

		case 2:
			/*
			 * timeout in SHMProcessEventsContext(): do nothing
			 * this is used to catch the Ctrl-C signal at some time when
			 * nothing else happens
			 */
			break;
			
		case -1:
			Log1(PCSC_LOG_ERROR, "Error in SHMProcessEventsContext");
			break;
			
		default:
			Log2(PCSC_LOG_ERROR,
				"SHMProcessEventsContext unknown retval: %d", rv);
			break;
		}
	}
}

/**
 * @brief Find out which message was sent by the Client and execute the right task.
 *
 * According to the command type sent by the client (\c pcsc_msg_commands),
 * cast the message data to the correct struct so that is can be demarshalled.
 * Then call the appropriate function to handle the request.
 *
 * Possible structs are: \c establish_struct \c release_struct 
 * \c connect_struct \c reconnect_struct \c disconnect_struct \c begin_struct
 * \c cancel_struct \c end_struct \c status_struct \c transmit_struct
 * \c control_struct \c getset_struct.
 *
 * @param[in] msgStruct Message to be demarshalled and executed.
 * @param[in] dwContextIndex 
 */
LONG MSGFunctionDemarshall(psharedSegmentMsg msgStruct, DWORD dwContextIndex)
{
	LONG rv;
	establish_struct *esStr;
	release_struct *reStr;
	connect_struct *coStr;
	reconnect_struct *rcStr;
	disconnect_struct *diStr;
	begin_struct *beStr;
	cancel_struct *caStr;
	end_struct *enStr;
	status_struct *stStr;
	transmit_struct *trStr;
	control_struct *ctStr;
	getset_struct *gsStr;

	/*
	 * Zero out everything 
	 */
	rv = 0;
	switch (msgStruct->command)
	{

	case SCARD_ESTABLISH_CONTEXT:
		esStr = ((establish_struct *) msgStruct->data);
		esStr->rv = SCardEstablishContext(esStr->dwScope, 0, 0,
			&esStr->phContext);

		if (esStr->rv == SCARD_S_SUCCESS)
			esStr->rv =
				MSGAddContext(esStr->phContext, dwContextIndex);
		break;

	case SCARD_RELEASE_CONTEXT:
		reStr = ((release_struct *) msgStruct->data);
		reStr->rv = SCardReleaseContext(reStr->hContext);

		if (reStr->rv == SCARD_S_SUCCESS)
			reStr->rv =
				MSGRemoveContext(reStr->hContext, dwContextIndex);

		break;

	case SCARD_CONNECT:
		coStr = ((connect_struct *) msgStruct->data);
		coStr->rv = SCardConnect(coStr->hContext, coStr->szReader,
			coStr->dwShareMode, coStr->dwPreferredProtocols,
			&coStr->phCard, &coStr->pdwActiveProtocol);

		if (coStr->rv == SCARD_S_SUCCESS)
			coStr->rv =
				MSGAddHandle(coStr->hContext, coStr->phCard, dwContextIndex);

		break;

	case SCARD_RECONNECT:
		rcStr = ((reconnect_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(rcStr->hCard, dwContextIndex);
		if (rv != 0) return rv;

		rcStr->rv = SCardReconnect(rcStr->hCard, rcStr->dwShareMode,
			rcStr->dwPreferredProtocols,
			rcStr->dwInitialization, &rcStr->pdwActiveProtocol);
		break;

	case SCARD_DISCONNECT:
		diStr = ((disconnect_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(diStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		diStr->rv = SCardDisconnect(diStr->hCard, diStr->dwDisposition);

		if (diStr->rv == SCARD_S_SUCCESS)
			diStr->rv =
				MSGRemoveHandle(diStr->hCard, dwContextIndex);
		break;

	case SCARD_BEGIN_TRANSACTION:
		beStr = ((begin_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(beStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		beStr->rv = SCardBeginTransaction(beStr->hCard);
		break;

	case SCARD_END_TRANSACTION:
		enStr = ((end_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(enStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		enStr->rv =
			SCardEndTransaction(enStr->hCard, enStr->dwDisposition);
		break;

	case SCARD_CANCEL_TRANSACTION:
		caStr = ((cancel_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(caStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		caStr->rv = SCardCancelTransaction(caStr->hCard);
		break;

	case SCARD_STATUS:
		stStr = ((status_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(stStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		stStr->rv = SCardStatus(stStr->hCard, stStr->mszReaderNames,
			&stStr->pcchReaderLen, &stStr->pdwState,
			&stStr->pdwProtocol, stStr->pbAtr, &stStr->pcbAtrLen);
		break;

	case SCARD_TRANSMIT:
		trStr = ((transmit_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(trStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		trStr->rv = SCardTransmit(trStr->hCard, &trStr->pioSendPci,
			trStr->pbSendBuffer, trStr->cbSendLength,
			&trStr->pioRecvPci, trStr->pbRecvBuffer,
			&trStr->pcbRecvLength);
		break;

	case SCARD_CONTROL:
		ctStr = ((control_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(ctStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		ctStr->rv = SCardControl(ctStr->hCard, ctStr->dwControlCode,
			ctStr->pbSendBuffer, ctStr->cbSendLength,
			ctStr->pbRecvBuffer, ctStr->cbRecvLength,
			&ctStr->dwBytesReturned);
		break;

	case SCARD_GET_ATTRIB:
		gsStr = ((getset_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(gsStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		gsStr->rv = SCardGetAttrib(gsStr->hCard, gsStr->dwAttrId,
			gsStr->pbAttr, &gsStr->cbAttrLen);
		break;

	case SCARD_SET_ATTRIB:
		gsStr = ((getset_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(gsStr->hCard, dwContextIndex);
		if (rv != 0) return rv;
		gsStr->rv = SCardSetAttrib(gsStr->hCard, gsStr->dwAttrId,
			gsStr->pbAttr, gsStr->cbAttrLen);
		break;

	case SCARD_TRANSMIT_EXTENDED:
		{
			transmit_struct_extended *treStr;
			unsigned char pbSendBuffer[MAX_BUFFER_SIZE_EXTENDED];
			unsigned char pbRecvBuffer[MAX_BUFFER_SIZE_EXTENDED];

			treStr = ((transmit_struct_extended *) msgStruct->data);
			rv = MSGCheckHandleAssociation(treStr->hCard, dwContextIndex);
			if (rv != 0) return rv;

			/* on more block to read? */
			if (treStr->size > PCSCLITE_MAX_MESSAGE_SIZE)
			{
				/* copy the first APDU part */
				memcpy(pbSendBuffer, treStr->data,
					PCSCLITE_MAX_MESSAGE_SIZE-sizeof(*treStr));

				/* receive the second block */
				rv = SHMMessageReceive(
					pbSendBuffer+PCSCLITE_MAX_MESSAGE_SIZE-sizeof(*treStr),
					treStr->size - PCSCLITE_MAX_MESSAGE_SIZE,
					psContext[dwContextIndex].dwClientID,
					PCSCLITE_SERVER_ATTEMPTS);
				if (rv)
					Log1(PCSC_LOG_CRITICAL, "reception failed");
			}
			else
				memcpy(pbSendBuffer, treStr->data, treStr->cbSendLength);

			treStr->rv = SCardTransmit(treStr->hCard, &treStr->pioSendPci,
				pbSendBuffer, treStr->cbSendLength,
				&treStr->pioRecvPci, pbRecvBuffer,
				&treStr->pcbRecvLength);

			treStr->size = sizeof(*treStr) + treStr->pcbRecvLength;
			if (treStr->size > PCSCLITE_MAX_MESSAGE_SIZE)
			{
				/* two blocks */
				memcpy(treStr->data, pbRecvBuffer, PCSCLITE_MAX_MESSAGE_SIZE
					- sizeof(*treStr));

				rv = SHMMessageSend(msgStruct, sizeof(*msgStruct),
					psContext[dwContextIndex].dwClientID,
					PCSCLITE_SERVER_ATTEMPTS);
				if (rv)
					Log1(PCSC_LOG_CRITICAL, "transmission failed");

				rv = SHMMessageSend(pbRecvBuffer + PCSCLITE_MAX_MESSAGE_SIZE
					- sizeof(*treStr),
					treStr->size - PCSCLITE_MAX_MESSAGE_SIZE, 
					psContext[dwContextIndex].dwClientID,
					PCSCLITE_SERVER_ATTEMPTS);
				if (rv)
					Log1(PCSC_LOG_CRITICAL, "transmission failed");
			}
			else
			{
				/* one block only */
				memcpy(treStr->data, pbRecvBuffer, treStr->pcbRecvLength);

				rv = SHMMessageSend(msgStruct, sizeof(*msgStruct),
					psContext[dwContextIndex].dwClientID,
					PCSCLITE_SERVER_ATTEMPTS);
				if (rv)
					Log1(PCSC_LOG_CRITICAL, "transmission failed");
			}
		}
		break;

	default:
		Log2(PCSC_LOG_CRITICAL, "Unknown command: %d", msgStruct->command);
		return -1;
	}

	return 0;
}

LONG MSGAddContext(SCARDCONTEXT hContext, DWORD dwContextIndex)
{
	psContext[dwContextIndex].hContext = hContext;
	return SCARD_S_SUCCESS;
}

LONG MSGRemoveContext(SCARDCONTEXT hContext, DWORD dwContextIndex)
{
	int i;
	LONG rv;

	if (psContext[dwContextIndex].hContext == hContext)
	{

		for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
		{
			/*
			 * Disconnect each of these just in case 
			 */
			
			if (psContext[dwContextIndex].hCard[i] != 0)
			{
				
				/*
				 * We will use SCardStatus to see if the card has been 
				 * reset there is no need to reset each time
				 * Disconnect is called 
				 */
				
				rv = SCardStatus(psContext[dwContextIndex].hCard[i], 0, 0, 0, 0, 0, 0);
				
				if (rv == SCARD_W_RESET_CARD
				    || rv == SCARD_W_REMOVED_CARD)
				{
					SCardDisconnect(psContext[dwContextIndex].hCard[i], SCARD_LEAVE_CARD);
				} else
				{
					SCardDisconnect(psContext[dwContextIndex].hCard[i], SCARD_RESET_CARD);
				}

				psContext[dwContextIndex].hCard[i] = 0;
			}

		}

		psContext[dwContextIndex].hContext = 0;
		return SCARD_S_SUCCESS;
	} 

	return SCARD_E_INVALID_VALUE;
}

LONG MSGAddHandle(SCARDCONTEXT hContext, SCARDHANDLE hCard, DWORD dwContextIndex)
{
	int i;

	if (psContext[dwContextIndex].hContext == hContext)
	{
		
		/*
		 * Find an empty spot to put the hCard value 
		 */
		for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
		{
			if (psContext[dwContextIndex].hCard[i] == 0)
			{
				psContext[dwContextIndex].hCard[i] = hCard;
				break;
			}
		}
		
		if (i == PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS)
		{
			return SCARD_F_INTERNAL_ERROR;
		} else
		{
			return SCARD_S_SUCCESS;
		}

	}
	
	return SCARD_E_INVALID_VALUE;
}

LONG MSGRemoveHandle(SCARDHANDLE hCard, DWORD dwContextIndex)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
	{
		if (psContext[dwContextIndex].hCard[i] == hCard)
		{
			psContext[dwContextIndex].hCard[i] = 0;
			return SCARD_S_SUCCESS;
		}
	}

	return SCARD_E_INVALID_VALUE;
}


LONG MSGCheckHandleAssociation(SCARDHANDLE hCard, DWORD dwContextIndex)
{
	int i;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
	{
		if (psContext[dwContextIndex].hCard[i] == hCard)
		{
			return 0;
		}
	}
	
	/* Must be a rogue client, debug log and sleep a couple of seconds */
	Log1(PCSC_LOG_ERROR, "Client failed to authenticate");
	SYS_Sleep(2);

	return -1;
}

LONG MSGCleanupClient(DWORD dwContextIndex)
{
	if (psContext[dwContextIndex].hContext != 0)
	{
		SCardReleaseContext(psContext[dwContextIndex].hContext);	
		MSGRemoveContext(psContext[dwContextIndex].hContext, dwContextIndex);
	}

	psContext[dwContextIndex].dwClientID = 0;
	psContext[dwContextIndex].protocol_major = 0;
	psContext[dwContextIndex].protocol_minor = 0;
	
	return 0;
}
