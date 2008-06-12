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
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>


#include "pcsclite.h"
#include "auth.h"
#include "pcsc_config.h"
#include "instance.h"
#include "clientcred.h"
#include "winscard.h"
#include "debuglog.h"
#include "winscard_msg.h"
#include "winscard_svc.h"
#include "winscard_client.h"
#include "sys_generic.h"
#include "thread_generic.h"
#include "wintypes.h"
#include "readerfactory.h"
#include "eventhandler.h"
#include "launcher.h"


/**
 * @brief Represents the an Application Context on the Server side.
 *
 * An Application Context contains Channels (\c hCard).
 */
static struct _psContext
{
#ifdef _HAVE_SYS_DOORS_H
	PCSCLITE_MUTEX mMutex;
	PCSCLITE_COND  mCond;
#endif
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard[PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS];
	DWORD dwClientID;			/* Connection ID used to reference the Client. */
	PCSCLITE_THREAD_T pthThread;		/* Event polling thread's ID */
	PCSCLITE_CRED_T cred;                   /* Client credentials struct */
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
	memset(psContext, 0,
	    sizeof(struct _psContext)*PCSCLITE_MAX_APPLICATIONS_CONTEXTS);
	return 1;
}

/**
 * @brief Creates threads to handle messages received from Clients.
 *
 * @param[in] pdwClientID Connection ID used to reference the Client.
 *
 * @return Error code.
 * @retval SCARD_S_SUCCESS Success.
 * @retval SCARD_F_INTERNAL_ERROR Exceded the maximum number of
 *         simultaneous Application Contexts.
 * @retval SCARD_E_NO_MEMORY Error creating the Context Thread.
 */

LONG
CreateContextThread(PDWORD pdwClientID)
{
	int i;


	/*
	 * If we're running as launcher the context lookup lock
	 * is already held.
	 */
	for (i = 0; i < PCSCLITE_MAX_APPLICATIONS_CONTEXTS; i++)
	{
		if (psContext[i].dwClientID == 0)
		{
			psContext[i].dwClientID = *pdwClientID;
			*pdwClientID = 0;
			break;
		}
	}

	if (pcscCfg.launchMode == INSTANCE)
		UnlockContextLookup();

	if (i == PCSCLITE_MAX_APPLICATIONS_CONTEXTS)
	{
		SYS_CloseFile(psContext[i].dwClientID);
		psContext[i].dwClientID = 0;
		Log2(PCSC_LOG_CRITICAL, "No more context available (max: %d)",
			PCSCLITE_MAX_APPLICATIONS_CONTEXTS);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (SYS_ThreadCreate(&psContext[i].pthThread, THREAD_ATTR_DETACHED,
		(PCSCLITE_THREAD_FUNCTION( )) ContextThread,
		(LPVOID) i) != 1)
	{
		SYS_CloseFile(psContext[i].dwClientID);
		psContext[i].dwClientID = 0;
		Log1(PCSC_LOG_CRITICAL, "SYS_ThreadCreate failed");
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
	int saveRemaining;
	static unsigned long fn;

	Log2(PCSC_LOG_DEBUG, "Context thread started for client (fd=%d)",
		psContext[dwContextIndex].dwClientID);

	while (1)
	{
		switch (rv = SHMProcessEventsContext(
			&psContext[dwContextIndex].dwClientID,
			dwContextIndex, &msgStruct, 0))
		{
		case 0:
			if (msgStruct.mtype == CMD_CLIENT_DIED)
			{
				/*
				 * Clean up the dead client
				 */
				Log2(PCSC_LOG_DEBUG,
					"Client fd=%d died. Shutting down thread",
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

				switch(pcscCfg.transportType) {
				case SOCKET_UNIX:
				case SOCKET_INETV4:
					/* the SCARD_TRANSMIT_EXTENDED anwser is already sent by
					* MSGFunctionDemarshall */
					if (msgStruct.command != SCARD_TRANSMIT_EXTENDED)
						rv = SHMMessageSend(&msgStruct, sizeof(msgStruct),
							psContext[dwContextIndex].dwClientID,
							PCSCLITE_SERVER_ATTEMPTS);

					break;
				}
			}
			else
			if (msgStruct.mtype == CMD_VERSION) /* client/server protocol version */
			{
				version_struct *veStr;
				veStr = (version_struct *) msgStruct.data;

				/* get the client protocol version */
				psContext[dwContextIndex].protocol_major = veStr->major;
				psContext[dwContextIndex].protocol_minor = veStr->minor;

				Log3(PCSC_LOG_DEBUG,
					"Client is protocol version %d:%d ",
					veStr->major, veStr->minor);


				/* set the server protocol version */
				veStr->major = PROTOCOL_VERSION_MAJOR;
				veStr->minor = PROTOCOL_VERSION_MINOR;
				veStr->rv = SCARD_S_SUCCESS;

				switch(pcscCfg.transportType) {
				case SOCKET_UNIX:
				case SOCKET_INETV4:
					/* send back the response */
					rv = SHMMessageSend(&msgStruct, sizeof(msgStruct),
						psContext[dwContextIndex].dwClientID,
							PCSCLITE_SERVER_ATTEMPTS);
					break;
				}
			}
			else
		if (msgStruct.mtype == CMD_FETCH) /* Request data */
			{
				++fn;
				fetch_struct *pfetch;
				pfetch = (fetch_struct *)msgStruct.data;

				switch(msgStruct.command) {
				case FETCH_READER_STATE: {
					pfetch->rv = EHfetchReaderState(
							pfetch->type.index,
							(PREADER_STATE)pfetch->data);
					break;
				   }
				}
				switch(pcscCfg.transportType) {
				case SOCKET_UNIX:
				case SOCKET_INETV4:
					/* send back the response */
					rv = SHMMessageSend(&msgStruct, sizeof(msgStruct),
						psContext[dwContextIndex].dwClientID,
							PCSCLITE_SERVER_ATTEMPTS);
					break;
				}
			}
			else
				continue;



		case 2:
			/*
			 * timeout in SHMProcessEventsContext(): do nothing
			 * this is used to catch the Ctrl-C signal at some time when
			 * nothing else happens
			 */
			break;

		case -1:
			if (pcscCfg.pcscdExiting) {
				Log1(PCSC_LOG_ERROR,
					"SHMProcessEventsContext: Exit flag set."
					"Context thread terminating\n");
				return;
			}
			Log1(PCSC_LOG_ERROR, "Error in SHMProcessEventsContext");
			if (msgStruct.mtype == CMD_FETCH)
				Log2(PCSC_LOG_ERROR, "Fetch seq# %ld", fn);
			break;

		default:
			if (pcscCfg.pcscdExiting) {
				Log1(PCSC_LOG_ERROR,
					"SHMProcessEventsContext: Exit flag set."
					"Context thread terminating\n");
				return;
			}
			Log2(PCSC_LOG_ERROR,
				"SHMProcessEventsContext unknown retval: %d", rv);
			if (msgStruct.mtype == CMD_FETCH)
				Log2(PCSC_LOG_ERROR, "Fetch seq# %ld", fn);
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
	LONG rv = 0;
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
	PCSCLITE_CRED_T *cred;

	switch (msgStruct->command)
	{

	case SCARD_ESTABLISH_CONTEXT:
		esStr = ((establish_struct *) msgStruct->data);

		cred = &psContext[dwContextIndex].cred;
		cred->dpyNbr = esStr->dpyNbr;
		cred->screenNbr = esStr->screenNbr;
		cred->clientXhostIP = esStr->clientXhostIP;

		AUTHGetClientCreds(psContext[dwContextIndex].dwClientID, cred);

		esStr->rv = SCardEstablishContext(esStr->dwScope, 0,
			(LPVOID *)cred, &esStr->phContext);

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
		if (rv != 0) {
			rcStr->rv = rv;
			return rv;
		}
		rcStr->rv = SCardReconnect(rcStr->hCard, rcStr->dwShareMode,
			rcStr->dwPreferredProtocols,
			rcStr->dwInitialization, &rcStr->pdwActiveProtocol);
		break;

	case SCARD_DISCONNECT:
		diStr = ((disconnect_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(diStr->hCard, dwContextIndex);
		if (rv != 0) {
			diStr->rv = 0; /* make idempotent */
			return rv;
		}
		diStr->rv = SCardDisconnect(diStr->hCard, diStr->dwDisposition);

		if (diStr->rv == SCARD_S_SUCCESS)
			diStr->rv =
				MSGRemoveHandle(diStr->hCard, dwContextIndex);

		break;

	case SCARD_BEGIN_TRANSACTION:
		beStr = ((begin_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(beStr->hCard, dwContextIndex);
		if (rv != 0) {
			beStr->rv = rv;
			return rv;
		}
		beStr->rv = SCardBeginTransaction(beStr->hCard);
		break;

	case SCARD_END_TRANSACTION:
		enStr = ((end_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(enStr->hCard, dwContextIndex);
		if (rv != 0) {
			enStr->rv = rv;
			return rv;
		}
		enStr->rv =
			SCardEndTransaction(enStr->hCard, enStr->dwDisposition);
		break;

	case SCARD_CANCEL_TRANSACTION:
		caStr = ((cancel_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(caStr->hCard, dwContextIndex);
		if (rv != 0) {
			caStr->rv = rv;
			return rv;
		}
		caStr->rv = SCardCancelTransaction(caStr->hCard);
		break;

	case SCARD_STATUS:
		stStr = ((status_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(stStr->hCard, dwContextIndex);
		if (rv != 0) {
			stStr->rv = rv;
			return rv;
		}
		stStr->rv = SCardStatus(stStr->hCard, stStr->mszReaderNames,
			&stStr->pcchReaderLen, &stStr->pdwState,
			&stStr->pdwProtocol, stStr->pbAtr, &stStr->pcbAtrLen);
		break;

	case SCARD_TRANSMIT:
		trStr = ((transmit_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(trStr->hCard, dwContextIndex);
		if (rv != 0) {
			trStr->rv = rv;
			return rv;
		}
		trStr->rv = SCardTransmit(trStr->hCard, &trStr->pioSendPci,
			trStr->pbSendBuffer, trStr->cbSendLength,
			&trStr->pioRecvPci, trStr->pbRecvBuffer,
			&trStr->pcbRecvLength);
		break;

	case SCARD_CONTROL:
		ctStr = ((control_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(ctStr->hCard, dwContextIndex);
		if (rv != 0) {
			ctStr->rv = rv;
			return rv;
		}
		ctStr->rv = SCardControl(ctStr->hCard, ctStr->dwControlCode,
			ctStr->pbSendBuffer, ctStr->cbSendLength,
			ctStr->pbRecvBuffer, ctStr->cbRecvLength,
			&ctStr->dwBytesReturned);
		break;

	case SCARD_GET_ATTRIB:
		gsStr = ((getset_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(gsStr->hCard, dwContextIndex);
		if (rv != 0) {
			gsStr->rv = rv;
			return rv;
		}
		gsStr->rv = SCardGetAttrib(gsStr->hCard, gsStr->dwAttrId,
			gsStr->pbAttr, &gsStr->cbAttrLen);
		break;

	case SCARD_SET_ATTRIB:
		gsStr = ((getset_struct *) msgStruct->data);
		rv = MSGCheckHandleAssociation(gsStr->hCard, dwContextIndex);
		if (rv != 0) {
			gsStr->rv = rv;
			return rv;
		}
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
			if (rv != 0) {
				treStr->rv = rv;
				return rv;
			}

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
			if (rv)
				treStr->rv = rv;
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
					SCardDisconnect(psContext[dwContextIndex].hCard[i],
							SCARD_LEAVE_CARD);
				} else
				{
					SCardDisconnect(psContext[dwContextIndex].hCard[i],
							SCARD_RESET_CARD);
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
	int i, tally = 0;

	Log3(PCSC_LOG_DEBUG,
	     "MSGCleanupClient(%d) close fd=%d.",
	     dwContextIndex, psContext[dwContextIndex].dwClientID );

	LockContextLookup();

	if (psContext[dwContextIndex].hContext != 0) {
		SCardReleaseContext(psContext[dwContextIndex].hContext);
		MSGRemoveContext(psContext[dwContextIndex].hContext, dwContextIndex);
	}

	SYS_CloseFile(psContext[dwContextIndex].dwClientID);
	psContext[dwContextIndex].dwClientID = 0;
	psContext[dwContextIndex].protocol_major = 0;
	psContext[dwContextIndex].protocol_minor = 0;

	for (i = 0; i < PCSCLITE_MAX_APPLICATION_CONTEXT_CHANNELS; i++)
		if (psContext[i].dwClientID != 0)
			++tally;

	Log3(PCSC_LOG_DEBUG, "MSGCleanupClient(%d): Active contexts: %d",
	    dwContextIndex, tally);

	if (tally < 1 && pcscCfg.instanceTimeout > -1) {
		if (pcscCfg.instanceTimeout == 0) {
			Log1(PCSC_LOG_DEBUG,
				"Instance configured for immediate exit");
			InstanceExitHandler(0);
		} else {
			StartInstanceTimer();
		}
	}
	UnlockContextLookup();

	return 0;
}
