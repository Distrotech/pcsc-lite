/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2001-2004
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2003-2004
 *  Damien Sauveron <damien.sauveron@labri.fr>
 * Copyright (C) 2002-2009
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 * Copyright (C) 2009
 *  Jean-Luc Giraud <jlgiraud@googlemail.com>
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
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "pcscd.h"
#include "winscard.h"
#include "debuglog.h"
#include "winscard_msg.h"
#include "winscard_svc.h"
#include "sys_generic.h"
#include "thread_generic.h"
#include "readerfactory.h"
#include "eventhandler.h"
#include "simclist.h"

/**
 * @brief Represents an Application Context on the Server side.
 *
 * An Application Context contains Channels (\c hCard).
 */

extern char AutoExit;
static int contextMaxThreadCounter = PCSC_MAX_CONTEXT_THREADS;
static int contextMaxCardHandles = PCSC_MAX_CONTEXT_CARD_HANDLES;

/* Context tracking list */
static list_t contextsList;

struct _psContext
{
	int32_t hContext;
	list_t cardsList;
	uint32_t dwClientID;			/**< Connection ID used to reference the Client. */
	PCSCLITE_THREAD_T pthThread;		/**< Event polling thread's ID */
	int protocol_major, protocol_minor;	/**< Protocol number agreed between client and server*/
};
typedef struct _psContext SCONTEXT;

static LONG MSGCheckHandleAssociation(SCARDHANDLE, SCONTEXT *);
static LONG MSGAddContext(SCARDCONTEXT, SCONTEXT *);
static LONG MSGRemoveContext(SCARDCONTEXT, SCONTEXT *);
static LONG MSGAddHandle(SCARDCONTEXT, SCARDHANDLE, SCONTEXT *);
static LONG MSGRemoveHandle(SCARDHANDLE, SCONTEXT *);
static LONG MSGCleanupClient(SCONTEXT *);

static void ContextThread(LPVOID pdwIndex);

extern READER_STATE readerStates[PCSCLITE_MAX_READERS_CONTEXTS];

static int contextsListhContext_seeker(const void *el, const void *key)
{
	const SCONTEXT * currentContext = (SCONTEXT *)el;

	if ((el == NULL) || (key == NULL))
	{
		Log3(PCSC_LOG_CRITICAL, "contextsListhContext_seeker called with NULL pointer: el=%X, key=%X", el, key);
	}

	if (currentContext->hContext == *(int32_t *)key)
		return 1;
	return 0;
}

LONG ContextsInitialize(int customMaxThreadCounter, int customMaxThreadCardHandles)
{
	int lrv = 0;

	if (customMaxThreadCounter != 0)
		contextMaxThreadCounter = customMaxThreadCounter;

	if (customMaxThreadCardHandles != 0)
		contextMaxCardHandles = customMaxThreadCardHandles;

	lrv = list_init(&contextsList);
	if (lrv < 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_init failed with return value: %X", lrv);
		return -1;
	}
	lrv = list_attributes_seeker(& contextsList, contextsListhContext_seeker);
	if (lrv < 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_attributes_seeker failed with return value: %X", lrv);
		return -1;
	}

	return 1;
}

void ContextsDeinitialize(void)
{
	int listSize;
	listSize = list_size(&contextsList);
	Log2(PCSC_LOG_DEBUG, "remaining threads: %d", listSize);
	/* This is currently a no-op. It should terminate the threads properly. */
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
LONG CreateContextThread(uint32_t *pdwClientID)
{
	int rv;
	int lrv;
	int listSize;
	SCONTEXT * newContext = NULL;

	listSize = list_size(&contextsList);

	if (listSize >= contextMaxThreadCounter)
	{
		Log2(PCSC_LOG_CRITICAL, "Too many context running: %d", listSize);
		goto error;
	}

	/* Create the context for this thread. */
	newContext = malloc(sizeof(*newContext));
	if (NULL == newContext)
	{
		Log1(PCSC_LOG_CRITICAL, "Could not allocate new context");
		goto error;
	}
	memset(newContext, 0, sizeof(*newContext));

	newContext->dwClientID = *pdwClientID;

	/* Initialise the list of card contexts */
	lrv = list_init(&(newContext->cardsList));
	if (lrv < 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_init failed with return value: %X", lrv);
		goto error;
	}

	/* request to store copies, and provide the metric function */
	list_attributes_copy(&(newContext->cardsList), list_meter_int32_t, 1);

	/* Adding a comparator
	 * The stored type is SCARDHANDLE (long) but has only 32 bits
	 * usefull even on a 64-bit CPU since the API between pcscd and
	 * libpcscliter uses "int32_t hCard;"
	 */
	lrv = list_attributes_comparator(&(newContext->cardsList), list_comparator_int32_t);
	if (lrv != 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_attributes_comparator failed with return value: %X", lrv);
		list_destroy(&(newContext->cardsList));
		goto error;
	}

	lrv = list_append(&contextsList, newContext);
	if (lrv < 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_append failed with return value: %X", lrv);
		list_destroy(&(newContext->cardsList));
		goto error;
	}

	rv = SYS_ThreadCreate(&(newContext->pthThread), THREAD_ATTR_DETACHED,
		(PCSCLITE_THREAD_FUNCTION( )) ContextThread, (LPVOID) newContext);
	if (rv)
	{
		int lrv2;

		Log2(PCSC_LOG_CRITICAL, "SYS_ThreadCreate failed: %s", strerror(rv));
		lrv2 = list_delete(&contextsList, newContext);
		if (lrv2 < 0)
			Log2(PCSC_LOG_CRITICAL, "list_delete failed with error %X", lrv2);
		list_destroy(&(newContext->cardsList));
		goto error;
	}

	/* disable any suicide alarm */
	if (AutoExit)
		alarm(0);

	return SCARD_S_SUCCESS;

error:
	if (newContext)
		free(newContext);
	(void)SYS_CloseFile(*pdwClientID);
	return SCARD_E_NO_MEMORY;
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
 * \c SCONTEXT *.
 */
static const char *CommandsText[] = {
	"NULL",
	"ESTABLISH_CONTEXT",	/* 0x01 */
	"RELEASE_CONTEXT",
	"LIST_READERS",
	"CONNECT",
	"RECONNECT",			/* 0x05 */
	"DISCONNECT",
	"BEGIN_TRANSACTION",
	"END_TRANSACTION",
	"TRANSMIT",
	"CONTROL",				/* 0x0A */
	"STATUS",
	"GET_STATUS_CHANGE",
	"CANCEL",
	"CANCEL_TRANSACTION",
	"GET_ATTRIB",			/* 0x0F */
	"SET_ATTRIB",
	"CMD_VERSION",
	"CMD_GET_READERS_STATE",
	"CMD_WAIT_READER_STATE_CHANGE",
	"CMD_STOP_WAITING_READER_STATE_CHANGE",	/* 0x14 */
	"NULL"
};

#define READ_BODY(v) \
	if (header.size != sizeof(v)) { goto wrong_length; } \
	ret = SHMMessageReceive(header.command, &v, sizeof(v), filedes, PCSCLITE_READ_TIMEOUT); \
	if (ret < 0) { Log2(PCSC_LOG_DEBUG, "Client die: %d", filedes); goto exit; }

#define WRITE_BODY(v) \
	ret = SHMMessageSend(&v, sizeof(v), filedes, PCSCLITE_WRITE_TIMEOUT);

static void ContextThread(LPVOID newContext)
{
	SCONTEXT * threadContext = (SCONTEXT *) newContext;
	int32_t filedes = threadContext->dwClientID;

	Log3(PCSC_LOG_DEBUG, "Thread is started: dwClientID=%d, threadContext @%X",
		threadContext->dwClientID, threadContext);

	while (1)
	{
		struct rxHeader header;
		int32_t ret = SHMMessageReceive(0, &header, sizeof(header), filedes, PCSCLITE_READ_TIMEOUT);

		if (ret < 0)
		{
			/* Clean up the dead client */
			Log2(PCSC_LOG_DEBUG, "Client die: %d", filedes);
			EHTryToUnregisterClientForEvent(filedes);
			goto exit;
		}

		Log3(PCSC_LOG_DEBUG, "Received command: %s from client %d",
			CommandsText[header.command], filedes);

		switch (header.command)
		{
			/* pcsc-lite client/server protocol version */
			case CMD_VERSION:
			{
				struct version_struct veStr;

				READ_BODY(veStr)

				/* get the client protocol version */
				threadContext->protocol_major = veStr.major;
				threadContext->protocol_minor = veStr.minor;

				Log3(PCSC_LOG_DEBUG,
						"Client is protocol version %d:%d",
						veStr.major, veStr.minor);

				veStr.rv = SCARD_S_SUCCESS;

				/* client is newer than server */
				if ((veStr.major > PROTOCOL_VERSION_MAJOR)
						|| (veStr.major == PROTOCOL_VERSION_MAJOR
							&& veStr.minor > PROTOCOL_VERSION_MINOR))
				{
					Log3(PCSC_LOG_CRITICAL,
							"Client protocol is too new %d:%d",
							veStr.major, veStr.minor);
					Log3(PCSC_LOG_CRITICAL,
							"Server protocol is %d:%d",
							PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
					veStr.rv = SCARD_E_NO_SERVICE;
				}

				/* set the server protocol version */
				veStr.major = PROTOCOL_VERSION_MAJOR;
				veStr.minor = PROTOCOL_VERSION_MINOR;

				/* send back the response */
				WRITE_BODY(veStr)
			}
			break;

			case CMD_GET_READERS_STATE:
			{
				/* nothing to read */

				/* dump the readers state */
				ret = SHMMessageSend(readerStates, sizeof(readerStates), filedes, PCSCLITE_WRITE_TIMEOUT);
			}
			break;

			case CMD_WAIT_READER_STATE_CHANGE:
			{
				struct wait_reader_state_change waStr;

				READ_BODY(waStr)

				/* add the client fd to the list */
				EHRegisterClientForEvent(filedes);

				/* We do not send anything here.
				 * Either the client will timeout or the server will
				 * answer if an event occurs */
			}
			break;

			case CMD_STOP_WAITING_READER_STATE_CHANGE:
			{
				struct wait_reader_state_change waStr;

				READ_BODY(waStr)

				/* add the client fd to the list */
				waStr.rv = EHUnregisterClientForEvent(filedes);

				WRITE_BODY(waStr)
			}
			break;

			case SCARD_ESTABLISH_CONTEXT:
			{
				struct establish_struct esStr;
				SCARDCONTEXT hContext;

				READ_BODY(esStr)

				hContext = esStr.hContext;
				esStr.rv = SCardEstablishContext(esStr.dwScope, 0, 0, &hContext);
				esStr.hContext = hContext;

				if (esStr.rv == SCARD_S_SUCCESS)
					esStr.rv =
						MSGAddContext(esStr.hContext, threadContext);

				WRITE_BODY(esStr)
			}
			break;

			case SCARD_RELEASE_CONTEXT:
			{
				struct release_struct reStr;

				READ_BODY(reStr)

				reStr.rv = SCardReleaseContext(reStr.hContext);

				if (reStr.rv == SCARD_S_SUCCESS)
					reStr.rv =
						MSGRemoveContext(reStr.hContext, threadContext);

				WRITE_BODY(reStr)
			}
			break;

			case SCARD_CONNECT:
			{
				struct connect_struct coStr;
				SCARDHANDLE hCard;
				DWORD dwActiveProtocol;

				READ_BODY(coStr)

				hCard = coStr.hCard;
				dwActiveProtocol = coStr.dwActiveProtocol;

				coStr.rv = SCardConnect(coStr.hContext, coStr.szReader,
						coStr.dwShareMode, coStr.dwPreferredProtocols,
						&hCard, &dwActiveProtocol);

				coStr.hCard = hCard;
				coStr.dwActiveProtocol = dwActiveProtocol;

				if (coStr.rv == SCARD_S_SUCCESS)
					coStr.rv =
						MSGAddHandle(coStr.hContext, coStr.hCard, threadContext);

				WRITE_BODY(coStr)
			}
			break;

			case SCARD_RECONNECT:
			{
				struct reconnect_struct rcStr;
				DWORD dwActiveProtocol;

				READ_BODY(rcStr)

				if (MSGCheckHandleAssociation(rcStr.hCard, threadContext))
					goto exit;

				rcStr.rv = SCardReconnect(rcStr.hCard, rcStr.dwShareMode,
						rcStr.dwPreferredProtocols,
						rcStr.dwInitialization, &dwActiveProtocol);
				rcStr.dwActiveProtocol = dwActiveProtocol;

				WRITE_BODY(rcStr)
			}
			break;

			case SCARD_DISCONNECT:
			{
				struct disconnect_struct diStr;
				LONG rv;

				READ_BODY(diStr)

				rv = MSGCheckHandleAssociation(diStr.hCard, threadContext);
				if (0 == rv)
				{
					diStr.rv = SCardDisconnect(diStr.hCard, diStr.dwDisposition);

					if (SCARD_S_SUCCESS == diStr.rv)
						diStr.rv =
							MSGRemoveHandle(diStr.hCard, threadContext);
				}

				WRITE_BODY(diStr)
			}
			break;

			case SCARD_BEGIN_TRANSACTION:
			{
				struct begin_struct beStr;
				LONG rv;

				READ_BODY(beStr)

				rv = MSGCheckHandleAssociation(beStr.hCard, threadContext);
				if (0 == rv)
					beStr.rv = SCardBeginTransaction(beStr.hCard);

				WRITE_BODY(beStr)
			}
			break;

			case SCARD_END_TRANSACTION:
			{
				struct end_struct enStr;
				LONG rv;

				READ_BODY(enStr)

				rv = MSGCheckHandleAssociation(enStr.hCard, threadContext);
				if (0 == rv)
					enStr.rv =
						SCardEndTransaction(enStr.hCard, enStr.dwDisposition);

				WRITE_BODY(enStr)
			}
			break;

			case SCARD_CANCEL_TRANSACTION:
			{
				struct cancel_transaction_struct caStr;
				LONG rv;

				READ_BODY(caStr)

				rv = MSGCheckHandleAssociation(caStr.hCard, threadContext);
				if (0 == rv)
					caStr.rv = SCardCancelTransaction(caStr.hCard);

				WRITE_BODY(caStr)
			}
			break;

			case SCARD_CANCEL:
			{
				struct cancel_struct caStr;
				SCONTEXT * psTargetContext = NULL;
				READ_BODY(caStr)

				/* find the client */
				psTargetContext = (SCONTEXT *) list_seek(&contextsList,
					&(caStr.hContext));
				if (psTargetContext != NULL)
				{
					uint32_t fd = psTargetContext->dwClientID;
					caStr.rv = MSGSignalClient(fd, SCARD_E_CANCELLED);
				}
				else
					caStr.rv = SCARD_E_INVALID_HANDLE;

				WRITE_BODY(caStr)
			}
			break;

			case SCARD_STATUS:
			{
				struct status_struct stStr;
				LONG rv;

				READ_BODY(stStr)

				rv = MSGCheckHandleAssociation(stStr.hCard, threadContext);
				if (0 == rv)
				{
					DWORD cchReaderLen;
					DWORD dwState;
					DWORD dwProtocol;
					DWORD cbAtrLen;

					cchReaderLen = stStr.pcchReaderLen;
					dwState = stStr.dwState;
					dwProtocol = stStr.dwProtocol;
					cbAtrLen = stStr.pcbAtrLen;

					/* avoids buffer overflow */
					if ((cchReaderLen > sizeof(stStr.mszReaderNames))
						|| (cbAtrLen > sizeof(stStr.pbAtr)))
					{
						stStr.rv = SCARD_E_INSUFFICIENT_BUFFER ;
					}
					else
					{
						stStr.rv = SCardStatus(stStr.hCard,
							stStr.mszReaderNames,
							&cchReaderLen, &dwState,
							&dwProtocol, stStr.pbAtr, &cbAtrLen);

						stStr.pcchReaderLen = cchReaderLen;
						stStr.dwState = dwState;
						stStr.dwProtocol = dwProtocol;
						stStr.pcbAtrLen = cbAtrLen;
					}
				}

				WRITE_BODY(stStr)
			}
			break;

			case SCARD_TRANSMIT:
			{
				struct transmit_struct trStr;
				unsigned char pbSendBuffer[MAX_BUFFER_SIZE_EXTENDED];
				unsigned char pbRecvBuffer[MAX_BUFFER_SIZE_EXTENDED];
				SCARD_IO_REQUEST ioSendPci;
				SCARD_IO_REQUEST ioRecvPci;
				DWORD cbRecvLength;

				READ_BODY(trStr)

				if (MSGCheckHandleAssociation(trStr.hCard, threadContext))
					goto exit;

				/* avoids buffer overflow */
				if ((trStr.pcbRecvLength > sizeof(pbRecvBuffer))
					|| (trStr.cbSendLength > sizeof(pbSendBuffer)))
					goto exit;

				/* read sent buffer */
				ret = SHMMessageReceive(SCARD_TRANSMIT, pbSendBuffer, trStr.cbSendLength,
					filedes, PCSCLITE_READ_TIMEOUT);
				if (ret < 0)
				{
					Log2(PCSC_LOG_DEBUG, "Client die: %d", filedes);
					goto exit;
				}

				ioSendPci.dwProtocol = trStr.ioSendPciProtocol;
				ioSendPci.cbPciLength = trStr.ioSendPciLength;
				ioRecvPci.dwProtocol = trStr.ioRecvPciProtocol;
				ioRecvPci.cbPciLength = trStr.ioRecvPciLength;
				cbRecvLength = trStr.pcbRecvLength;

				trStr.rv = SCardTransmit(trStr.hCard, &ioSendPci,
					pbSendBuffer, trStr.cbSendLength, &ioRecvPci,
					pbRecvBuffer, &cbRecvLength);

				trStr.ioSendPciProtocol = ioSendPci.dwProtocol;
				trStr.ioSendPciLength = ioSendPci.cbPciLength;
				trStr.ioRecvPciProtocol = ioRecvPci.dwProtocol;
				trStr.ioRecvPciLength = ioRecvPci.cbPciLength;
				trStr.pcbRecvLength = cbRecvLength;

				WRITE_BODY(trStr)

				/* write received buffer */
				if (SCARD_S_SUCCESS == trStr.rv)
					ret = SHMMessageSend(pbRecvBuffer, cbRecvLength,
						filedes, PCSCLITE_WRITE_TIMEOUT);
			}
			break;

			case SCARD_CONTROL:
			{
				struct control_struct ctStr;
				unsigned char pbSendBuffer[MAX_BUFFER_SIZE_EXTENDED];
				unsigned char pbRecvBuffer[MAX_BUFFER_SIZE_EXTENDED];
				DWORD dwBytesReturned;

				READ_BODY(ctStr)

				if (MSGCheckHandleAssociation(ctStr.hCard, threadContext))
					goto exit;

				/* avoids buffer overflow */
				if ((ctStr.cbRecvLength > sizeof(pbRecvBuffer))
					|| (ctStr.cbSendLength > sizeof(pbSendBuffer)))
				{
					goto exit;
				}

				/* read sent buffer */
				ret = SHMMessageReceive(SCARD_CONTROL, pbSendBuffer, ctStr.cbSendLength,
					filedes, PCSCLITE_READ_TIMEOUT);
				if (ret < 0)
				{
					Log2(PCSC_LOG_DEBUG, "Client die: %d", filedes);
					goto exit;
				}

				dwBytesReturned = ctStr.dwBytesReturned;

				ctStr.rv = SCardControl(ctStr.hCard, ctStr.dwControlCode,
					pbSendBuffer, ctStr.cbSendLength,
					pbRecvBuffer, ctStr.cbRecvLength,
					&dwBytesReturned);

				ctStr.dwBytesReturned = dwBytesReturned;

				WRITE_BODY(ctStr)

				/* write received buffer */
				if (SCARD_S_SUCCESS == ctStr.rv)
					ret = SHMMessageSend(pbRecvBuffer, dwBytesReturned,
						filedes, PCSCLITE_WRITE_TIMEOUT);
			}
			break;

			case SCARD_GET_ATTRIB:
			{
				struct getset_struct gsStr;
				DWORD cbAttrLen;

				READ_BODY(gsStr)

				if (MSGCheckHandleAssociation(gsStr.hCard, threadContext))
					goto exit;

				/* avoids buffer overflow */
				if (gsStr.cbAttrLen > sizeof(gsStr.pbAttr))
					goto buffer_overflow;

				cbAttrLen = gsStr.cbAttrLen;

				gsStr.rv = SCardGetAttrib(gsStr.hCard, gsStr.dwAttrId,
						gsStr.pbAttr, &cbAttrLen);

				gsStr.cbAttrLen = cbAttrLen;

				WRITE_BODY(gsStr)
			}
			break;

			case SCARD_SET_ATTRIB:
			{
				struct getset_struct gsStr;

				READ_BODY(gsStr)

				if (MSGCheckHandleAssociation(gsStr.hCard, threadContext))
					goto buffer_overflow;

				/* avoids buffer overflow */
				if (gsStr.cbAttrLen > sizeof(gsStr.pbAttr))
					goto buffer_overflow;

				gsStr.rv = SCardSetAttrib(gsStr.hCard, gsStr.dwAttrId,
					gsStr.pbAttr, gsStr.cbAttrLen);

				WRITE_BODY(gsStr)
			}
			break;

			default:
				Log2(PCSC_LOG_CRITICAL, "Unknown command: %d", header.command);
				goto exit;
		}

		/* SHMMessageSend() failed */
		if (-1 == ret)
		{
			/* Clean up the dead client */
			Log2(PCSC_LOG_DEBUG, "Client die: %d", filedes);
			goto exit;
		}
	}

buffer_overflow:
	Log2(PCSC_LOG_DEBUG, "Buffer overflow detected: %d", filedes);
	goto exit;
wrong_length:
	Log2(PCSC_LOG_DEBUG, "Wrong length: %d", filedes);
exit:
	(void)SYS_CloseFile(filedes);
	(void)MSGCleanupClient(threadContext);
	(void)SYS_ThreadExit((LPVOID) NULL);
}

LONG MSGSignalClient(uint32_t filedes, LONG rv)
{
	uint32_t ret;
	struct wait_reader_state_change waStr;

	Log2(PCSC_LOG_DEBUG, "Signal client: %d", filedes);

	waStr.rv = rv;
	WRITE_BODY(waStr)

	return ret;
} /* MSGSignalClient */

static LONG MSGAddContext(SCARDCONTEXT hContext, SCONTEXT * threadContext)
{
	threadContext->hContext = hContext;
	return SCARD_S_SUCCESS;
}

static LONG MSGRemoveContext(SCARDCONTEXT hContext, SCONTEXT * threadContext)
{
	LONG rv;
	int lrv;

	if (threadContext->hContext != hContext)
		return SCARD_E_INVALID_VALUE;

	while (list_size(&(threadContext->cardsList)) != 0)
	{
		READER_CONTEXT * rContext = NULL;
		SCARDHANDLE hCard, hLockId;
		void *ptr;

		/*
		 * Disconnect each of these just in case
		 */
		ptr = list_get_at(&(threadContext->cardsList), 0);
		if (NULL == ptr)
		{
			Log1(PCSC_LOG_CRITICAL, "list_get_at failed");
			continue;
		}
		hCard = *(int32_t *)ptr;

		/*
		 * Unlock the sharing
		 */
		rv = RFReaderInfoById(hCard, &rContext);
		if (rv != SCARD_S_SUCCESS)
			return rv;

		hLockId = rContext->hLockId;
		rContext->hLockId = 0;

		if (hCard != hLockId)
		{
			/*
			 * if the card is locked by someone else we do not reset it
			 * and simulate a card removal
			 */
			rv = SCARD_W_REMOVED_CARD;
		}
		else
		{
			/*
			 * We will use SCardStatus to see if the card has been
			 * reset there is no need to reset each time
			 * Disconnect is called
			 */
			rv = SCardStatus(hCard, NULL, NULL, NULL, NULL, NULL, NULL);
		}

		if (rv == SCARD_W_RESET_CARD || rv == SCARD_W_REMOVED_CARD)
			(void)SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		else
			(void)SCardDisconnect(hCard, SCARD_RESET_CARD);

		/* Remove entry from the list */
		lrv = list_delete_at(&(threadContext->cardsList), 0);
		if (lrv < 0)
			Log2(PCSC_LOG_CRITICAL,
				"list_delete_at failed with return value: %X", lrv);
	}
	list_destroy(&(threadContext->cardsList))	;

	/* We only mark the context as no longer in use.
	 * The memory is freed in MSGCleanupCLient() */
	threadContext->hContext = 0;

	return SCARD_S_SUCCESS;
}

static LONG MSGAddHandle(SCARDCONTEXT hContext, SCARDHANDLE hCard,
	SCONTEXT * threadContext)
{
	if (threadContext->hContext == hContext)
	{
		/*
		 * Find an empty spot to put the hCard value
		 */
		int listLength, lrv;

		listLength = list_size(&(threadContext->cardsList));
		if (listLength >= contextMaxCardHandles)
		{
			Log4(PCSC_LOG_DEBUG, "Too many card handles for thread context @%X: %d (max is %d)"
				"Restart pcscd with --max-card-handle-per-thread value",
				threadContext, listLength, contextMaxCardHandles);
			return SCARD_E_NO_MEMORY;
		}

		lrv = list_append(&(threadContext->cardsList), &hCard);
		if (lrv < 0)
		{
			Log2(PCSC_LOG_CRITICAL, "list_append failed with return value: %X",
				lrv);
			return SCARD_E_NO_MEMORY;
		}
		return SCARD_S_SUCCESS;
	}

	return SCARD_E_INVALID_VALUE;
}

static LONG MSGRemoveHandle(SCARDHANDLE hCard, SCONTEXT * threadContext)
{
	int lrv;

	lrv = list_delete(&(threadContext->cardsList), &hCard);
	if (lrv < 0)
	{
		Log2(PCSC_LOG_CRITICAL, "list_delete failed with error %X", lrv);
		return SCARD_E_INVALID_VALUE;
	}

	return SCARD_S_SUCCESS;
}


static LONG MSGCheckHandleAssociation(SCARDHANDLE hCard, SCONTEXT * threadContext)
{
	int list_index = 0;
	list_index = list_locate(&(threadContext->cardsList), &hCard);
	if (list_index >= 0)
		return 0;

	/* Must be a rogue client, debug log and sleep a couple of seconds */
	Log1(PCSC_LOG_ERROR, "Client failed to authenticate");
	(void)SYS_Sleep(2);

	return -1;
}


/* Should be called just prior to exiting the thread as it de-allocates
 * the thread memory strucutres
 */
static LONG MSGCleanupClient(SCONTEXT * threadContext)
{
	int lrv;

	if (threadContext->hContext != 0)
	{
		(void)SCardReleaseContext(threadContext->hContext);
		(void)MSGRemoveContext(threadContext->hContext, threadContext);
	}

	Log3(PCSC_LOG_DEBUG,
		"Thread is stopping: dwClientID=%d, threadContext @%X",
		threadContext->dwClientID, threadContext);

	/* Clear the struct to ensure that we detect
	 * access to de-allocated memory
	 * Hopefully the compiler won't optimise it out */
	memset((void*) threadContext, 0, sizeof(SCONTEXT));
	Log2(PCSC_LOG_DEBUG, "Freeing SCONTEXT @%X", threadContext);

	lrv = list_delete(&contextsList, threadContext);
	if (lrv < 0)
		Log2(PCSC_LOG_CRITICAL, "list_delete failed with error %x", lrv);

	free(threadContext);

	/* start a suicide alarm */
	if (AutoExit && (list_size(&contextsList) < 1))
	{
		Log2(PCSC_LOG_DEBUG, "Starting suicide alarm in %d seconds",
			TIME_BEFORE_SUICIDE);
		alarm(TIME_BEFORE_SUICIDE);
	}

	return 0;
}
