/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2001-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludoic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This is responsible for client/server communication.
 *
 * A file based socket (\c commonSocket) is used to send/receive only messages
 * among clients and server.\n
 * The messages' data are passed throw a memory mapped file: \c sharedSegmentMsg.
 */

#include "config.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <stdlib.h>
#include <ucred.h>
#include <thread.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_DOOR_H
#include <door.h>
#endif

#include "misc.h"
#include "pcsclite.h"
#include "pcsc_config.h"
#include "winscard.h"
#include "clientcred.h"
#include "debug.h"
#include "winscard_msg.h"
#include "sys_generic.h"

#define CONNECT_TIMEOUT 30

int MessageSendSocket(void *, size_t,int, int);
int MessageReceiveSocket(void *, size_t, int, int);
int MessageSendDoor(void *, size_t,int, int);
int MessageReceiveDoor(void *, size_t, int, int);

void dumpContexts();


static PCSCLITE_MUTEX fdMutex[256];
static PCSCLITE_MUTEX clientSessionMutex = PTHREAD_MUTEX_INITIALIZER;


void traceback();


/**
 * @brief Wrapper for the SHMMessageReceive() function.
 *
 * Called by clients to read the server responses.
 *
 * @param[out] msgStruct Message read.
 * @param[in] dwClientID Client socket handle.
 * @param[in] blockamount Timeout in milliseconds.
 *
 * @return Same error codesj as SHMMessageReceive().
 */
INTERNAL int SHMClientRead(psharedSegmentMsg msgStruct, DWORD dwClientID, int blockamount)
{
	return SHMMessageReceive(msgStruct, sizeof(*msgStruct), dwClientID, blockamount);
}


/**
 * @brief Prepares a communication channel for the client to talk to the server.
 *
 * This is called by the application to create a socket for local IPC with the
 * server. The socket is associated to the file \c PCSCLITE_CSOCK_NAME by default
 * but this can be overridden in the global configuration file pcscd.conf, and
 * affected by the -b or INSTANCE_BASE_DIR key-value setting in pcscd.conf
 *
 * @param[out] pdwClientID Client Connection ID.
 *
 * @retval 0 Success.
 * @retval -1 Can not create the socket.
 * @retval -1 The socket can not open a connection.
 * @retval -1 Can not set the socket to non-blocking.
 */
INTERNAL int SHMClientSetupSession(PDWORD pdwClientID)
{
	int rv;

	SYS_MutexLock(&clientSessionMutex);
	switch(pcscCfg.transportType) {
	case SOCKET_UNIX:
	    {
		struct sockaddr_un svc_addr;
		int one;
		if ((*pdwClientID = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)  {
			Log2(PCSC_LOG_CRITICAL, "Error: create on client socket: %s",
				strerror(errno));
			SYS_MutexUnLock(&clientSessionMutex);
			return -1;
		}

		SYS_MutexLock(&fdMutex[*pdwClientID]);

		svc_addr.sun_family = AF_UNIX;
		strncpy(svc_addr.sun_path, pcscCfg.netBindFile,
			sizeof(svc_addr.sun_path));

		if ((rv = connect(*pdwClientID, (struct sockaddr *) &svc_addr,
			sizeof(svc_addr.sun_family) +
			strlen(svc_addr.sun_path) + 1)) < 0) {
				Log2(PCSC_LOG_CRITICAL,
				     "Error: connect to client socket: %s",
				     strerror(errno));
				SYS_CloseFile(*pdwClientID);
				SYS_MutexUnLock(&clientSessionMutex);
				SYS_MutexUnLock(&fdMutex[*pdwClientID]);
				return -1;
		}

		one = 1;
		if (ioctl(*pdwClientID, FIONBIO, &one) < 0)  {
			Log2(PCSC_LOG_CRITICAL,
			    "Error: cannot set socket nonblocking: %s",
			    strerror(errno));
			SYS_CloseFile(*pdwClientID);
			SYS_MutexUnLock(&clientSessionMutex);
			SYS_MutexUnLock(&fdMutex[*pdwClientID]);

			return -1;
		}
		SYS_MutexUnLock(&fdMutex[*pdwClientID]);
		break;

	    }
	case SOCKET_INETV4:
	    {
		union {
		     struct sockaddr s;
		     struct sockaddr_in i;
		} serv_addr;
		int one;
		struct linger l = {0, 0};
		int sndbufsize = 4096;
		int rcvbufsize = 4096;
		l.l_onoff  = 1;
		l.l_linger = 0;

		if ((*pdwClientID = socket(AF_INET, SOCK_STREAM, 0)) < 0)  {
			Log2(PCSC_LOG_CRITICAL,
				"Error: create on client socket: %s",
				strerror(errno));
			SYS_MutexUnLock(&clientSessionMutex);
			return -1;
		}

		if (setsockopt(*pdwClientID, SOL_SOCKET, SO_LINGER,
		     &l, sizeof (l)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_LINGER: %s", strerror(errno));
			return -1;
		}
		if (setsockopt(*pdwClientID, SOL_SOCKET, SO_SNDBUF,
		     &sndbufsize, sizeof (sndbufsize)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_SNDBUF: %s", strerror(errno));
			return -1;
		}
		if (setsockopt(*pdwClientID, SOL_SOCKET, SO_RCVBUF,
		     &rcvbufsize, sizeof (rcvbufsize)) < 0) {
			Log2(PCSC_LOG_CRITICAL,
			    "setsockopt()/SO_RCVBUF: %s", strerror(errno));
			return -1;
		}

		SYS_MutexLock(&fdMutex[*pdwClientID]);

		serv_addr.i.sin_family = AF_INET;
		serv_addr.i.sin_port = htons(pcscCfg.portNbr);
		bcopy((char *)&pcscCfg.xHostIp, (char *)&serv_addr.i.sin_addr.s_addr,
		     sizeof (pcscCfg.xHostIp));


		if ((rv = connect(*pdwClientID, &serv_addr.s, sizeof (serv_addr))) < 0) {
			int errcnt = 0;
			// If EADDRUSE encountered re-try in case system socket resources
			// are temporarily exhausted
			while (rv < 0 &&
				(errno == EADDRINUSE || errno == EINTR || errno == EAGAIN)
				&& errcnt++ < 100) {
					usleep(50000);
					rv = connect(*pdwClientID, &serv_addr.s, sizeof (serv_addr));
			}
			if (rv < 0) {
				Log3(PCSC_LOG_INFO,
				"SHMClientSetupSession: Server connect err:\n%d: %s",
				errno, strerror(errno));
				SYS_CloseFile(*pdwClientID);
				SYS_MutexUnLock(&clientSessionMutex);
				SYS_MutexUnLock(&fdMutex[*pdwClientID]);
				return -1;
			}
		}

		Log3(PCSC_LOG_DEBUG,
			"SHMClientSetupSession(%d) thr:%x",
			*pdwClientID, thr_self());

#ifdef PCSCLITE_PORTSVC_PORTNO
		/*
		 * If we're in daemon launcher mode, we need to
		 * identify the display we need to contact.  If the launcher
		 * can't authenticate us, it will shut down the connection
		 * immediately.
		 */
		if (pcscCfg.launchMode == LAUNCHER) {
			char buf[256];
			char *ipaddr =  inet_ntoa(*(struct in_addr *)&pcscCfg.xHostIp);
			sprintf(buf, "%s:%d.%d\r", ipaddr, pcscCfg.dpyNbr, pcscCfg.screenNbr);
			 if (pcscCfg.logLevel == DEBUG) {
				Log2(PCSC_LOG_DEBUG,
				    "[Client send connect msg to launcher]: %s\n",
				    buf);
				Log2(PCSC_LOG_DEBUG,
					"Waiting for %d secs for reply from launcher",
					CONNECT_TIMEOUT);

			 }
			 /*
			 * Read reply from launcher
			 */
			write(*pdwClientID, buf, strlen(buf));
			{
				fd_set read_fd;
				struct timeval tv;
				int rv;
				tv.tv_sec = CONNECT_TIMEOUT;
				tv.tv_usec = 0;

				FD_ZERO(&read_fd);
				FD_SET(*pdwClientID, &read_fd);

				rv = select(*pdwClientID + 1, &read_fd, NULL, NULL, &tv);
				if (rv < 0) {
					while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
						usleep(50000);
						rv = select(*pdwClientID + 1, &read_fd, NULL, NULL, &tv);
					}
					if (rv < 0) {
						Log2(PCSC_LOG_CRITICAL,
						    "Launcher reply select() error: %s",
						    strerror(errno));
						SYS_CloseFile(*pdwClientID);
						SYS_MutexUnLock(&clientSessionMutex);
						SYS_MutexUnLock(&fdMutex[*pdwClientID]);
						return -1;      // Error
					}
				} else if (rv == 0) {
					Log2(PCSC_LOG_INFO,
					    "Launcher reply timed out after %d sec.",
					    CONNECT_TIMEOUT);
					SYS_CloseFile(*pdwClientID);
					SYS_MutexUnLock(&clientSessionMutex);
					SYS_MutexUnLock(&fdMutex[*pdwClientID]);
					return -1;      // Timeout
				}

				if (FD_ISSET(*pdwClientID, &read_fd)) {
					if ((rv = read(*pdwClientID, buf, sizeof (buf))) < 0) {
						while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
							usleep(50000);
							rv = read(*pdwClientID, buf, sizeof (buf));
						}
						if (rv < 0) {
							Log3(PCSC_LOG_INFO,
							    "read() err on launcher reply after select(fd=%d): %s",
							    *pdwClientID, strerror(errno));
							SYS_MutexUnLock(&clientSessionMutex);
							SYS_MutexUnLock(&fdMutex[*pdwClientID]);
							return -1;      // Error
						}
					}
				}
			}
			if (pcscCfg.logLevel == DEBUG) {
				Log2(PCSC_LOG_DEBUG,
				    "[Client received handshake from instance]:\n%s", buf);
			}
			if (strncmp(buf, CONNECTOK, strlen(CONNECTOK)) != 0) {
				Log1(PCSC_LOG_INFO,
					"Error: Didn't get CONNECT OK message from instance.");
				Log2(PCSC_LOG_INFO,
					"Received following buffer instead:\n%s", buf);
				Log2(PCSC_LOG_INFO,
					"Closing FD: %d", *pdwClientID);
				SYS_CloseFile(*pdwClientID);
				SYS_MutexUnLock(&clientSessionMutex);
				SYS_MutexUnLock(&fdMutex[*pdwClientID]);
				return -1;
			}
		}
#endif
		one = 1;
		if (ioctl(*pdwClientID, FIONBIO, &one) < 0)  {
			Log2(PCSC_LOG_CRITICAL,
				"Error: cannot set socket nonblocking: %s",
				strerror(errno));
			SYS_CloseFile(*pdwClientID);
			SYS_MutexUnLock(&clientSessionMutex);
			SYS_MutexUnLock(&fdMutex[*pdwClientID]);
			return -1;
		}
		break;
	    }
	}

	SYS_MutexUnLock(&clientSessionMutex);
	SYS_MutexUnLock(&fdMutex[*pdwClientID]);
	return 0;
}

/**
 * @brief Closes the socket used by the client to communicate with the server.
 *
 * @param[in] dwClientID Client socket handle to be closed.
 *
 * @retval 0 Success.
 */
INTERNAL int SHMClientCloseSession(DWORD dwClientID)
{
	Log3(PCSC_LOG_DEBUG,
		"SHMClientCloseSession(%d) thr:%x", dwClientID, thr_self());
	SYS_MutexLock(&clientSessionMutex);
	SYS_MutexLock(&fdMutex[dwClientID]);
	SYS_CloseFile(dwClientID);
	SYS_MutexUnLock(&clientSessionMutex);
	SYS_MutexUnLock(&fdMutex[dwClientID]);
	return 0;
}


/**
 * @brief Sends a menssage over UNIX or INETV4 domain socket
 *
 * Writes the message in the shared file \c filedes.
 *
 * @param[in] buffer Message to be sent.
 * @param[in] buffer_size Size of the message to send
 * @param[in] filedes Socket handle.
 * @param[in] blockAmount Timeout in milliseconds.
 *
 * @retval 0 Success
 * @retval -1 Timeout.
 * @retval -1 Socket is closed.
 * @retval -1 A signal was received.
 */

INTERNAL int SHMMessageSend(void *buffer, size_t buffer_size,
	int filedes, int blockAmount)

{
	char *pBuf = (char *)buffer;
	SYS_MutexLock(&fdMutex[filedes]);

	/*
	 * default is success
	 */
	int retval = 0;
	/*
	 * record the time when we started
	 */
	time_t start = time(0);
	/*
	 * how many bytes remains to be written
	 */
	size_t remaining = buffer_size;

	/*
	 * repeat until all data is written
	 */
	while (remaining > 0)
	{
		fd_set write_fd;
		struct timeval timeout;
		int selret;

		FD_ZERO(&write_fd);
		FD_SET(filedes, &write_fd);

		timeout.tv_usec = 0;
		if ((timeout.tv_sec = start + blockAmount - time(0)) < 0)
		{
			/*
			 * we already timed out
			 */
			errno = ETIMEDOUT;
			retval = -1;
			break;
		}

		selret = select(filedes + 1, NULL, &write_fd, NULL, &timeout);

		/*
		 * try to write only when the file descriptor is writable
		 */
		if (selret > 0)
		{
			int written;

			if (!FD_ISSET(filedes, &write_fd))
			{
				/*
				 * very strange situation. it should be an assert really
				 */
				retval = -1;
				break;
			}
			written = write(filedes, pBuf, remaining);

			if (written > 0)
			{
				/*
				 * we wrote something
				 */
				pBuf += written;
				remaining -= written;
			} else if (written == 0)
			{
				/*
				 * peer closed the socket
				 */
				errno = ECONNRESET;
				retval = -1;
				break;
			} else
			{
				/*
				 * we ignore the signals and socket full situations, all
				 * other errors are fatal
				 */
				if (errno != EINTR && errno != EAGAIN)
				{
					retval = -1;
					break;
				}
			}
		} else if (selret == 0)
		{
			/*
			 * timeout
			 */
			errno = ETIMEDOUT;
			retval = -1;
			break;
		} else
		{
			/*
			 * ignore signals
			 */
			if (errno != EINTR)
			{
				Log4(PCSC_LOG_ERROR,
					"select(fd=%d) thr=%x returns with failure: %s",
					filedes, thr_self(), strerror(errno));
				traceback(thr_self());
				dumpContexts();
				retval = -1;
				break;
			}
		}
	}
	SYS_MutexUnLock(&fdMutex[filedes]);
	return retval;
}


/**
 * @brief Receives a menssage over UNIX or INETV4 domain socket
 *
 * Writes the message in the shared file \c filedes.
 *
 * @param[in] buffer Message to be sent.
 * @param[in] buffer_size Size of the message to send
 * @param[in] filedes Socket handle.
 * @param[in] blockAmount Timeout in milliseconds.
 *
 * @retval 0 Success
 * @retval -1 Timeout.
 * @retval -1 Socket is closed.
 * @retval -1 A signal was received.
 */
INTERNAL int SHMMessageReceive(void *buffer, size_t buffer_size,
	int filedes, int blockAmount)
{
	char *pBuf = (char *)buffer;

	SYS_MutexLock(&fdMutex[filedes]);

	/*
	 * default is success
	 */
	int retval = 0;
	/*
	 * record the time when we started
	 */
	time_t start = time(0);
	/*
	 * how many bytes we must read
	 */
	size_t remaining = buffer_size;

	/*
	 * repeate until we get the whole message
	 */
	while (remaining > 0)
	{
		fd_set read_fd;
		struct timeval timeout;
		int selret;

		FD_ZERO(&read_fd);
		FD_SET(filedes, &read_fd);

		timeout.tv_usec = 0;
		if ((timeout.tv_sec = start + blockAmount - time(0)) < 0)
		{
			/*
			 * we already timed out
			 */
			errno = ETIMEDOUT;
			retval = -1;
			break;
		}

		selret = select(filedes + 1, &read_fd, NULL, NULL, &timeout);

		/*
		 * try to read only when socket is readable
		 */
		if (selret > 0)
		{
			int readed;

			if (!FD_ISSET(filedes, &read_fd))
			{
				/*
				 * very strange situation. it should be an assert really
				 */
				Log2(PCSC_LOG_CRITICAL,
					"SHMMessageReceive(fd=%d): Unexpected select() result",
					filedes);
				retval = -1;
				break;
			}
			readed = read(filedes, pBuf, remaining);

			if (readed > 0)
			{
				/*
				 * we got something
				 */
				pBuf += readed;
				remaining -= readed;
			} else if (readed == 0)
			{
				/*
				 * peer closed the socket
				 */
				errno = ECONNRESET;
				retval = -1;
				break;
			} else
			{
				/*
				 * we ignore the signals and empty socket situations, all
				 * other errors are fatal
				 */
				if (errno != EINTR && errno != EAGAIN)
				{
					retval = -1;
					break;
				}
			}
		} else if (selret == 0)
		{
			/*
			 * timeout
			 */
			retval = -1;
			errno = ETIMEDOUT;
			break;
		} else
		{
			/*
			 * we ignore signals, all other errors are fatal
			 */
			if (errno != EINTR)
			{
				Log4(PCSC_LOG_ERROR,
					"SHMMessageReceive(): select(fd=%d) thr:%x, failed: %s",
					filedes, thr_self(), strerror(errno));
				traceback(thr_self());
				dumpContexts();
				retval = -1;
				break;
			}
		}
	}
	SYS_MutexUnLock(&fdMutex[filedes]);
	return retval;
}


/**
 * @brief Wrapper for the SHMMessageSend() function.
 *
 * Called by clients to send messages to the server.
 * The parameters \p command and \p data are set in the \c sharedSegmentMsg
 * struct in order to be sent.
 *
 * @param[in] command Command to be sent.
 * @param[in] dwClientID Client socket handle.
 * @param[in] size Size of the message (\p data).
 * @param[in] blockAmount Timeout to the operation in ms.
 * @param[in] data Data to be sent.
 *
 * @return Same error codes as SHMMessageSend().
 */
INTERNAL int WrapSHMWrite(unsigned int command, DWORD dwClientID,
	unsigned int size, unsigned int blockAmount, void *data)
{
	sharedSegmentMsg msgStruct;
	int ret;
	char *pData = data;

	/*
	 * Set the appropriate packet parameters
	 */

	memset(&msgStruct, 0, sizeof(msgStruct));
	msgStruct.mtype = CMD_FUNCTION;
	msgStruct.user_id = SYS_GetUID();
	msgStruct.group_id = SYS_GetGID();
	msgStruct.command = command;
	msgStruct.date = time(NULL);
	if (SCARD_TRANSMIT_EXTENDED == command)
	{
		/* first block */
		memcpy(msgStruct.data, pData, PCSCLITE_MAX_MESSAGE_SIZE);
		ret = SHMMessageSend(&msgStruct, sizeof(msgStruct), dwClientID,
			blockAmount);
		if (ret)
			return ret;

		/* do not send an empty second block */
		if (size > PCSCLITE_MAX_MESSAGE_SIZE)
		{
			/* second block */
			ret = SHMMessageSend(pData+PCSCLITE_MAX_MESSAGE_SIZE,
				size-PCSCLITE_MAX_MESSAGE_SIZE, dwClientID, blockAmount);
			if (ret)
				return ret;
		}
	}
	else
	{
		memcpy(msgStruct.data, pData, size);

		ret = SHMMessageSend(&msgStruct, sizeof(msgStruct), dwClientID,
			blockAmount);
	}
	return ret;
}

/*
 * @brief Does a remote procedure call based on transport type.
 *
 * This is called by the client to invoke a function on the server.
 *
 * @param command
 * @param dwClientID
 * @param pData
 * @param size
 * @param blockAmount
 * @param pMutex
 */
INTERNAL int SHMrpc(unsigned int command, DWORD dwClientID,
		    void *pData, unsigned int size)
{
	sharedSegmentMsg msgStruct;
	int rv;

	switch (pcscCfg.transportType) {
	case SOCKET_UNIX:
	case SOCKET_INETV4:
		/*
		 * Write command describing remote function call to server.
		 */
		if ((rv = WrapSHMWrite(command, dwClientID, size,
		     PCSCLITE_CLIENT_ATTEMPTS, pData)) == -1) {
			Log4(PCSC_LOG_INFO,
			     "SHMrpc(): WrapSHMWrite(fd=%d) returned errno=%d: %s",
			     dwClientID, errno, strerror(errno));
			return -1;
		}
		/*
		 * Read RPC return message from the server
		 */
		bzero(&msgStruct, sizeof (sharedSegmentMsg));
		rv = SHMClientRead(&msgStruct, dwClientID, PCSCLITE_CLIENT_ATTEMPTS);

		/*
		 * Copy received server data back to caller's buffer
		 */
		memcpy(pData, &msgStruct.data, size);

		if (rv == -1) {
			Log4(PCSC_LOG_INFO,
			     "SHMrpc(): SHMClientReader(fd=%d) returned errno=%d: %s",
			     dwClientID, errno, strerror(errno));
			 return -1;
		}
	       break;
	}
	return(0);
}

/**
 * @brief Called by client to peek memory in the server's exportable memory
 *
 *  Build and sends request to server to peek at memory.
 *
 * @param[in] dwClientID Client socket handle.
 * @param[in] addr it the location to store retrieved contents
 * @param[in] offset is the offset into the shared memory to start at.
 * @param[in] size is the length of the memory segment
 *
 * @return Same error codes as SHMMessageSend() or SHMMessageReceive()
 */
INTERNAL int SHMfetchReaderState(PREADER_STATE localReaderState,
				 unsigned int readerStateIdx, DWORD dwClientID) {
	int rv;
	sharedSegmentMsg msgStruct;
	fetch_struct fetch, *pfetch;

	/*
	 * Set up the message type for server-side shared
	 * memory peek
	 */

	memset(&msgStruct, 0, sizeof(msgStruct));
	msgStruct.mtype = CMD_FETCH;
	msgStruct.user_id = SYS_GetUID();
	msgStruct.group_id = SYS_GetGID();
	msgStruct.command = FETCH_READER_STATE;
	msgStruct.date = time(NULL);

	fetch.type.index = readerStateIdx;
	memcpy(msgStruct.data, &fetch, sizeof (struct fetch_struct));
	/*
	 * Send the request
	 */
	rv = SHMMessageSend(&msgStruct, sizeof(msgStruct), dwClientID, 100);
	if (rv < 0) {
		Log2(PCSC_LOG_INFO,
			"SHMfetchReaderState(): SHMMessageSend(fd=%d) failed",
				dwClientID);
		Log3(PCSC_LOG_INFO, "errno: %d: %s",errno, strerror( errno));
		return rv;
	}
	/*
	 * Receive requested memory segment
	 */
	if ((rv = SHMClientRead(&msgStruct, dwClientID, 100)) < 0) {
		Log1(PCSC_LOG_INFO,
			"SHMfetchReaderState(): SHMClientRead() failed.");
		Log3(PCSC_LOG_INFO, "errno=%d: %s", errno, strerror(errno));
		return rv;
	}
	pfetch = (fetch_struct *)msgStruct.data;

	if (pfetch->rv < 0) {
		Log1(PCSC_LOG_INFO,
			"SHMfetchReaderState(): Server got bad request parameters");
		return pfetch->rv;
	}

	/*
	 * Return memory to caller's buffer
	 */
	memcpy(localReaderState, pfetch->data, sizeof (READER_STATE));
	return 0;
}


INTERNAL int SHMCheckProtocolVersion(int major, int minor, DWORD dwClientID)
{

	switch(pcscCfg.transportType) {
	case SOCKET_UNIX:
	case SOCKET_INETV4:
	  {
		  /* exchange client/server protocol versions */
		  sharedSegmentMsg msgStruct;
		  version_struct *veStr;
		  int rv;
		  do {
			memset(&msgStruct, 0, sizeof(msgStruct));
			msgStruct.mtype = CMD_VERSION;
			msgStruct.user_id = SYS_GetUID();
			msgStruct.group_id = SYS_GetGID();
			msgStruct.command = 0;
			msgStruct.date = time(NULL);

			veStr = (version_struct *) msgStruct.data;
			veStr->major = major;
			veStr->minor = minor;

			if ((rv = SHMMessageSend(&msgStruct, sizeof(msgStruct), dwClientID,
				PCSCLITE_MCLIENT_ATTEMPTS)) == -1) {
				Log1(PCSC_LOG_CRITICAL,
					"Error trying sending protocol version request to server: ");
				Log3(PCSC_LOG_CRITICAL,
					"errno=%d: %x", errno, strerror(errno));
				if (errno == EPIPE) {
					Log1(PCSC_LOG_CRITICAL, "Re-trying");
					usleep(250000);
					continue;
				}
				return SCARD_E_NO_SERVICE;
			}

			/*
			 * Read a message from the server
			 */
			if ((rv = SHMMessageReceive(&msgStruct, sizeof(msgStruct), dwClientID,
				PCSCLITE_CLIENT_ATTEMPTS)) == -1) {
				Log1(PCSC_LOG_CRITICAL,
					"Error trying to read protocol version from server: ");
				Log3(PCSC_LOG_CRITICAL,
					"errno=%d: %x", errno, strerror(errno));
				if (errno == EPIPE) {
					Log1(PCSC_LOG_CRITICAL, "Re-trying");
					usleep(250000);
					continue;
				}
				return SCARD_F_COMM_ERROR;
			}

		    } while(rv == -1 && errno == EPIPE);

		    Log3(PCSC_LOG_DEBUG, "Server is protocol version %d:%d",
			veStr->major, veStr->minor);
		    break;
	  }

	}
	return SCARD_S_SUCCESS;
}


/**
 * @brief Closes the communications channel used by the server to talk to the
 * clients.
 *
 * The socket used is closed and the file it is bound to is removed.
 *
 * @param[in] sockValue Socket to be closed.
 * @param[in] pcFilePath File used by the socket.
 */
INTERNAL void SHMCleanupSharedSegment(int sockValue, char *pcFilePath)
{
	Log2(PCSC_LOG_DEBUG, "SHMCleanupSharedSegment(fd=%d)", sockValue);
	SYS_CloseFile(sockValue);
	SYS_Unlink(pcFilePath);
}


/*
 * This is used to determine the availability of the PCSClite
 * service.  It only ping the launcher.
 */
 INTERNAL int SHMping() {
	union {
	     struct sockaddr s;
	     struct sockaddr_in i;
	} serv_addr;
	int one, fd, rv;
	fd_set read_fd;
	struct timeval tv;
	char buf[20], cmp[80];


	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)  {
		Log2(PCSC_LOG_CRITICAL,
			"ping: Error creating client socket: %s",
			strerror(errno));
		return -1;
	}
	serv_addr.i.sin_family = AF_INET;
	serv_addr.i.sin_port = htons(pcscCfg.portNbr);
	bcopy((char *)&pcscCfg.xHostIp, (char *)&serv_addr.i.sin_addr.s_addr,
	     sizeof (pcscCfg.xHostIp));

	if ((rv = connect(fd, &serv_addr.s, sizeof (serv_addr))) < 0) {
		if (rv < 0) {
			while (rv < 0 && (errno == EINTR || errno == EAGAIN)) {
				usleep(50000);
				rv = connect(fd, &serv_addr.s, sizeof (serv_addr));
			}
			if (rv < 0) {
				Log3(PCSC_LOG_INFO,
					"ping: Server connect err:\n%d: %s",
					errno, strerror(errno));
				close(fd);
				return -1;
			}
		}
	}
	bzero(buf, sizeof (buf));
	sprintf(cmp, "PING %d\r", getpid());
	write(fd, cmp, strlen(cmp));

	tv.tv_sec = CONNECT_TIMEOUT;
	tv.tv_usec = 0;

	FD_ZERO(&read_fd);
	FD_SET(fd, &read_fd);
	rv = select(fd + 1, &read_fd, NULL, NULL, &tv);
	if (rv < 0) {
		int connreset = 0;
		while (rv < 0 && (errno == EINTR || errno == EAGAIN || errno == ECONNRESET)) {
			if (errno == ECONNRESET && ++connreset > 20)
				break;
			usleep(50000);
			rv = select(fd + 1, &read_fd, NULL, NULL, &tv);
		}
		if (rv < 0) {
			Log2(PCSC_LOG_INFO,
				"ping: select() error: %s", strerror(errno));
			close(fd);
			return -1;      // Error
		}
	} else if (rv == 0) {
		Log2(PCSC_LOG_ERROR,
			"ping: Launcher reply timed out after %d sec.",
			CONNECT_TIMEOUT);
		close(fd);
		return -1;      // Timeout
	}
	if (FD_ISSET(fd, &read_fd)) {
		int connreset = 0;
		if ((rv = read(fd, buf, sizeof (buf))) < 0) {
			while (rv < 0 && (errno == EINTR || errno == EAGAIN || errno == ECONNRESET)) {
				if (errno == ECONNRESET && ++connreset > 20)
					break;
				usleep(50000);
				rv = read(fd, buf, sizeof (buf));
			}
			if (rv < 0) {
				Log3(PCSC_LOG_INFO,
					"ping: Err reading launcher "
					"reply after select (reset cnt=%d): %s",
					 connreset, strerror(errno));
				close(fd);
				return -1;      // Error
			}
		}
	}

	sprintf(cmp, "ACK %d", getpid());
	if (strncmp(buf, cmp, strlen(cmp)) == 0) {
		close(fd);
		return 0;
	}
	Log2(PCSC_LOG_INFO, "Error pinging launcher."
		"Reply was: %s\n", buf);
	close(fd);
	return -1;
}
