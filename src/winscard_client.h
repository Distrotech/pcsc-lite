/*
 * Copyright (C) 2001-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 * 
 * $Id: winscard_svc.h 1421 2005-04-12 12:09:21Z rousseau $
 */

/**
 * @file
 * @brief This contains internal information conveyed between
 * the service and the server side API implementation.
 */

#ifndef __winscard_client_h__
#define __winscard_client_h__

#ifdef  __cplusplus
extern "C"
{
#endif	

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
        
        struct client_struct
	{
		SCARDCONTEXT hContext;
		in_addr_t hostIpv4;
		LONG xDispNbr;
		LONG xSubDispNbr;
		uid_t euid;
		gid_t egid;
	};
	typedef struct client_struct client_struct;
        
#ifdef  __cplusplus
}
#endif

#endif
