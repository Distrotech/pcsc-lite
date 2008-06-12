/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2001-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This demarshalls functions over the message queue and
 * keeps track of clients and their handles.
 */

#ifndef __winscard_svc_h__
#define __winscard_svc_h__

#ifdef __cplusplus
extern "C"
{
#endif
	LONG ContextsInitialize(void);
	LONG CreateContextThread(PDWORD);
#ifdef _HAVE_SYS_DOOR_H
        void ContextWaitForDoorRecv(DWORD);
        void ContextSignalDoorRecv(char *, size_t);
#endif        
#ifdef __cplusplus
}
#endif

#endif
