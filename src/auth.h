/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 * <NEED TO FIX KEYWORDS>
 */


#ifndef	__auth_h__
#define	__auth_h__

#include "clientcred.h"

#ifdef __cplusplus
extern "C"
{
#endif

int AUTHGetClientCreds(int, PCSCLITE_CRED_T *);

int AUTHCheckDaemon(const char *facilityTag, PCSCLITE_CRED_T *cred,
    const char *resource);

int AUTHCheckIfd(const char *facilityTag, PCSCLITE_CRED_T *cred,
    const char *ifdHandlerName, const char *resource);


#ifdef __cplusplus
extern "C"
}
#endif

#endif
