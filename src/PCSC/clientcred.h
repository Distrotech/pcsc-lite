/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999-2006
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *  David Markowitz <david.markowitz@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 * //// PUT RIGHT MACRO EXPANSION KEYWORDS IN HERE ////
 */

/**
 * @file
 * @brief This is for passing client credentials.
 */

#ifndef _client_cred_h_
#define _client_cred_h_

#include <ucred.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define	IOCTL_CLIENT_CRED	SCARD_CTL_CODE(0x340001)

typedef struct pcsc_client_cred {
	uid_t		euid;		/* Solaris, Linux, FreeBSD, MacOS */
	uid_t		egid;		/* Solaris, Linux, FreeBSD, MacOS */
	pid_t		pid;		/* Solaris, Linux */
	uint_t		dpyNbr;		/* X11 */
	uint_t		screenNbr;	/* X11 */
	in_addr_t	clientXhostIP;	/* Avail from $DISPLAY */
	in_addr_t	clientIP;	/* Avail from accept() */
	struct {
		uid_t		ruid;	/* Real user id */
		uid_t		rgid;	/* Real group id */
#if 0
#ifdef _SYS_TSOL_LABEL_H
		m_label_t	*zone_label; /* Zone label */
#endif
#ifdef _ZONE_H
		zoneid_t	zone_id; /* Zone Id */
#endif
#endif
	} solaris;
} PCSCLITE_CRED_T;

#ifdef __cplusplus
}
#endif

#endif
