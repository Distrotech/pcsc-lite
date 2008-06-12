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


#ifndef	__validate_h__
#define	__validate_h__

#include "clientcred.h"

#ifdef __cplusplus
extern "C"
{
#endif


void VALloadPlugins();
int VALfindInstanceFiles(int, char **, char **);
char *VALgetDisplayTag(int, void *, char **);
void *VALgetDisplayResource(int, void *, void **);
int VALgetDisplayStatus(int, void **, unsigned int *);

#ifdef __cplusplus
extern "C"
}
#endif

#endif
