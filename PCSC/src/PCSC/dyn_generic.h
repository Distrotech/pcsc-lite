/*
 * This abstracts dynamic library loading functions.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#ifndef __dyn_generic_h__
#define __dyn_generic_h__

#ifdef __cplusplus
extern "C"
{
#endif

	int DYN_LoadLibrary(void **, char *);
	int DYN_CloseLibrary(void **);
	int DYN_GetAddress(void *, void **, char *);

#ifdef __cplusplus
}
#endif

#endif
