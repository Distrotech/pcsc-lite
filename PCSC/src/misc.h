/*
 * This handles GCC attributes
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2005
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

#ifndef __local_h__
#define __local_h__

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Declare the function as internal to the library: the function name is
 * not exported and can't be used by a program linked to the library
 *
 * see http://gcc.gnu.org/onlinedocs/gcc-3.3.5/gcc/Function-Attributes.html#Function-Attributes
 */
#define INTERNAL __attribute__ ((visibility("hidden")))

#ifdef __cplusplus
}
#endif

#endif /* __lcoal_h__ */
