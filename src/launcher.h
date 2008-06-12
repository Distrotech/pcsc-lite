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


#ifndef	__launcher_h__
#define	__launcher_h__

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Misc constants
 */        
#define LINEMAX                 256        // buffer size constraint
#define MAX_INST_CHECKS 300  // 30 seconds worth of 100000 usec waits

void Launcher();


#ifdef __cplusplus
extern "C"
}
#endif

#endif
