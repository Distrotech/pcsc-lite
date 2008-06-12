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


#ifndef	__instance_h__
#define	__instance_h__

#ifdef __cplusplus
extern "C"
{
#endif

#define PID_ASCII_SIZE 11

void InitializeInstance(void);
void StartInstanceTimer(void);
void CancelInstanceTimer(void);
void LockContextLookup(void);
void UnlockContextLookup(void);
void InstanceExitHandler(int);

#ifdef __cplusplus
extern "C"
}
#endif

#endif
