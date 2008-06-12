/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

/**
 * @file
 * @brief This handles thread function abstraction.
 */

#include "config.h"
#include "wintypes.h"
#include "thread_generic.h"
#include "misc.h"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif


INTERNAL int SYS_CondInit(PCSCLITE_COND_T mCond) 
{
        return pthread_cond_init(&mCond, NULL);
}

INTERNAL int SYS_CondWait(PCSCLITE_COND_T mCond, PCSCLITE_MUTEX_T mMutex) 
{
        return pthread_cond_wait(mCond, mMutex);
}

INTERNAL int SYS_CondSignal(PCSCLITE_COND_T mCond)
{
        return pthread_cond_signal(mCond);
}

INTERNAL int SYS_CondBroadcast(PCSCLITE_COND_T mCond)
{
        return pthread_cond_broadcast(mCond);
}

INTERNAL int SYS_MutexInit(PCSCLITE_MUTEX_T mMutex)
{
	return pthread_mutex_init(mMutex, NULL);
}

INTERNAL int SYS_MutexDestroy(PCSCLITE_MUTEX_T mMutex)
{
	return pthread_mutex_destroy(mMutex);
}

INTERNAL int SYS_MutexLock(PCSCLITE_MUTEX_T mMutex)
{
	return pthread_mutex_lock(mMutex);
}

INTERNAL int SYS_MutexUnLock(PCSCLITE_MUTEX_T mMutex)
{
	return pthread_mutex_unlock(mMutex);
}

INTERNAL int SYS_ThreadCreate(PCSCLITE_THREAD_T * pthThread, int attributes,
	PCSCLITE_THREAD_FUNCTION(pvFunction), LPVOID pvArg)
{
	pthread_attr_t attr;
	
	if (0 != pthread_attr_init(&attr))
		return FALSE;
	
	if (0 != pthread_attr_setdetachstate(&attr,
		attributes & THREAD_ATTR_DETACHED ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE))
		return FALSE;
	
	if (0 != pthread_create(pthThread, &attr, pvFunction, pvArg)) {
		pthread_attr_destroy(&attr);
		return FALSE;
	}
	pthread_attr_destroy(&attr);
	return TRUE;
	
}

INTERNAL int SYS_ThreadCancel(PCSCLITE_THREAD_T * pthThread)
{
	if (0 == pthread_cancel(*pthThread))
		return TRUE;
	else
		return FALSE;
}

INTERNAL int SYS_ThreadDetach(PCSCLITE_THREAD_T pthThread)
{
	if (0 == pthread_detach(pthThread))
		return TRUE;
	else
		return FALSE;
}

INTERNAL int SYS_ThreadJoin(PCSCLITE_THREAD_T *pthThread, LPVOID* pvRetVal)
{
	if (0 == pthread_join(*pthThread, pvRetVal))
		return TRUE;
	else
		return FALSE;
}

INTERNAL int SYS_ThreadExit(LPVOID pvRetVal)
{
	pthread_exit(pvRetVal);
	return 1;
}

INTERNAL PCSCLITE_THREAD_T SYS_ThreadSelf(void)
{
	return pthread_self();
}

INTERNAL int SYS_ThreadEqual(PCSCLITE_THREAD_T *pthThread1, PCSCLITE_THREAD_T *pthThread2)
{
	return pthread_equal(*pthThread1, *pthThread2);
}

