/*
 * This handles card insertion/removal events, updates ATR,
 * protocol, and status information.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#ifndef __eventhandler_h__
#define __eventhandler_h__

#ifdef __cplusplus
extern "C"
{
#endif

	/*
	 * Define an exported public reader state structure so each
	 * application gets instant notification of changes in state. 
	 */

	typedef struct pubReaderStatesList
	{
		LONG readerID;
		char readerName[MAX_READERNAME];
		DWORD readerState;
		LONG readerSharing;
		DWORD lockState;

		UCHAR cardAtr[MAX_ATR_SIZE];
		DWORD cardAtrLength;
		DWORD cardProtocol;
	}
	READER_STATES, *PREADER_STATES;

	LONG EHInitializeEventStructures(void);
	LONG EHSpawnEventHandler(PREADER_CONTEXT);
	LONG EHDestroyEventHandler(PREADER_CONTEXT);
	void EHSetSharingEvent(PREADER_CONTEXT, DWORD);

#ifdef __cplusplus
}
#endif

#endif							/* __eventhandler_h__ */
