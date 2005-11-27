/*
 * This handles protocol defaults, PTS, etc.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2004
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
 * $Id$
 */

#include "config.h"
#include <string.h>

#include "pcsclite.h"
#include "ifdhandler.h"
#include "debuglog.h"
#include "readerfactory.h"
#include "prothandler.h"
#include "atrhandler.h"
#include "ifdwrapper.h"
#include "eventhandler.h"

/*
 * Function: PHGetDefaultProtocol Purpose : To get the default protocol
 * used immediately after reset. This protocol is returned from the
 * function. 
 */

UCHAR PHGetDefaultProtocol(PUCHAR pucAtr, DWORD dwLength)
{
	SMARTCARD_EXTENSION sSmartCard;

	/*
	 * Zero out everything 
	 */
	memset(&sSmartCard, 0x00, sizeof(SMARTCARD_EXTENSION));

	if (ATRDecodeAtr(&sSmartCard, pucAtr, dwLength))
		return sSmartCard.CardCapabilities.CurrentProtocol;
	else
		return 0x00;
}

/*
 * Function: PHGetAvailableProtocols Purpose : To get the protocols
 * supported by the card. These protocols are returned from the function
 * as bit masks. 
 */

UCHAR PHGetAvailableProtocols(PUCHAR pucAtr, DWORD dwLength)
{
	SMARTCARD_EXTENSION sSmartCard;

	/*
	 * Zero out everything 
	 */
	memset(&sSmartCard, 0x00, sizeof(SMARTCARD_EXTENSION));

	if (ATRDecodeAtr(&sSmartCard, pucAtr, dwLength))
		return sSmartCard.CardCapabilities.AvailableProtocols;
	else
		return 0x00;
}

/*
 * Function: PHSetProtocol Purpose : To determine which protocol to use.
 * SCardConnect has a DWORD dwPreferredProtocols that is a bitmask of what 
 * protocols to use.  Basically, if T=N where N is not zero will be used
 * first if it is available in ucAvailable.  Otherwise it will always
 * default to T=0.
 *
 * IFDSetPTS() is _always_ called so that the driver can initialise its data
 */

DWORD PHSetProtocol(struct ReaderContext * rContext,
	DWORD dwPreferred, UCHAR ucAvailable, UCHAR ucDefault)
{
	DWORD protocol;
	LONG rv;
	UCHAR ucChosen;

	/* App has specified no protocol */
	if (dwPreferred == 0)
		return SET_PROTOCOL_WRONG_ARGUMENT;

	/* requested protocol is not available */
	if (! (dwPreferred & ucAvailable))
	{
		/* Note:
		 * dwPreferred must be either SCARD_PROTOCOL_T0 or SCARD_PROTOCOL_T1
		 * if dwPreferred == SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1 the test
		 * (SCARD_PROTOCOL_T0 == dwPreferred) will not work as expected
		 * and the debug message will not be correct.
		 *
		 * This case may only occur if
		 * dwPreferred == SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
		 * and ucAvailable == 0 since we have (dwPreferred & ucAvailable) == 0
		 * and the case ucAvailable == 0 should never occur (the card is at
		 * least T=0 or T=1)
		 */
		DebugLogB("Protocol T=%d requested but unsupported by the card",
			(SCARD_PROTOCOL_T0 == dwPreferred) ? 0 : 1);
		return SET_PROTOCOL_WRONG_ARGUMENT;
	}

	/* set default value */
	protocol = ucDefault;

	/* keep only the available protocols */
	dwPreferred &= ucAvailable;

	/* we try to use T=1 first */
	if (dwPreferred & SCARD_PROTOCOL_T1)
		ucChosen = SCARD_PROTOCOL_T1;
	else
		if (dwPreferred & SCARD_PROTOCOL_T0)
			ucChosen = SCARD_PROTOCOL_T0;
		else
			/* App wants unsupported protocol */
			return SET_PROTOCOL_WRONG_ARGUMENT;

	DebugLogB("Attempting PTS to T=%d",
		(SCARD_PROTOCOL_T0 == ucChosen ? 0 : 1));
	rv = IFDSetPTS(rContext, ucChosen, 0x00, 0x00, 0x00, 0x00);

	if (IFD_SUCCESS == rv)
		protocol = ucChosen;
	else
		if (IFD_NOT_SUPPORTED == rv)
			DebugLogB("PTS not supported by driver, using T=%d",
				(SCARD_PROTOCOL_T0 == protocol) ? 0 : 1);
		else
		{
			DebugLogB("PTS failed, using T=%d",
				(SCARD_PROTOCOL_T0 == protocol) ? 0 : 1);

 			/* ISO 7816-3:1997 ch. 7.2 PPS protocol page 14
 			 * - If the PPS exchange is unsuccessful, then the interface device
 			 *   shall either reset or reject the card.
 			 */
 			return SET_PROTOCOL_PPS_FAILED;
 		}

	return protocol;
}

