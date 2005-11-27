/*
 * This is a test program for pcsc-lite.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 1999
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>

#include "pcsclite.h"
#include "winscard.h"

int main(int argc, char **argv)
{
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	SCARD_READERSTATE_A rgReaderStates[1];
	unsigned long dwReaderLen, dwState, dwProt, dwAtrLen;
	unsigned long dwPref, dwReaders;
	char *pcReaders, *mszReaders;
	unsigned char pbAtr[MAX_ATR_SIZE];
	char *mszGroups;
	unsigned long dwGroups;
	long rv;
	int i, p, iReader;
	int iList[16];

	printf("\nMUSCLE PC/SC Lite Test Program\n\n");

	printf("Testing SCardEstablishContext    : ");
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		return -1;
	}

	printf("Testing SCardGetStatusChange \n");
	printf("Please insert a working reader   : ");
	rv = SCardGetStatusChange(hContext, INFINITE, 0, 0);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	printf("Testing SCardListReaderGroups    : ");

	rv = SCardListReaderGroups(hContext, 0, &dwGroups);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	mszGroups = (char *) malloc(sizeof(char) * dwGroups);
	rv = SCardListReaderGroups(hContext, mszGroups, &dwGroups);

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	/*
	 * Have to understand the multi-string here 
	 */
	p = 0;
	for (i = 0; i < dwGroups - 1; i++)
	{
		++p;
		printf("Group %02d: %s\n", p, &mszGroups[i]);
		iList[p] = i;
		while (mszGroups[++i] != 0) ;
	}

	printf("Testing SCardListReaders         : ");

	mszGroups = 0;
	rv = SCardListReaders(hContext, mszGroups, 0, &dwReaders);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	mszReaders = (char *) malloc(sizeof(char) * dwReaders);
	rv = SCardListReaders(hContext, mszGroups, mszReaders, &dwReaders);

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	/*
	 * Have to understand the multi-string here 
	 */
	p = 0;
	for (i = 0; i < dwReaders - 1; i++)
	{
		++p;
		printf("Reader %02d: %s\n", p, &mszReaders[i]);
		iList[p] = i;
		while (mszReaders[++i] != 0) ;
	}

	if (p > 1)
		do
		{
			printf("Enter the reader number          : ");
			scanf("%d", &iReader);
			printf("\n");

			if (iReader > p || iReader <= 0)
				printf("Invalid Value - try again\n");
		}
		while (iReader > p || iReader <= 0);
	else
		iReader = 1;

	rgReaderStates[0].szReader = &mszReaders[iList[iReader]];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;

	printf("Waiting for card insertion       : ");
	fflush(stdout);
	rv = SCardGetStatusChange(hContext, INFINITE, rgReaderStates, 1);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	printf("Testing SCardConnect             : ");
	rv = SCardConnect(hContext, &mszReaders[iList[iReader]],
		SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&hCard, &dwPref);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	printf("Testing SCardControl             : ");
#ifdef PCSC_PRE_120
	{
		char buffer[1024] = "Foobar";
		DWORD cbRecvLength = sizeof(buffer);

		rv = SCardControl(hCard, buffer, 7, buffer, &cbRecvLength);
	}
#else
	{
		char buffer[1024] = "Foobar";
		DWORD cbRecvLength = sizeof(buffer);

		rv = SCardControl(hCard, 0x42000001, buffer, 7, buffer, sizeof(buffer),
			&cbRecvLength);
	}
#endif
	printf("%s %s\n", pcsc_stringify_error(rv), rv != SCARD_S_SUCCESS ? "(don't panic)" : "");

	printf("Testing SCardGetAttrib           : ");
	dwAtrLen = sizeof(pbAtr);
	rv = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING, pbAtr, &dwAtrLen);
	printf("%s %s\n", pcsc_stringify_error(rv), rv != SCARD_S_SUCCESS ? "(don't panic)" : "");
	if (rv == SCARD_S_SUCCESS)
	{
		for (i = 0; i < dwAtrLen; i++)
			printf("%02X ", pbAtr[i]);
		printf("\n");
	}

	printf("Testing SCardSetAttrib           : ");
	rv = SCardSetAttrib(hCard, SCARD_ATTR_ATR_STRING, (LPCBYTE)"", 1);
	printf("%s %s\n", pcsc_stringify_error(rv), rv != SCARD_S_SUCCESS ? "(don't panic)" : "");

	printf("Testing SCardStatus              : ");

	dwReaderLen = 50;
	pcReaders   = (char *) malloc(sizeof(char) * 50);
	dwAtrLen    = MAX_ATR_SIZE;

	rv = SCardStatus(hCard, pcReaders, &dwReaderLen, &dwState, &dwProt,
		pbAtr, &dwAtrLen);

	printf("%s\n", pcsc_stringify_error(rv));

	printf("Current Reader Name              : %s\n", pcReaders);
	printf("Current Reader State             : 0x%.4lx\n", dwState);
	printf("Current Reader Protocol          : T=%ld\n", dwProt - 1);
	printf("Current Reader ATR Size          : %ld bytes\n", dwAtrLen);
	printf("Current Reader ATR Value         : ");

	for (i = 0; i < dwAtrLen; i++)
	{
		printf("%02X ", pbAtr[i]);
	}
	printf("\n");

	if (rv != SCARD_S_SUCCESS)
	{
		SCardDisconnect(hCard, SCARD_RESET_CARD);
		SCardReleaseContext(hContext);
	}

	printf("Testing SCardDisconnect          : ");
	rv = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		return -1;
	}

	printf("Testing SCardReleaseContext      : ");
	rv = SCardReleaseContext(hContext);

	printf("%s\n", pcsc_stringify_error(rv));

	if (rv != SCARD_S_SUCCESS)
	{
		return -1;
	}

	printf("\n");
	printf("PC/SC Test Completed Successfully !\n");

	return 0;
}
