/******************************************************************
 
        MUSCLE SmartCard Development ( http://www.linuxnet.com )
            Title  : formaticc.c
            Package: pcsc lite
            Author : David Corcoran, Ludovic Rousseau
            Date   : 5/16/00, 8/16/2002
            License: Copyright (C) 2000 David Corcoran
                     <corcoran@linuxnet.com>
            Purpose: This is an APDU robot for pcsc-lite.
 
$Id$

********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wintypes.h>
#include <winscard.h>

#include "configfile.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

int main(int argc, char *argv[])
{
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	// struct ReaderContext *rContext;
	// SCARD_IO_REQUEST sSendPci;
	SCARD_IO_REQUEST sRecvPci;
	SCARD_READERSTATE_A rgReaderStates[1];
	// DWORD dwReaderLen, dwState, dwProt, dwAtrLen;
	DWORD dwSendLength, dwRecvLength, dwPref, dwReaders;
	// LPSTR pcReaders;
	LPSTR mszReaders;
	// BYTE pbAtr[MAX_ATR_SIZE];
	BYTE s[MAX_BUFFER_SIZE], r[MAX_BUFFER_SIZE];
	LPCSTR mszGroups;
	LONG rv;
	FILE *fp;
	FILE *fo;
	int i, p, iReader, cnum, iProtocol;
	int iList[16];
	char pcHost[MAXHOSTNAMELEN];
	char pcAFile[FILENAME_MAX];
	char pcOFile[FILENAME_MAX];
	char line[80];
	char *line_ptr;
	unsigned int x;

	// int t = 0;

	printf("\nWinscard PC/SC Lite Test Program\n\n");

	printf("Please enter the desired host (localhost for this machine) [localhost]: ");
	fgets(line, sizeof(line), stdin);
	if (line[0] == '\n')
		strncpy(pcHost, "localhost", sizeof(pcHost)-1);
	else
		strncpy(pcHost, line, sizeof(pcHost)-1);

	printf("Please input the desired transmit protocol (0/1) [0]: ");
	fgets(line, sizeof(line), stdin);
	if (line[0] == '\n')
		iProtocol = 0;
	else
		sscanf(line, "%d", &iProtocol);

	printf("Please input the desired input apdu file: ");
	fgets(line, sizeof(line), stdin);
	sscanf(line, "%s", pcAFile);

	printf("Please input the desired output apdu file: ");
	fgets(line, sizeof(line), stdin);
	sscanf(line, "%s", pcOFile);

	fp = fopen(pcAFile, "r");
	if (fp == NULL)
	{
		perror(pcAFile);
		return 1;
	}

	fo = fopen(pcOFile, "w");
	if (fo == NULL)
	{
		perror(pcOFile);
		return 1;
	}

	rv = SCardEstablishContext(SCARD_SCOPE_GLOBAL, pcHost, NULL, &hContext);

	if (rv != SCARD_S_SUCCESS)
	{
		printf("ERROR :: Cannot Connect to Resource Manager\n");
		return 1;
	}

	mszGroups = 0;
	SCardListReaders(hContext, mszGroups, 0, &dwReaders);
	mszReaders = (char *) malloc(sizeof(char) * dwReaders);
	SCardListReaders(hContext, mszGroups, mszReaders, &dwReaders);

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

	do
	{
		printf("Enter the desired reader number: ");
		fgets(line, sizeof(line), stdin);
		sscanf(line, "%d", &iReader);
		printf("\n");

		if (iReader > p || iReader <= 0)
		{
			printf("Invalid Value - try again\n");
		}
	}
	while (iReader > p || iReader <= 0);

	rgReaderStates[0].szReader = &mszReaders[iList[iReader]];
	rgReaderStates[0].dwCurrentState = SCARD_STATE_EMPTY;

	printf("Please insert a smartcard\n");
	SCardGetStatusChange(hContext, INFINITE, rgReaderStates, 1);
	rv = SCardConnect(hContext, &mszReaders[iList[iReader]],
		SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&hCard, &dwPref);

	if (rv != SCARD_S_SUCCESS)
	{
		SCardReleaseContext(hContext);
		printf("Error connecting to reader %ld\n", rv);
		return 1;
	}

	/*
	 * Now lets get some work done 
	 */

	SCardBeginTransaction(hCard);

	cnum = 0;

	do
	{
		cnum += 1;

		if (fgets(line, sizeof(line), fp) == NULL)
			break;

		line_ptr = line;
		if (sscanf(line_ptr, "%x", &x) == 0)
			break;
		dwSendLength = x;

		line_ptr = strchr(line_ptr, ' ') +1;
		if (line_ptr == NULL+1)
			break;

		for (i = 0; i < dwSendLength; i++)
		{
			if (sscanf(line_ptr, "%x", &x) == 0)
			{
				printf("Corrupt APDU: %s\n", line);
				SCardDisconnect(hCard, SCARD_RESET_CARD);
				SCardReleaseContext(hContext);
				return 1;
			}
			s[i] = x;

			line_ptr = strchr(line_ptr, ' ') +1;

			if (line_ptr == NULL+1)
				break;
		}

		printf("Processing Command %03d of length %03lX: %s", cnum,
			dwSendLength, line);

		memset(r, 0x00, MAX_BUFFER_SIZE);
		dwRecvLength = MAX_BUFFER_SIZE;

		if (iProtocol == 0)
		{
			rv = SCardTransmit(hCard, SCARD_PCI_T0, s, dwSendLength,
				&sRecvPci, r, &dwRecvLength);
		}
		else
		{
			if (iProtocol == 1)
			{
				rv = SCardTransmit(hCard, SCARD_PCI_T1, s, dwSendLength,
					&sRecvPci, r, &dwRecvLength);
			}
			else
			{
				printf("Invalid Protocol\n");
				SCardDisconnect(hCard, SCARD_RESET_CARD);
				SCardReleaseContext(hContext);
				return 1;
			}
		}

		if (rv != SCARD_S_SUCCESS)
			fprintf(fo, ".error %ld\n", rv);
		else
		{
			fprintf(fo, "%02ld ", dwRecvLength);

			for (i = 0; i < dwRecvLength; i++)
				fprintf(fo, "%02X ", r[i]);

			fprintf(fo, "\n");
		}

		if (rv == SCARD_W_RESET_CARD)
		{
			SCardReconnect(hCard, SCARD_SHARE_SHARED,
				SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
				SCARD_RESET_CARD, &dwPref);
		}

	}
	while (1);

	SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
	SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
	SCardReleaseContext(hContext);

	return 0;
}

