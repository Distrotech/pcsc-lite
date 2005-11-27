/*
 * This tests the virtual card edge.
 *
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2001
 *  David Corcoran <corcoran@linuxnet.com>
 *
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PCSC/pcsclite.h"
#include "PCSC/winscard.h"
#include "PCSC/mscdefines.h"
#include "PCSC/musclecard.h"

#define MY_OBJECT_ID    "c1"
#define MY_OBJECT_SIZE  50

#ifdef WIN32
MSCString pcsc_stringify_error(MSCLong32 Error);
#endif

int main(int argc, char **argv)
{
	MSCLong32 rv;
	MSCTokenConnection pConnection;
	MSCStatusInfo statusInf;
	MSCObjectACL objACL;
	MSCObjectInfo objInfo;
	MSCUChar8 pRandomData[20];
	MSCUChar8 pSeed[8];
	MSCUChar8 defaultPIN[16];
	MSCUChar8 AID[] = { 0xA0, 0x00, 0x00, 0x00, 0x01, 0x01 };
	MSCUChar8 myData[] = "MUSCLE VIRTUAL CARD.";
	MSCUChar8 readData[50];
	MSCLPTokenInfo tokenList;
	MSCULong32 tokenSize;
	int reader_to_use;
	int i, j;

	printf("********************************************************\n");
	printf("\n");

	tokenList = NULL;
	tokenSize = 0;

	rv = MSCListTokens(MSC_LIST_SLOTS, tokenList, &tokenSize);
	if (rv != MSC_SUCCESS)
	{
		printf("MSCListTokens returns     : %s\n", msc_error(rv));
		return -1;
	}

	tokenList = (MSCLPTokenInfo) malloc(sizeof(MSCTokenInfo) * tokenSize);

	rv = MSCListTokens(MSC_LIST_SLOTS, tokenList, &tokenSize);
	if (rv != MSC_SUCCESS)
	{
		printf("MSCListTokens returns     : %s\n", msc_error(rv));
		return -1;
	}

	for (i = 0; i < tokenSize; i++)
	{
		printf("Token #%d\n", i);
		printf("Token name     : %s\n", tokenList[i].tokenName);
		printf("Slot name      : %s\n", tokenList[i].slotName);

		printf("Token id       : ");
		for (j = 0; j < tokenList[i].tokenIdLength; j++)
			printf("%02X", tokenList[i].tokenId[j]);
		printf("\n");

		printf("Token state    : %04lX\n", tokenList[i].tokenState);
		printf("Token type     : %04lX ", tokenList[i].tokenType);
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_REMOVED)
			printf("token removed ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_UNKNOWN)
			printf("token unkown ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_KNOWN)
			printf("token known ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_RESET)
			printf("token reset ");
		printf("\n\n");

		tokenList[i].tokenState = MSC_STATE_EMPTY;
	}

	printf("********************************************************\n");

	rv = MSCWaitForTokenEvent(tokenList, tokenSize, MSC_NO_TIMEOUT);

	reader_to_use = -1;
	for (i = 0; i < tokenSize; i++)
	{
		printf("Token #%d\n", i);
		printf("Token name     : %s\n", tokenList[i].tokenName);
		printf("Slot name      : %s\n", tokenList[i].slotName);

		printf("Token id       : ");
		for (j = 0; j < tokenList[i].tokenIdLength; j++)
			printf("%02X", tokenList[i].tokenId[j]);
		printf("\n");

		printf("Token state    : %04lX\n", tokenList[i].tokenState);
		printf("Token type     : %04lX ", tokenList[i].tokenType);
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_REMOVED)
			printf("token removed ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_UNKNOWN)
			printf("token unkown ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_KNOWN)
			printf("token known ");
		if (tokenList[i].tokenType & MSC_TOKEN_TYPE_RESET)
			printf("token reset ");
		printf("\n\n");

		if (tokenList[i].tokenState & SCARD_STATE_PRESENT)
			reader_to_use = i;
	}

	if (reader_to_use == -1)
	{
		printf("No valid token found\n");
		return -1;
	}

	rv = MSCEstablishConnection(&tokenList[reader_to_use], MSC_SHARE_SHARED,
		AID, 6, &pConnection);
	if (rv != MSC_SUCCESS)
	{
		printf("EstablishConn returns     : %s\n", msc_error(rv));
		return -1;
	}

	rv = MSCBeginTransaction(&pConnection);
	printf("BeginTransaction returns    : %s\n", msc_error(rv));

	rv = MSCGetStatus(&pConnection, &statusInf);
	printf("GetStatus returns           : %s\n", msc_error(rv));
	printf("Protocol version            : %04X\n", statusInf.appVersion);
	printf("Applet version              : %04X\n", statusInf.swVersion);
	printf("Total object memory         : %08ld\n", statusInf.totalMemory);
	printf("Free object memory          : %08ld\n", statusInf.freeMemory);
	printf("Number of used PINs         : %02d\n", statusInf.usedPINs);
	printf("Number of used Keys         : %02d\n", statusInf.usedKeys);
	printf("Currently logged identities : %04X\n", statusInf.loggedID);

	printf("Please enter the PIN value: ");
	fgets((char *)defaultPIN, sizeof(defaultPIN), stdin);
	if (defaultPIN[0] == '\n')
		strcpy((char *)defaultPIN, "Muscle00\n");

	rv = MSCVerifyPIN(&pConnection, 0, defaultPIN,
		strlen((char *)defaultPIN) - 1);
	printf("Verify default PIN          : %s\n", msc_error(rv));

	rv = MSCGetStatus(&pConnection, &statusInf);
	printf("Currently logged identities : %04X\n", statusInf.loggedID);

	objACL.readPermission = MSC_AUT_ALL;
	objACL.writePermission = MSC_AUT_ALL;
	objACL.deletePermission = MSC_AUT_ALL;

	rv = MSCCreateObject(&pConnection, MY_OBJECT_ID, MY_OBJECT_SIZE, &objACL);
	printf("CreateObject returns        : %s\n", msc_error(rv));

	rv = MSCWriteObject(&pConnection, MY_OBJECT_ID, 0, myData,
		            sizeof(myData), 0, 0);
	printf("WriteObject returns         : %s\n", msc_error(rv));

	rv = MSCReadObject(&pConnection, MY_OBJECT_ID, 0, readData, 25, 0, 0);
	printf("ReadObject returns          : %s\n", msc_error(rv));

	if (rv == MSC_SUCCESS)
	{
		printf("Object data                 : %s\n", readData);
		if (strcmp((char *)readData, (char*)myData) == 0)
			printf("Data comparison             : Successful\n");
		else
			printf("Data comparison             : Data mismatch\n");
	}

	rv = MSCListObjects(&pConnection, MSC_SEQUENCE_RESET, &objInfo);

	printf("\n");
	printf("Listing objects             : %s\n", msc_error(rv));
	printf("------------------------------------------------------\n");
	printf("           Object ID  Object Size   READ  WRITE  DELETE\n");
	printf("   -----------------  -----------   ----  -----  ------\n");

	if (rv == MSC_SUCCESS)
	{
		printf("%20s %12ld   %04X   %04X    %04X\n", objInfo.objectID,
			objInfo.objectSize,
			objInfo.objectACL.readPermission,
			objInfo.objectACL.writePermission,
			objInfo.objectACL.deletePermission);
	}

	do
	{
		rv = MSCListObjects(&pConnection, MSC_SEQUENCE_NEXT, &objInfo);
		if (rv == MSC_SUCCESS)
		{
			printf("%20s %12ld   %04X   %04X    %04X\n", objInfo.objectID,
				objInfo.objectSize,
				objInfo.objectACL.readPermission,
				objInfo.objectACL.writePermission,
				objInfo.objectACL.deletePermission);
		} else
			break;
	}
	while (1);

	printf("------------------------------------------------------\n");
	printf("\n");

	rv = MSCGetStatus(&pConnection, &statusInf);
	printf("Free object memory          : %08ld\n", statusInf.freeMemory);

	rv = MSCDeleteObject(&pConnection, MY_OBJECT_ID, MSC_ZF_DEFAULT);
	printf("DeleteObject returns        : %s\n", msc_error(rv));

	rv = MSCGetStatus(&pConnection, &statusInf);
	printf("Free object memory          : %08ld\n", statusInf.freeMemory);

	memset(pRandomData, 0, sizeof(pRandomData));
	rv = MSCGetChallenge(&pConnection, pSeed, 0, pRandomData, 8);
	printf("GetChallenge returns        : %s\n", msc_error(rv));

	printf("Random data                 : ");
	for (i = 0; i < 8; i++)
		printf("%02X ", pRandomData[i]);
	printf("\n");

	rv = MSCLogoutAll(&pConnection);
	printf("Logout all identities       : %s\n", msc_error(rv));

	rv = MSCGetStatus(&pConnection, &statusInf);
	printf("Currently logged identities : %04X\n", statusInf.loggedID);

	rv = MSCEndTransaction(&pConnection, SCARD_LEAVE_CARD);
	printf("EndTransaction returns      : %s\n", msc_error(rv));

	MSCReleaseConnection(&pConnection, SCARD_LEAVE_CARD);
	printf("ReleaseConn returns         : %s\n", msc_error(rv));

	return 0;
}

#ifdef WIN32
MSCString pcsc_stringify_error(MSCLong32 Error)
{
	static char strError[75];

	switch (Error)
	{
	case SCARD_S_SUCCESS:
		strcpy(strError, "Command successful.");
		break;
	case SCARD_E_CANCELLED:
		strcpy(strError, "Command cancelled.");
		break;
	case SCARD_E_CANT_DISPOSE:
		strcpy(strError, "Cannot dispose handle.");
		break;
	case SCARD_E_INSUFFICIENT_BUFFER:
		strcpy(strError, "Insufficient buffer.");
		break;
	case SCARD_E_INVALID_ATR:
		strcpy(strError, "Invalid ATR.");
		break;
	case SCARD_E_INVALID_HANDLE:
		strcpy(strError, "Invalid handle.");
		break;
	case SCARD_E_INVALID_PARAMETER:
		strcpy(strError, "Invalid parameter given.");
		break;
	case SCARD_E_INVALID_TARGET:
		strcpy(strError, "Invalid target given.");
		break;
	case SCARD_E_INVALID_VALUE:
		strcpy(strError, "Invalid value given.");
		break;
	case SCARD_E_NO_MEMORY:
		strcpy(strError, "Not enough memory.");
		break;
	case SCARD_F_COMM_ERROR:
		strcpy(strError, "RPC transport error.");
		break;
	case SCARD_F_INTERNAL_ERROR:
		strcpy(strError, "Unknown internal error.");
		break;
	case SCARD_F_UNKNOWN_ERROR:
		strcpy(strError, "Unknown internal error.");
		break;
	case SCARD_F_WAITED_TOO_MSCLong32:
		strcpy(strError, "Waited too long.");
		break;
	case SCARD_E_UNKNOWN_READER:
		strcpy(strError, "Unknown reader specified.");
		break;
	case SCARD_E_TIMEOUT:
		strcpy(strError, "Command timeout.");
		break;
	case SCARD_E_SHARING_VIOLATION:
		strcpy(strError, "Sharing violation.");
		break;
	case SCARD_E_NO_SMARTCARD:
		strcpy(strError, "No smart card inserted.");
		break;
	case SCARD_E_UNKNOWN_CARD:
		strcpy(strError, "Unknown card.");
		break;
	case SCARD_E_PROTO_MISMATCH:
		strcpy(strError, "Card protocol mismatch.");
		break;
	case SCARD_E_NOT_READY:
		strcpy(strError, "Subsystem not ready.");
		break;
	case SCARD_E_SYSTEM_CANCELLED:
		strcpy(strError, "System cancelled.");
		break;
	case SCARD_E_NOT_TRANSACTED:
		strcpy(strError, "Transaction failed.");
		break;
	case SCARD_E_READER_UNAVAILABLE:
		strcpy(strError, "Reader/s is unavailable.");
		break;
	case SCARD_W_UNSUPPORTED_CARD:
		strcpy(strError, "Card is not supported.");
		break;
	case SCARD_W_UNRESPONSIVE_CARD:
		strcpy(strError, "Card is unresponsive.");
		break;
	case SCARD_W_UNPOWERED_CARD:
		strcpy(strError, "Card is unpowered.");
		break;
	case SCARD_W_RESET_CARD:
		strcpy(strError, "Card was reset.");
		break;
	case SCARD_W_REMOVED_CARD:
		strcpy(strError, "Card was removed.");
		break;
	case SCARD_E_PCI_TOO_SMALL:
		strcpy(strError, "PCI struct too small.");
		break;
	case SCARD_E_READER_UNSUPPORTED:
		strcpy(strError, "Reader is unsupported.");
		break;
	case SCARD_E_DUPLICATE_READER:
		strcpy(strError, "Reader already exists.");
		break;
	case SCARD_E_CARD_UNSUPPORTED:
		strcpy(strError, "Card is unsupported.");
		break;
	case SCARD_E_NO_SERVICE:
		strcpy(strError, "Service not available.");
		break;
	case SCARD_E_SERVICE_STOPPED:
		strcpy(strError, "Service was stopped.");
		break;

	};

	return strError;
}
#endif
