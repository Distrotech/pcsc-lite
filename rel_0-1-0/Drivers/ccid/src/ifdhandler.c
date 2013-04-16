/*
    ifdhandler.c: IFDH API
    Copyright (C) 2003   Ludovic Rousseau

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <string.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "pcscdefines.h"
#include "ifdhandler.h"
#include "config.h"
#include "debug.h"
#include "defs.h"
#include "utils.h"
#include "ccid_usb.h"
#include "commands.h"

// Array of structures to hold the ATR and other state value of each slot
static CcidDesc CcidSlots[PCSCLITE_MAX_CHANNELS];


RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel)
{
	/*
	 * Lun - Logical Unit Number, use this for multiple card slots or
	 * multiple readers. 0xXXXXYYYY - XXXX multiple readers, YYYY multiple
	 * slots. The resource manager will set these automatically.  By
	 * default the resource manager loads a new instance of the driver so
	 * if your reader does not have more than one smartcard slot then
	 * ignore the Lun in all the functions. Future versions of PC/SC might
	 * support loading multiple readers through one instance of the driver
	 * in which XXXX would be important to implement if you want this.
	 */

	/*
	 * Channel - Channel ID.  This is denoted by the following: 0x000001 -
	 * /dev/pcsc/1 0x000002 - /dev/pcsc/2 0x000003 - /dev/pcsc/3
	 *
	 * USB readers may choose to ignore this parameter and query the bus
	 * for the particular reader.
	 */

	/*
	 * This function is required to open a communications channel to the
	 * port listed by Channel.  For example, the first serial reader on
	 * COM1 would link to /dev/pcsc/1 which would be a sym link to
	 * /dev/ttyS0 on some machines This is used to help with intermachine
	 * independance.
	 *
	 * Once the channel is opened the reader must be in a state in which
	 * it is possible to query IFDHICCPresence() for card status.
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_COMMUNICATION_ERROR
	 */
	RESPONSECODE return_value = IFD_SUCCESS;

	DEBUG_INFO2("Entering IFDHCreateChannel (lun: %X)", Lun);

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	// Reset ATR buffer
	CcidSlots[LunToReaderIndex(Lun)].nATRLength = 0;
	*CcidSlots[LunToReaderIndex(Lun)].pcATRBuffer = '\0';

	// Reset PowerFlags
	CcidSlots[LunToReaderIndex(Lun)].bPowerFlags = POWERFLAGS_RAZ;

	if (OpenUSB(Lun, Channel) != STATUS_SUCCESS)
	{
		DEBUG_CRITICAL("OpenReader failed");
		return_value = IFD_COMMUNICATION_ERROR;
	}

	return return_value;
} /* IFDHCreateChannel */


RESPONSECODE IFDHCloseChannel(DWORD Lun)
{
	/*
	 * This function should close the reader communication channel for the
	 * particular reader.  Prior to closing the communication channel the
	 * reader should make sure the card is powered down and the terminal
	 * is also powered down.
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_COMMUNICATION_ERROR
	 */

	DEBUG_INFO2("entering IFDHCloseChannel (lun: %X)", Lun);

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	CmdPowerOff(Lun);
	// No reader status check, if it failed, what can you do ? :)

	CloseUSB(Lun);

	return IFD_SUCCESS;
} /* IFDHCloseChannel */


RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag,
	PDWORD Length, PUCHAR Value)
{
	/*
	 * This function should get the slot/card capabilities for a
	 * particular slot/card specified by Lun.  Again, if you have only 1
	 * card slot and don't mind loading a new driver for each reader then
	 * ignore Lun.
	 *
	 * Tag - the tag for the information requested example: TAG_IFD_ATR -
	 * return the Atr and it's size (required). these tags are defined in
	 * ifdhandler.h
	 *
	 * Length - the length of the returned data Value - the value of the
	 * data
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_ERROR_TAG
	 */

	DEBUG_INFO2("entering IFDHGetCapabilities (lun: %X)", Lun);

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	switch (Tag)
	{
		case TAG_IFD_ATR:
			// If Length is not zero, powerICC has been performed.
			// Otherwise, return NULL pointer
			// Buffer size is stored in *Length
			*Length = (*Length < CcidSlots[LunToReaderIndex(Lun)]
				.nATRLength) ?
				*Length : CcidSlots[LunToReaderIndex(Lun)]
				.nATRLength;

			if (*Length)
				memcpy(Value, CcidSlots[LunToReaderIndex(Lun)]
					.pcATRBuffer, *Length);
			break;

		case TAG_IFD_SIMULTANEOUS_ACCESS:
			if (*Length >= 1)
			{
				*Length = 1;
				*Value = PCSCLITE_MAX_CHANNELS;
			}
			break;

		case TAG_IFD_SLOTS_NUMBER:
			if (*Length >= 1)
			{
				*Length = 1;
				*Value = 1; /* One slot only */
			}
			break;

		default:
			return IFD_ERROR_TAG;
	}
	return IFD_SUCCESS;
} /* IFDHGetCapabilities */


RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag,
	DWORD Length, PUCHAR Value)
{
	/*
	 * This function should set the slot/card capabilities for a
	 * particular slot/card specified by Lun.  Again, if you have only 1
	 * card slot and don't mind loading a new driver for each reader then
	 * ignore Lun.
	 *
	 * Tag - the tag for the information needing set
	 *
	 * Length - the length of the returned data Value - the value of the
	 * data
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_ERROR_TAG IFD_ERROR_SET_FAILURE
	 * IFD_ERROR_VALUE_READ_ONLY
	 */

	// By default, say it worked

	DEBUG_PERIODIC2("entering IFDHSetCapabilities (lun: %X)", Lun);

	/* if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR; */

	return IFD_SUCCESS;
} /* IFDHSetCapabilities */


RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol,
	UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3)
{
	/*
	 * This function should set the PTS of a particular card/slot using
	 * the three PTS parameters sent
	 *
	 * Protocol - 0 .... 14 T=0 .... T=14 Flags - Logical OR of possible
	 * values: IFD_NEGOTIATE_PTS1 IFD_NEGOTIATE_PTS2 IFD_NEGOTIATE_PTS3 to
	 * determine which PTS values to negotiate. PTS1,PTS2,PTS3 - PTS
	 * Values.
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_ERROR_PTS_FAILURE IFD_COMMUNICATION_ERROR
	 * IFD_PROTOCOL_NOT_SUPPORTED
	 */

	DEBUG_INFO2("entering IFDHSetProtocolParameters (lun: %X)", Lun);

	/* if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR; */

	return IFD_SUCCESS;
} /* IFDHSetProtocolParameters */


RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action,
	PUCHAR Atr, PDWORD AtrLength)
{
	/*
	 * This function controls the power and reset signals of the smartcard
	 * reader at the particular reader/slot specified by Lun.
	 *
	 * Action - Action to be taken on the card.
	 *
	 * IFD_POWER_UP - Power and reset the card if not done so (store the
	 * ATR and return it and it's length).
	 *
	 * IFD_POWER_DOWN - Power down the card if not done already
	 * (Atr/AtrLength should be zero'd)
	 *
	 * IFD_RESET - Perform a quick reset on the card.  If the card is not
	 * powered power up the card.  (Store and return the Atr/Length)
	 *
	 * Atr - Answer to Reset of the card.  The driver is responsible for
	 * caching this value in case IFDHGetCapabilities is called requesting
	 * the ATR and it's length.  This should not exceed MAX_ATR_SIZE.
	 *
	 * AtrLength - Length of the Atr.  This should not exceed
	 * MAX_ATR_SIZE.
	 *
	 * Notes:
	 *
	 * Memory cards without an ATR should return IFD_SUCCESS on reset but
	 * the Atr should be zero'd and the length should be zero
	 *
	 * Reset errors should return zero for the AtrLength and return
	 * IFD_ERROR_POWER_ACTION.
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_ERROR_POWER_ACTION IFD_COMMUNICATION_ERROR
	 * IFD_NOT_SUPPORTED
	 */

	int nlength;
	RESPONSECODE return_value = IFD_SUCCESS;
	unsigned char pcbuffer[RESP_BUF_SIZE];

	DEBUG_INFO2("entering IFDHPowerICC (lun: %X)", Lun);

	// By default, assume it won't work :)
	*AtrLength = 0;

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	switch (Action)
	{
		case IFD_POWER_UP:
		case IFD_RESET:
			nlength = sizeof(pcbuffer);
			if (CmdPowerOn(Lun, &nlength, pcbuffer) != IFD_SUCCESS)
			{
				DEBUG_CRITICAL("PowerUp failed");
				return_value = IFD_ERROR_POWER_ACTION;
				goto end;
			}

			// Power up successful, set state variable to memorise it
			CcidSlots[LunToReaderIndex(Lun)].bPowerFlags |=
				MASK_POWERFLAGS_PUP;
			CcidSlots[LunToReaderIndex(Lun)].bPowerFlags &=
				~MASK_POWERFLAGS_PDWN;

			// Reset is returned, even if TCK is wrong
			CcidSlots[LunToReaderIndex(Lun)].nATRLength = *AtrLength =
				(nlength < MAX_ATR_SIZE) ? nlength : MAX_ATR_SIZE;
			memcpy(Atr, pcbuffer, *AtrLength);
			memcpy(CcidSlots[LunToReaderIndex(Lun)].pcATRBuffer,
				pcbuffer, *AtrLength);
			break;

		case IFD_POWER_DOWN:
			// Clear ATR buffer
			CcidSlots[LunToReaderIndex(Lun)].nATRLength = 0;
			*CcidSlots[LunToReaderIndex(Lun)].pcATRBuffer = '\0';

			// Memorise the request
			CcidSlots[LunToReaderIndex(Lun)].bPowerFlags |=
				MASK_POWERFLAGS_PDWN;
			// send the command
			return_value = CmdPowerOff(Lun);
			break;

		default:
			DEBUG_CRITICAL("IFDHPowerICC Action not supported");
			return_value = IFD_NOT_SUPPORTED;
	}
end:

	return return_value;
} /* IFDHPowerICC */


RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci,
	PUCHAR TxBuffer, DWORD TxLength,
	PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci)
{
	/*
	 * This function performs an APDU exchange with the card/slot
	 * specified by Lun.  The driver is responsible for performing any
	 * protocol specific exchanges such as T=0/1 ... differences.  Calling
	 * this function will abstract all protocol differences.
	 *
	 * SendPci Protocol - 0, 1, .... 14 Length - Not used.
	 *
	 * TxBuffer - Transmit APDU example (0x00 0xA4 0x00 0x00 0x02 0x3F
	 * 0x00) TxLength - Length of this buffer. RxBuffer - Receive APDU
	 * example (0x61 0x14) RxLength - Length of the received APDU.  This
	 * function will be passed the size of the buffer of RxBuffer and this
	 * function is responsible for setting this to the length of the
	 * received APDU.  This should be ZERO on all errors.  The resource
	 * manager will take responsibility of zeroing out any temporary APDU
	 * buffers for security reasons.
	 *
	 * RecvPci Protocol - 0, 1, .... 14 Length - Not used.
	 *
	 * Notes: The driver is responsible for knowing what type of card it
	 * has.  If the current slot/card contains a memory card then this
	 * command should ignore the Protocol and use the MCT style commands
	 * for support for these style cards and transmit them appropriately.
	 * If your reader does not support memory cards or you don't want to
	 * then ignore this.
	 *
	 * RxLength should be set to zero on error.
	 *
	 * returns:
	 *
	 * IFD_SUCCESS IFD_COMMUNICATION_ERROR IFD_RESPONSE_TIMEOUT
	 * IFD_ICC_NOT_PRESENT IFD_PROTOCOL_NOT_SUPPORTED
	 */

	RESPONSECODE return_value = IFD_SUCCESS;	// Assume it will work
	char protocol;

	DEBUG_INFO2("entering IFDHTransmitToICC (lun: %X)", Lun);

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	protocol = SendPci.Protocol;

	// if the reader is in EMV mode use ISO_EXCHANGE instead of ISO_INPUT
	// and ISO_OUTPUT. This is done with T=1 protocol
	if (CcidSlots[LunToReaderIndex(Lun)].bPowerFlags & MASK_POWERFLAGS_EMV)
		protocol = T_1;

	// Check if command is going to fit in buffer
	if (TxLength > CMD_BUF_SIZE)
	{
		// Buffer too small, send an error
		return_value = IFD_COMMUNICATION_ERROR;
		goto clean_up_and_return;
	}

	switch (protocol)
	{
		case T_0:
			// Size should be command + one byte of length for
			// an outgoing TPDU (CLA, INS, P1, P2, P3)
			if (TxLength == (ISO_CMD_SIZE + ISO_LENGTH_SIZE))
			{
printf("%s %d\n", __FILE__, __LINE__);
				return_value = CmdXfrBlock(Lun, TxLength, TxBuffer, RxLength,
					RxBuffer);
			}
			else
			{
				// just (CLA, INS, P1, P2) for an APDU
				if (TxLength == ISO_CMD_SIZE)
				{
printf("%s %d\n", __FILE__, __LINE__);
					return_value = CmdXfrBlock(Lun, TxLength, TxBuffer,
							RxLength, RxBuffer);
				}
				else
				{
					DWORD ntestlength;

printf("%s %d %ld %d\n", __FILE__, __LINE__, TxLength, ISO_CMD_SIZE + ISO_LENGTH_SIZE);
					if (TxLength > (ISO_CMD_SIZE + ISO_LENGTH_SIZE))
					{
						// Check length to see if it is a full APDU or a TPDU
						ntestlength = TxBuffer[ISO_OFFSET_LENGTH] +
							ISO_CMD_SIZE + ISO_LENGTH_SIZE;

printf("%s %d %ld\n", __FILE__, __LINE__, ntestlength);
						if (TxLength == (ntestlength + ISO_LENGTH_SIZE))
						{
							DWORD old_RxLength = *RxLength;

							// TxBuffer holds a proper APDU
							return_value = CmdXfrBlock(Lun, TxLength, TxBuffer, RxLength, RxBuffer);

							// Get Response
							if ((return_value == IFD_SUCCESS) &&
								(*RxLength == 2))
							{
								TxBuffer[0] = 0x00;
								TxBuffer[1] = 0xC0;
								TxBuffer[2] = 0x00;
								TxBuffer[3] = 0x00;
								TxBuffer[4] = RxBuffer[1];
								*RxLength = old_RxLength;
								TxLength = 5;

								return_value = CmdXfrBlock(Lun, TxLength, TxBuffer, RxLength, RxBuffer);
							}
						}
						else
						{
							if (TxLength > (ntestlength + ISO_LENGTH_SIZE))
							{
printf("%s %d\n", __FILE__, __LINE__);
								// Data are too long
								return_value = IFD_COMMUNICATION_ERROR;

								goto clean_up_and_return;
							}
							else
							{
printf("%s %d\n", __FILE__, __LINE__);
								// TxBuffer holds a proper TPDU
								return_value = CmdXfrBlock(Lun, TxLength, TxBuffer, RxLength, RxBuffer);
							}
						}
					}
					else
					{
printf("%s %d\n", __FILE__, __LINE__);
						// TxBuffer holds too little data to form an APDU+length
						return_value = IFD_COMMUNICATION_ERROR;

						goto clean_up_and_return;
					}
				}
			}
			break;

		case T_1:
			return_value = CmdXfrBlock(Lun, TxLength, TxBuffer, RxLength,
				RxBuffer);
			break;

		default:
			return_value = IFD_PROTOCOL_NOT_SUPPORTED;
	}

clean_up_and_return:
	if (return_value != IFD_SUCCESS)
		*RxLength = 0;

	return return_value;
} /* IFDHTransmitToICC */


RESPONSECODE IFDHControl(DWORD Lun, PUCHAR TxBuffer,
	DWORD TxLength, PUCHAR RxBuffer, PDWORD RxLength)
{
	/*
	 * This function performs a data exchange with the reader (not the
	 * card) specified by Lun.  Here XXXX will only be used. It is
	 * responsible for abstracting functionality such as PIN pads,
	 * biometrics, LCD panels, etc.  You should follow the MCT, CTBCS
	 * specifications for a list of accepted commands to implement.
	 *
	 * TxBuffer - Transmit data TxLength - Length of this buffer. RxBuffer
	 * - Receive data RxLength - Length of the received data.  This
	 * function will be passed the length of the buffer RxBuffer and it
	 * must set this to the length of the received data.
	 *
	 * Notes: RxLength should be zero on error.
	 */

	DEBUG_INFO2("entering IFDHControl (lun: %X)", Lun);

	/* if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR; */

	return IFD_SUCCESS;
} /* IFDHControl */


RESPONSECODE IFDHICCPresence(DWORD Lun)
{
	/*
	 * This function returns the status of the card inserted in the
	 * reader/slot specified by Lun.  It will return either:
	 *
	 * returns: IFD_ICC_PRESENT IFD_ICC_NOT_PRESENT
	 * IFD_COMMUNICATION_ERROR
	 */

	unsigned char pcbuffer[SIZE_GET_SLOT_STATUS];
	RESPONSECODE return_value = IFD_COMMUNICATION_ERROR;

	DEBUG_PERIODIC2("entering IFDHICCPresence (lun: %X)", Lun);

	if (CheckLun(Lun))
		return IFD_COMMUNICATION_ERROR;

	if (CmdGetSlotStatus(Lun, pcbuffer) != IFD_SUCCESS)
		return IFD_COMMUNICATION_ERROR;

	switch (pcbuffer[7])	/* bStatus */
	{
		case 0x00:
			return_value = IFD_ICC_PRESENT;
			break;

		case 0x01:
			return_value = IFD_ICC_PRESENT;
			break;

		case 0x02:
			return_value = IFD_ICC_NOT_PRESENT;
			break;
	}

	return return_value;
} /* IFDHICCPresence */

void IFDSetEmv(DWORD lun)
{
	CcidSlots[LunToReaderIndex(lun)].bPowerFlags |= MASK_POWERFLAGS_EMV;
} /* IFDSetEmv */
