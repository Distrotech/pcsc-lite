#! /usr/bin/env python

"""
#    Display PC/SC functions arguments
#    Copyright (C) 2011  Ludovic Rousseau
"""
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# $Id$

import os


class PCSCspy(object):
    """ PC/SC spy """

    color_red = "\x1b[01;31m"
    color_green = "\x1b[32m"
    color_blue = "\x1b[34m"
    color_magenta = "\x1b[35m"
    color_normal = "\x1b[0m"

    def _parse_rv(self, line):
        """ parse the return value line """
        if line == "":
            raise Exception("Empty line (application exited?)")

        (direction, sec, usec, function, code, rv) = line.split('|')
        if direction != '<':
            raise Exception("Wrong line:", line)

        sec = int(sec)
        usec = int(usec)

        return (code, rv, sec, usec)

    def _log_rv(self):
        """ log the return value """
        line = self.filedesc.readline().strip()
        (code, rv, sec, usec) = self._parse_rv(line)
        delta_sec = sec - self.sec
        delta_usec = usec - self.usec
        if delta_usec < 0:
            delta_sec -= 1
            delta_usec += 1000000
        time = " [%d.%09d]" % (delta_sec, delta_usec)

        rvs = {
            0x00000000: "SCARD_S_SUCCESS",
            0x80100001: "SCARD_F_INTERNAL_ERROR",
            0x80100002: "SCARD_E_CANCELLED",
            0x80100003: "SCARD_E_INVALID_HANDLE",
            0x80100004: "SCARD_E_INVALID_PARAMETER",
            0x80100005: "SCARD_E_INVALID_TARGET",
            0x80100006: "SCARD_E_NO_MEMORY",
            0x80100007: "SCARD_F_WAITED_TOO_LONG",
            0x80100008: "SCARD_E_INSUFFICIENT_BUFFER",
            0x80100009: "SCARD_E_UNKNOWN_READER",
            0x8010000A: "SCARD_E_TIMEOUT",
            0x8010000B: "SCARD_E_SHARING_VIOLATION",
            0x8010000C: "SCARD_E_NO_SMARTCARD",
            0x8010000D: "SCARD_E_UNKNOWN_CARD",
            0x8010000E: "SCARD_E_CANT_DISPOSE",
            0x8010000F: "SCARD_E_PROTO_MISMATCH",
            0x80100010: "SCARD_E_NOT_READY",
            0x80100011: "SCARD_E_INVALID_VALUE",
            0x80100012: "SCARD_E_SYSTEM_CANCELLED",
            0x80100013: "SCARD_F_COMM_ERROR",
            0x80100014: "SCARD_F_UNKNOWN_ERROR",
            0x80100015: "SCARD_E_INVALID_ATR",
            0x80100016: "SCARD_E_NOT_TRANSACTED",
            0x80100017: "SCARD_E_READER_UNAVAILABLE",
            0x80100018: "SCARD_P_SHUTDOWN",
            0x80100019: "SCARD_E_PCI_TOO_SMALL",
            0x8010001A: "SCARD_E_READER_UNSUPPORTED",
            0x8010001B: "SCARD_E_DUPLICATE_READER",
            0x8010001C: "SCARD_E_CARD_UNSUPPORTED",
            0x8010001D: "SCARD_E_NO_SERVICE",
            0x8010001E: "SCARD_E_SERVICE_STOPPED",
            0x8010001F: "SCARD_E_UNSUPPORTED_FEATURE",
            0x80100020: "SCARD_E_ICC_INSTALLATION",
            0x80100021: "SCARD_E_ICC_CREATEORDER",
            0x80100023: "SCARD_E_DIR_NOT_FOUND",
            0x80100024: "SCARD_E_FILE_NOT_FOUND",
            0x80100025: "SCARD_E_NO_DIR",
            0x80100026: "SCARD_E_NO_FILE",
            0x80100027: "SCARD_E_NO_ACCESS",
            0x80100028: "SCARD_E_WRITE_TOO_MANY",
            0x80100029: "SCARD_E_BAD_SEEK",
            0x8010002A: "SCARD_E_INVALID_CHV",
            0x8010002B: "SCARD_E_UNKNOWN_RES_MNG",
            0x8010002C: "SCARD_E_NO_SUCH_CERTIFICATE",
            0x8010002D: "SCARD_E_CERTIFICATE_UNAVAILABLE",
            0x8010002E: "SCARD_E_NO_READERS_AVAILABLE",
            0x8010002F: "SCARD_E_COMM_DATA_LOST",
            0x80100030: "SCARD_E_NO_KEY_CONTAINER",
            0x80100031: "SCARD_E_SERVER_TOO_BUSY",
            0x80100065: "SCARD_W_UNSUPPORTED_CARD",
            0x80100066: "SCARD_W_UNRESPONSIVE_CARD",
            0x80100067: "SCARD_W_UNPOWERED_CARD",
            0x80100068: "SCARD_W_RESET_CARD",
            0x80100069: "SCARD_W_REMOVED_CARD",
            0x8010006A: "SCARD_W_SECURITY_VIOLATION",
            0x8010006B: "SCARD_W_WRONG_CHV",
            0x8010006C: "SCARD_W_CHV_BLOCKED",
            0x8010006D: "SCARD_W_EOF",
            0x8010006E: "SCARD_W_CANCELLED_BY_USER",
            0x8010006F: "SCARD_W_CARD_NOT_AUTHENTICATED",
            }
        rv_text = rvs[int(rv, 16)]
        data = " => " + code + " (" + rv_text + " [" + rv + "]) "
        if "0x00000000" != rv:
            print PCSCspy.color_red + data + PCSCspy.color_normal + time
        else:
            print data + time

    def log_in(self, line):
        """ generic log for IN line """
        print PCSCspy.color_green + " i " + line + PCSCspy.color_normal

    def log_out(self, line):
        """ generic log for OUT line """
        print PCSCspy.color_magenta + " o " + line + PCSCspy.color_normal

    def log_in_hCard(self):
        """ log hCard IN parameter """
        hContext = self.filedesc.readline().strip()
        self.log_in("hCard: %s" % hContext)

    def log_in_hContext(self):
        """ log hContext IN parameter """
        hContext = self.filedesc.readline().strip()
        self.log_in("hContext: %s" % hContext)

    def log_in_disposition(self):
        """ log dwDisposition IN parameter """
        dwDisposition = self.filedesc.readline().strip()
        dispositions = {0: 'SCARD_LEAVE_CARD',
            1: 'SCARD_RESET_CARD',
            2: 'SCARD_UNPOWER_CARD',
            3: 'SCARD_EJECT_CARD'}
        try:
            disposition = dispositions[int(dwDisposition, 16)]
        except KeyError:
            disposition = "UNKNOWN"
        self.log_in("dwDisposition: %s (%s)" % (disposition,
            dwDisposition))

    def log_in_attrid(self):
        """ log dwAttrId IN parameter """
        dwAttrId = self.filedesc.readline().strip()
        attrids = {0x00010100: 'SCARD_ATTR_VENDOR_NAME',
                0x00010102: 'SCARD_ATTR_VENDOR_IFD_VERSION',
                0x00010103: 'SCARD_ATTR_VENDOR_IFD_SERIAL_NO',
                0x0007A007: 'SCARD_ATTR_MAXINPUT',
                0x00090300: 'SCARD_ATTR_ICC_PRESENCE',
                0x00090301: 'SCARD_ATTR_ICC_INTERFACE_STATUS',
                0x00090303: 'SCARD_ATTR_ATR_STRING',
                0x7FFF0003: 'SCARD_ATTR_DEVICE_FRIENDLY_NAME'}
        try:
            attrid = attrids[int(dwAttrId, 16)]
        except KeyError:
            attrid = "UNKNOWN"
        self.log_in("dwAttrId: %s (%s)" % (attrid, dwAttrId))

    def log_in_dwShareMode(self):
        """ log dwShareMode IN parameter """
        dwShareMode = self.filedesc.readline().strip()
        sharemodes = {1: 'SCARD_SHARE_EXCLUSIVE',
                2: 'SCARD_SHARE_SHARED',
                3: 'SCARD_SHARE_DIRECT'}
        try:
            sharemode = sharemodes[int(dwShareMode, 16)]
        except KeyError:
            sharemode = "UNKNOWN"
        self.log_in("dwShareMode: %s (%s)" % (sharemode, dwShareMode))

    def log_in_dwPreferredProtocols(self):
        """ log dwPreferredProtocols IN parameter """
        dwPreferredProtocols = self.filedesc.readline().strip()
        PreferredProtocols = list()
        protocol = int(dwPreferredProtocols, 16)
        if protocol & 1:
            PreferredProtocols.append("T=0")
        if protocol & 2:
            PreferredProtocols.append("T=1")
        if protocol & 4:
            PreferredProtocols.append("RAW")
        if protocol & 8:
            PreferredProtocols.append("T=15")
        self.log_in("dwPreferredProtocols: %s (%s)" % (dwPreferredProtocols,
            ", ".join(PreferredProtocols)))

    def log_out_dwActiveProtocol(self):
        """ log dwActiveProtocol OUT parameter """
        dwActiveProtocol = self.filedesc.readline().strip()
        protocol = int(dwActiveProtocol, 16)
        if protocol & 1:
            protocol = "T=0"
        elif protocol & 2:
            protocol = "T=1"
        elif protocol & 4:
            protocol = "RAW"
        elif protocol & 8:
            protocol = "T=15"
        else:
            protocol = "UNKNOWN"
        self.log_out("dwActiveProtocol: %s (%s)" % (protocol,
            dwActiveProtocol))

    def log_out_hContext(self):
        """ log hContext OUT parameter """
        hContext = self.filedesc.readline().strip()
        self.log_out("hContext: %s" % hContext)

    def _get_state(self, dwState):
        """ parse dwCurrentState and dwEventState """
        SCardStates = {0: 'SCARD_STATE_UNAWARE',
            1: 'SCARD_STATE_IGNORE',
            2: 'SCARD_STATE_CHANGED',
            4: 'SCARD_STATE_UNKNOWN',
            8: 'SCARD_STATE_UNAVAILABLE',
            16: 'SCARD_STATE_EMPTY',
            32: 'SCARD_STATE_PRESENT',
            64: 'SCARD_STATE_ATRMATCH',
            128: 'SCARD_STATE_EXCLUSIVE',
            256: 'SCARD_STATE_INUSE',
            512: 'SCARD_STATE_MUTE',
            1024: 'SCARD_STATE_UNPOWERED'}

        state = list()
        for bit in SCardStates.keys():
            if dwState & bit:
                state.append(SCardStates[bit])
        return ", ".join(state)

    def log_dwCurrentState(self, log):
        """ log dwCurrentState IN/OUT parameter """
        dwCurrentState = self.filedesc.readline().strip()
        state = self._get_state(int(dwCurrentState, 16))
        log(" dwCurrentState: %s (%s)" % (state, dwCurrentState))

    def log_dwEventState(self, log):
        """ log dwEventState IN/OUT parameter """
        dwEventState = self.filedesc.readline().strip()
        state = self._get_state(int(dwEventState, 16))
        log(" dwEventState: %s (%s)" % (state, dwEventState))

    def log_dwControlCode(self):
        """ log SCardControl() dwControlCode """
        dwControlCode = self.filedesc.readline().strip()

        try:
            code = self.ControlCodes[int(dwControlCode, 16)]
        except KeyError:
            code = "UNKNOWN"
        self.log_in("dwControlCode: %s (%s)" % (code, dwControlCode))

        return int(dwControlCode, 16)

    def log_in2(self, header):
        """ generic log IN parameter """
        data = self.filedesc.readline().strip()
        self.log_in("%s %s" % (header, data))
        return data

    def log_out2(self, header):
        """ generic log OUT parameter """
        data = self.filedesc.readline().strip()
        self.log_out("%s %s" % (header, data))
        return data

    def log_out_n_str(self, size_name, field_name):
        """ log multi-lines entries """
        data = self.filedesc.readline().strip()
        self.log_out("%s %s" % (size_name, data))
        size = int(data, 16)
        data_read = 0
        while data_read < size:
            data = self.filedesc.readline().strip()
            self.log_out("%s %s" % (field_name, data))
            if data == 'NULL':
                break
            data_read += len(data) + 1

    def log_name(self, name):
        """ log function name """
        print PCSCspy.color_blue + name + PCSCspy.color_normal

    def _log_readers(self, readers, direction):
        """ log SCARD_READERSTATE structure """
        log = self.log_in2
        raw_log = self.log_in
        if (direction == 1):
            log = self.log_out2
            raw_log = self.log_out
        for index in range(readers):
            log("szReader:")
            self.log_dwCurrentState(raw_log)
            self.log_dwEventState(raw_log)
            log(" Atr length:")
            log(" Atr:")

    def _SCardEstablishContext(self):
        """ SCardEstablishContext """
        self.log_name("SCardEstablishContext")
        dwScope = self.filedesc.readline().strip()
        scopes = {0: 'SCARD_SCOPE_USER',
                1: 'SCARD_SCOPE_TERMINAL',
                2: 'SCARD_SCOPE_SYSTEM'}
        self.log_in("dwScope: %s (%s)" % (scopes[int(dwScope, 16)], dwScope))
        self.log_out_hContext()
        self._log_rv()

    def _SCardIsValidContext(self):
        """ SCardIsValidContext """
        self.log_name("SCardIsValidContext")
        self.log_in_hContext()
        self._log_rv()

    def _SCardReleaseContext(self):
        """ SCardReleaseContext """
        self.log_name("SCardReleaseContext")
        self.log_in_hContext()
        self._log_rv()

    def _SCardListReaders(self):
        """ SCardListReaders """
        self.log_name("SCardListReaders")
        self.log_in_hContext()
        self.log_in2("mszGroups:")
        self.log_out_n_str("pcchReaders:", "mszReaders:")
        self._log_rv()

    def _SCardListReaderGroups(self):
        """ SCardListReaderGroups """
        self.log_name("SCardListReaderGroups")
        self.log_in_hContext()
        self.log_in2("pcchGroups:")
        self.log_out_n_str("pcchGroups:", "mszGroups:")
        self._log_rv()

    def _SCardGetStatusChange(self):
        """ SCardGetStatusChange """
        self.log_name("SCardGetStatusChange")
        self.log_in_hContext()
        self.log_in2("dwTimeout:")
        readers = int(self.filedesc.readline().strip(), 16)
        self.log_in("cReaders: %d" % readers)
        self._log_readers(readers, direction=0)
        self._log_readers(readers, direction=1)
        self._log_rv()

    def _SCardFreeMemory(self):
        """ SCardFreeMemory """
        self.log_name("SCardFreeMemory")
        self.log_in_hContext()
        self.log_in2("pvMem:")
        self._log_rv()

    def _SCardConnect(self):
        """ SCardConnect """
        self.log_name("SCardConnect")
        self.log_in_hContext()
        self.log_in2("szReader")
        self.log_in_dwShareMode()
        self.log_in_dwPreferredProtocols()
        self.log_in2("phCard")
        self.log_in2("pdwActiveProtocol")
        self.log_out2("phCard")
        self.log_out_dwActiveProtocol()
        self._log_rv()

    def _SCardTransmit(self):
        """ SCardTransmit """
        self.log_name("SCardTransmit")
        self.log_in_hCard()
        self.log_in2("bSendLength")
        self.log_in2("bSendBuffer")
        self.log_out2("bRecvLength")
        self.log_out2("bRecvBuffer")
        self._log_rv()

    def _SCardControl(self):
        """ SCardControl """
        self.log_name("SCarControl")
        self.log_in_hCard()
        dwControlCode = self.log_dwControlCode()
        self.log_in2("bSendLength")
        self.log_in2("bSendBuffer")
        bRecvLength = self.log_out2("bRecvLength")
        bRecvBuffer = self.log_out2("bRecvBuffer")

        def hex2int(data, lengh):
            return [int(x, 16) for x in data.split(" ")]

        if dwControlCode == self.CM_IOCTL_GET_FEATURE_REQUEST:
            bRecvLength = int(bRecvLength, 16)

            # remove the ASCII part at the end
            bRecvBuffer = bRecvBuffer[0:bRecvLength*3-1]
            bRecvBuffer = hex2int(bRecvBuffer, bRecvLength)

            features = {0x01: "FEATURE_VERIFY_PIN_START",
                0x02: "FEATURE_VERIFY_PIN_FINISH",
                0x03: "FEATURE_MODIFY_PIN_START",
                0x04: "FEATURE_MODIFY_PIN_FINISH",
                0x05: "FEATURE_GET_KEY_PRESSED",
                0x06: "FEATURE_VERIFY_PIN_DIRECT",
                0x07: "FEATURE_MODIFY_PIN_DIRECT",
                0x08: "FEATURE_MCT_READER_DIRECT",
                0x09: "FEATURE_MCT_UNIVERSAL",
                0x0A: "FEATURE_IFD_PIN_PROPERTIES",
                0x0B: "FEATURE_ABORT",
                0x0C: "FEATURE_SET_SPE_MESSAGE",
                0x0D: "FEATURE_VERIFY_PIN_DIRECT_APP_ID",
                0x0E: "FEATURE_MODIFY_PIN_DIRECT_APP_ID",
                0x0F: "FEATURE_WRITE_DISPLAY",
                0x10: "FEATURE_GET_KEY",
                0x11: "FEATURE_IFD_DISPLAY_PROPERTIES",
                0x12: "FEATURE_GET_TLV_PROPERTIES",
                0x13: "FEATURE_CCID_ESC_COMMAND"}

            # parse GET_FEATURE_REQUEST results
            while bRecvBuffer:
                tag = bRecvBuffer[0]
                length = bRecvBuffer[1]
                value = bRecvBuffer[2:2+length]
                value_int = value[3] + 256 * (value[2] + 256 * (value[1] + 256 *value[0]))
                try:
                    self.ControlCodes[value_int] = features[tag]
                except KeyError:
                    self.ControlCodes[value_int] = "UNKNOWN"

                print "  Tag %s is 0x%X" % (self.ControlCodes[value_int],
                        value_int)

                bRecvBuffer = bRecvBuffer[2+length:]

        self._log_rv()

    def _SCardGetAttrib(self):
        """ SCardGetAttrib """
        self.log_name("SCardGetAttrib")
        self.log_in_hCard()
        self.log_in_attrid()
        self.log_out2("bAttrLen")
        self.log_out2("bAttr")
        self._log_rv()

    def _SCardSetAttrib(self):
        """ SCardSetAttrib """
        self.log_name("SCardSetAttrib")
        self.log_in_hCard()
        self.log_in_attrid()
        self.log_in2("bAttrLen")
        self.log_in2("bAttr")
        self._log_rv()

    def _SCardStatus(self):
        """ SCardStatus """
        self.log_name("SCardStatus")
        self.log_in_hCard()
        self.log_in2("pcchReaderLen")
        self.log_in2("pcbAtrLen")
        self.log_out2("cchReaderLen")
        self.log_out2("mszReaderName")
        self.log_out2("dwState")
        self.log_out2("dwProtocol")
        self.log_out2("bAtrLen")
        self.log_out2("bAtr")
        self._log_rv()

    def _SCardReconnect(self):
        """ SCardReconnect """
        self.log_name("SCardReconnect")
        self.log_in_hCard()
        self.log_in_dwShareMode()
        self.log_in_dwPreferredProtocols()
        self.log_in2("dwInitialization")
        self.log_out_dwActiveProtocol()
        self._log_rv()

    def _SCardDisconnect(self):
        """" SCardDisconnect """
        self.log_name("SCardDisconnect")
        self.log_in_hCard()
        self.log_in_disposition()
        self._log_rv()

    def _SCardBeginTransaction(self):
        """ SCardBeginTransaction """
        self.log_name("SCardBeginTransaction")
        self.log_in_hCard()
        self._log_rv()

    def _SCardEndTransaction(self):
        """ SCardEndTransaction """
        self.log_name("SCardEndTransaction")
        self.log_in_hCard()
        self.log_in_disposition()
        self._log_rv()

    def __del__(self):
        """ cleanup """
        os.unlink(self.fifo)

    def __init__(self):
        self.fifo = os.path.expanduser('~/pcsc-spy')

        # create the FIFO file
        try:
            os.mkfifo(self.fifo)
        except (OSError):
            print "fifo %s already present. Reusing it." % self.fifo

        self.sec = self.usec = 0

        self.filedesc = open(self.fifo, 'r')
        #import sys
        #self.filedesc = sys.stdin

        def SCARD_CTL_CODE(code):
            return 0x42000000 + code

        self.CM_IOCTL_GET_FEATURE_REQUEST = SCARD_CTL_CODE(3400)
        self.ControlCodes = {
            SCARD_CTL_CODE(1): "IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE",
            SCARD_CTL_CODE(3400): "CM_IOCTL_GET_FEATURE_REQUEST"
            }

    def loop(self):
        """ loop reading logs """

        # check version
        version = self.filedesc.readline().strip()
        if version != "PCSC SPY VERSION: 1":
            print "Wrong version:", version
            return

        line = self.filedesc.readline()
        while line != '':
            # Enter function?
            if line[0] != '>':
                print "Garbage: ", line
            else:
                # dispatch
                (direction, sec, usec, fct) = line.strip().split('|')
                self.sec = int(sec)
                self.usec = int(usec)
                if fct == 'SCardEstablishContext':
                    self._SCardEstablishContext()
                elif fct == 'SCardReleaseContext':
                    self._SCardReleaseContext()
                elif fct == 'SCardIsValidContext':
                    self._SCardIsValidContext()
                elif fct == 'SCardListReaderGroups':
                    self._SCardListReaderGroups()
                elif fct == 'SCardFreeMemory':
                    self._SCardFreeMemory()
                elif fct == 'SCardListReaders':
                    self._SCardListReaders()
                elif fct == 'SCardGetStatusChange':
                    self._SCardGetStatusChange()
                elif fct == 'SCardConnect':
                    self._SCardConnect()
                elif fct == 'SCardTransmit':
                    self._SCardTransmit()
                elif fct == 'SCardControl':
                    self._SCardControl()
                elif fct == 'SCardGetAttrib':
                    self._SCardGetAttrib()
                elif fct == 'SCardSetAttrib':
                    self._SCardSetAttrib()
                elif fct == 'SCardStatus':
                    self._SCardStatus()
                elif fct == 'SCardReconnect':
                    self._SCardReconnect()
                elif fct == 'SCardDisconnect':
                    self._SCardDisconnect()
                elif fct == 'SCardBeginTransaction':
                    self._SCardBeginTransaction()
                elif fct == 'SCardEndTransaction':
                    self._SCardEndTransaction()
                else:
                    print "Unknown function:", fct

            line = self.filedesc.readline()


def main():
    """ main """
    spy = PCSCspy()
    spy.loop()


if __name__ == "__main__":
    main()
