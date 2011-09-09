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

        (function, rv) = line.split(':')
        if function[0] != '<':
            raise Exception("Wrong line:", line)

        return rv

    def _log_rv(self):
        """ log the return value """
        line = self.filedesc.readline().strip()
        rv = self._parse_rv(line)
        if not "0x00000000" in rv:
            print PCSCspy.color_red + " =>" + rv + PCSCspy.color_normal
        else:
            print " =>", rv

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

    def log_out_hContext(self):
        """ log hContext OUT parameter """
        hContext = self.filedesc.readline().strip()
        self.log_out("hContext: %s" % hContext)

    def log_in2(self, header):
        """ generic log IN parameter """
        data = self.filedesc.readline().strip()
        self.log_in("%s %s" % (header, data))

    def log_out2(self, header):
        """ generic log OUT parameter """
        data = self.filedesc.readline().strip()
        self.log_out("%s %s" % (header, data))

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
        log = self.log_in2
        if (direction == 1):
            log = self.log_out2
        for index in range(readers):
            log("szReader:")
            log(" dwCurrentState:")
            log(" dwEventState:")
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
        self._log_readers(readers, direction = 0)
        self._log_readers(readers, direction = 1)
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
        self.log_in2("dwShareMode")
        self.log_in2("dwPreferredProtocols")
        self.log_in2("phCard")
        self.log_in2("pdwActiveProtocol")
        self.log_out2("phCard")
        self.log_out2("pdwActiveProtocol")
        self._log_rv()

    def _SCardTransmit(self):
        """ SCardTransmit """
        self.log_name("SCardTransmit")
        self.log_in_hCard()
        self.log_in2("bSendBuffer")
        self.log_out2("bRecvBuffer")
        self._log_rv()

    def _SCardControl(self):
        """ SCardControl """
        self.log_name("SCarControl")
        self.log_in_hCard()
        self.log_in2("dwControlCode")
        self.log_in2("bSendBuffer")
        self.log_out2("bRecvBuffer")
        self._log_rv()

    def _SCardGetAttrib(self):
        """ SCardGetAttrib """
        self.log_name("SCardGetAttrib")
        self.log_in_hCard()
        self.log_in2("dwAttrId")
        self.log_out2("bAttr")
        self._log_rv()

    def _SCardSetAttrib(self):
        """ SCardSetAttrib """
        self.log_name("SCardSetAttrib")
        self.log_in_hCard()
        self.log_in2("dwAttrId")
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
        self.log_out2("bAtr")
        self._log_rv()

    def _SCardReconnect(self):
        """ SCardReconnect """
        self.log_name("SCardReconnect")
        self.log_in_hCard()
        self.log_in2("dwShareMode")
        self.log_in2("dwPreferredProtocols")
        self.log_in2("dwInitialization")
        self.log_out2("dwActiveProtocol")
        self._log_rv()

    def _SCardDisconnect(self):
        """" SCardDisconnect """
        self.log_name("SCardDisconnect")
        self.log_in_hCard()
        self.log_in2("dwDisposition")
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

        self.filedesc = open(self.fifo, 'r')
        #import sys
        #self.filedesc = sys.stdin

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
                fct = line[2:-1]
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
                else:
                    print "Unknown function:", fct

            line = self.filedesc.readline()


def main():
    """ main """
    spy = PCSCspy()
    spy.loop()


if __name__ == "__main__":
    main()
