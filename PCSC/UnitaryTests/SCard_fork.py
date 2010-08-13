#! /usr/bin/env python

#   SCardCancel.py : Unitary test for SCardCancel()
#   Copyright (C) 2008-2009  Ludovic Rousseau
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


from smartcard.scard import *
from smartcard.pcsc.PCSCExceptions import *
import time
import os


hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
if hresult != SCARD_S_SUCCESS:
    raise EstablishContextException(hresult)

hresult, readers = SCardListReaders(hcontext, [])
if hresult != SCARD_S_SUCCESS:
    raise ListReadersException(hresult)
print 'PC/SC Readers:', readers

reader = readers[0]
print "Using reader:", reader

hresult, hcard, dwActiveProtocol = SCardConnect(hcontext, reader,
    SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY)
if hresult != SCARD_S_SUCCESS:
    raise BaseSCardException(hresult)

pid = os.fork()
if pid == 0:
    # son

    # the handle should be invalid after a fork
    hresult, readers = SCardListReaders(hcontext, [])

    # expected value
    if hresult == SCARD_E_INVALID_HANDLE:
        print "test passed"
    elif hresult != SCARD_S_SUCCESS:
        raise ListReadersException(hresult)
    else:
        print "test failed"

    hresult = SCardDisconnect(hcard, SCARD_LEAVE_CARD)
    if hresult != SCARD_S_SUCCESS:
        raise BaseSCardException(hresult)

    hresult = SCardReleaseContext(hcontext)
    print "SCardReleaseContext()", SCardGetErrorMessage(hresult)
    if hresult != SCARD_S_SUCCESS:
        raise ReleaseContextException(hresult)

else:
    # father

    # give some time to the son
    time.sleep(1)

    hresult = SCardDisconnect(hcard, SCARD_LEAVE_CARD)
    if hresult != SCARD_S_SUCCESS:
        raise BaseSCardException(hresult)

    hresult = SCardReleaseContext(hcontext)
    print "SCardReleaseContext()", SCardGetErrorMessage(hresult)
    if hresult != SCARD_S_SUCCESS:
        raise ReleaseContextException(hresult)
