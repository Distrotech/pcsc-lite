#! /usr/bin/env python

#   SCardBeginTransaction_Disconnect.py : Unitary test for SCardDisconnect()
#   Copyright (C) 2009  Ludovic Rousseau
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

# A bug has been corrected in revision 3467
# The problem occurs if SCardBeginTransaction() are made without
# corresponding SCardEndTransaction(). OpenSC "pkcs11-tool -I" exhibits
# such a behavior.

from smartcard.scard import *

hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to establish context: ' + SCardGetErrorMessage(hresult))

hresult, readers = SCardListReaders(hcontext, [])
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to list readers: ' + SCardGetErrorMessage(hresult))
print 'PC/SC Readers:', readers

hresult, hcard, dwActiveProtocol = SCardConnect(hcontext, readers[0], SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to SCardConnect: ' + SCardGetErrorMessage(hresult))

hresult = SCardBeginTransaction(hcard)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to SCardBeginTransaction: ' + SCardGetErrorMessage(hresult))

hresult = SCardBeginTransaction(hcard)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to SCardBeginTransaction: ' + SCardGetErrorMessage(hresult))

hresult = SCardDisconnect(hcard, SCARD_RESET_CARD)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to SCardDisconnect: ' + SCardGetErrorMessage(hresult))

hresult = SCardReleaseContext(hcontext)
if hresult != SCARD_S_SUCCESS:
    raise Exception('Failed to release context: ' + SCardGetErrorMessage(hresult))
