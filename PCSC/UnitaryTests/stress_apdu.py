#! /usr/bin/env python

"""
    stress_apdu.py: send an apdu in loop
    Copyright (C) 2010  Ludovic Rousseau
"""

#   this program is free software; you can redistribute it and/or modify
#   it under the terms of the gnu general public license as published by
#   the free software foundation; either version 2 of the license, or
#   (at your option) any later version.
#
#   this program is distributed in the hope that it will be useful,
#   but without any warranty; without even the implied warranty of
#   merchantability or fitness for a particular purpose.  see the
#   gnu general public license for more details.
#
#   you should have received a copy of the gnu general public license along
#   with this program; if not, write to the free software foundation, inc.,
#   51 franklin street, fifth floor, boston, ma 02110-1301 usa.

from smartcard.System import readers
from time import time, ctime


def stress(reader):
    # define the APDUs used in this script
    SELECT = [0x00, 0xA4, 0x04, 0x00, 0x0A, 0xA0, 0x00, 0x00, 0x00, 0x62,
        0x03, 0x01, 0x0C, 0x06, 0x01]
    COMMAND = [0x00, 0x00, 0x00, 0x00]

    connection = reader.createConnection()
    connection.connect()

    data, sw1, sw2 = connection.transmit(SELECT)
    print data
    print "Select Applet: %02X %02X" % (sw1, sw2)

    i = 0
    while True:
        before = time()
        data, sw1, sw2 = connection.transmit(COMMAND)
        after = time()
        print data
        delta = after - before
        print "%d Command: %02X %02X, delta: %f" % (i, sw1, sw2, delta)
        if delta > 1:
            sys.stderr.write(ctime() + " %f\n" % delta)
        i += 1

if __name__ == "__main__":
    import sys

    # get all the available readers
    readers = readers()
    print "Available readers:"
    i = 0
    for r in readers:
        print "%d: %s" % (i, r)
        i += 1

    try:
        i = int(sys.argv[1])
    except IndexError:
        i = 0

    reader = readers[i]
    print "Using:", reader

    stress(reader)