# Process this file with automake to create Makefile.in.

lib_LTLIBRARIES = libPcscdAuth.la libIfdAuth.la libValidate.la

AM_CPPFLAGS = -I$(top_srcdir)/src/PCSC -I$(top_builddir)/src/PCSC

libPcscdAuth_la_SOURCES = pcscdAuth_generic.c
libPcscdAuth_la_CFLAGS = $(CFLAGS) -D_RENTRANT -Kpic
libPcscdAuth_la_LIBADD = $(LIBSOCKET) $(LIBNSL)

libIfdAuth_la_SOURCES = ifdAuth_generic.c
libIfdAuth_la_CFLAGS = $(CFLAGS) -D_RENTRANT -Kpic
libIfdAuth_la_LIBADD = $(LIBSOCKET) $(LIBNSL)
	
libValidate_la_SOURCES = validate_generic.c
libValidate_la_CFLAGS = $(CFLAGS) -D_REENTRANT -Kpic
libValidate_la_LIBADD = $(LIBSOCKET) $(LIBNSL) 

confdir = $(datadir)
conf_DATA = pcscd_validate.conf

