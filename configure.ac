# -*- mode: m4; -*-
# Process this file with autoconf to produce a configure script

m4_pattern_allow([AC_MSG_ERROR])
m4_pattern_allow([AS_AC_EXPAND])
m4_pattern_allow([AC_DEFINE])
m4_pattern_allow([AC_MSG_WARN])
m4_pattern_allow([AC_VERBOSE])
m4_pattern_allow([AC_PROGRAM_CHECK])
m4_pattern_allow([_PKG_SHORT_ERRORS_SUPPORTED])

AC_PREREQ(2.60)

AC_INIT([pcsclite with Solaris security and scalability enhancements],[1.1])
AC_CONFIG_SRCDIR([src/pcscdaemon.c])
AM_INIT_AUTOMAKE(1.10)
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_HOST
AC_PROG_CC
AC_C_BIGENDIAN

# Check for some target-specific stuff
case "$host" in
*-*-hpux*)
	CPPFLAGS="$CPPFLAGS -D_HPUX_SOURCE -D_XOPEN_SOURCE_EXTENDED"
	;;
*-*-solaris*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include"
	LDFLAGS="$LDFLAGS -L/usr/local/lib -R/usr/local/lib"
	need_dash_r=1
	;;
*-*-sunos4*)
	CPPFLAGS="$CPPFLAGS -DSUNOS4"
	;;
*-*-aix*)
	CPPFLAGS="$CPPFLAGS -I/usr/local/include"
	LDFLAGS="$LDFLAGS -L/usr/local/lib"
	if (test "$LD" != "gcc" && test -z "$blibpath"); then
		blibpath="/usr/lib:/lib:/usr/local/lib"
	fi
	;;
*-*-osf*)
	CPPFLAGS="$CPPFLAGS -D_POSIX_PII_SOCKET"
	;;
*-*-darwin*)
	AC_SUBST(COREFOUNDATION)
	COREFOUNDATION="-Wl,-framework,CoreFoundation"
	AC_SUBST(IOKIT)
	IOKIT="-Wl,-framework,IOKit"
	if test "$GCC" = "yes"; then
		CFLAGS="$CFLAGS -no-cpp-precomp"
	fi
	use_libusb=no
	AC_MSG_WARN([[libusb disabled on Darwin for pcsc-lite]])
	;;
esac

# Options
AM_MAINTAINER_MODE

# Checks for programs
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LEX
AC_PROG_GCC_TRADITIONAL
AC_PROG_RANLIB
AC_PATH_PROG(TEST_MINUS_S_SH, bash)
AC_PATH_PROG(TEST_MINUS_S_SH, ksh)
AC_PATH_PROG(TEST_MINUS_S_SH, sh)

# Special check for pthread support
ACX_PTHREAD(
  [AC_DEFINE(
             HAVE_PTHREAD, 
	     1,
             [Define if you have POSIX threads libraries and header files.]
            )
  ], 
  [AC_MSG_ERROR([POSIX thread support required])]
)

CC="$PTHREAD_CC"

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)

# Add libtool support
AM_PROG_LIBTOOL
# Automatically update the libtool script if it becomes out-of-date
#AC_SUBST(LIBTOOL_DEPS)

# Checks for header files
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_DIRENT
AC_CHECK_HEADERS([dirent.h dl.h dlfcn.h errno.h fcntl.h getopt.h malloc.h stdlib.h string.h strings.h sys/filio.h sys/time.h syslog.h unistd.h smartcard/scf.h zone.h sys/tsol/label.h libgen.h arpa/inet.h netdb.h netinet/in.h  sys/file.h sys/ioctl.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_HEADER_TIME

# Checks for library functions
AC_FUNC_ERROR_AT_LINE
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
#AC_FUNC_SELECT
AC_FUNC_SELECT_ARGTYPES

AC_CHECK_FUNCS(daemon flock getopt_long nanosleep strerror vsnprintf atexit gethostbyname getpagesize gettimeofday inet_ntoa memset mkdir mkfifo munmap putenv rmdir select socket strchr strdup strrchr strstr strtol strtoul)

# strlcpy, strlcat from OpenBSD
AC_CHECK_FUNCS(strlcpy strlcat)

# C Compiler features
AC_C_INLINE
if test "$GCC" = "yes"; then
	CFLAGS="-Wall -fno-common $CFLAGS"
fi

# check if the compiler support -fvisibility=hidden (GCC >= 4)
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden"
AC_MSG_CHECKING([for -fvisibility=hidden])
AC_COMPILE_IFELSE([char foo;],
	[	AC_VERBOSE([yes])
		SYMBOL_VISIBILITY="-fvisibility=hidden" ],
	AC_VERBOSE([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AC_SUBST(LIBDL)
AC_CHECK_LIB(dl, dlopen, [LIBDL="$LIBDL -ldl" ac_cv_func_dlopen_ldl=yes], ac_cv_func_dlopen_ldl=no)

# Use 'uname' output as an architecture define
uname=`uname`
case "$uname" in
Darwin)
	uname=MacOS
	;;
SunOS)
	uname=Solaris
	;;
esac
AC_DEFINE_UNQUOTED(PCSC_ARCH, "$uname", [PC/SC target architecture])

# See if socket() is found from libsocket
AC_CHECK_LIB(socket, socket, [LIBS="$LIBS -lsocket"])

# See if gethostbyname is found from libnsl.so
AC_CHECK_LIB(nsl, gethostbyname, [LIBS="$LIBS -lnsl"])

# --enable-xtag                                       
AC_ARG_ENABLE(xtag,
                AS_HELP_STRING([--enable-xtag=<Xservers PATH>],
		[specifies path to system's Xservers file.  Needed only if configuring for portsvc, ie. launcher mode]), 
                [xtag="${enableval}"],[xtag=false])           
AC_VERBOSE([enable xtag: $xtag])             
                                                         
AC_DEFINE_UNQUOTED(xservers_file, 
		   "$xtag", [path to Xservers file])


# --enable-portsvc
AC_ARG_ENABLE(portsvc,
		AS_HELP_STRING([--enable-portsvc=PORT],[specifies port \
                        client library can contact pcscd on if a server \
			instance is running in 'port server' mode. \
			(default=port server mode not available)]),
		[portsvc="${enableval}"],[portsvc=false])
AC_VERBOSE([enable portsvc                : $portsvc])

AC_DEFINE_UNQUOTED(PCSCLITE_PORTSVC_PORTNO, 
		$enableval, 
		[Port client library contacts pcscd on to obtain info])


# --enable-libusb
AC_ARG_ENABLE(libusb,
	AS_HELP_STRING([--disable-libusb,do not use libusb]),
	[ use_libusb="${enableval}" ], [ use_libusb="${use_libusb-yes}" ] )

# check if libusb is used
if test "x$use_libusb" != xno ; then
	PKG_CHECK_MODULES([LIBUSB], [libusb], [],
		[
			AC_VERBOSE([no])
			AC_PROGRAM_CHECK([LIBUSBCONFIG], [libusb-config], [yes])

			if test "$LIBUSBCONFIG" = "yes" ; then
				LIBUSB_CFLAGS="$LIBUSB_CFLAGS `libusb-config --cflags`"
				LIBUSB_LIBS="$LIBUSB_LIBS `libusb-config --libs`"
			else
				AC_MSG_WARN([libusb-config not found.])
			fi
		])

	saved_CPPFLAGS="$CPPFLAGS"
	saved_LIBS="$LIBS"

	CPPFLAGS="$CPPFLAGS $LIBUSB_CFLAGS"
	LIBS="$LDFLAGS $LIBUSB_LIBS"

	AC_CHECK_HEADERS(usb.h, [],
		[ AC_MSG_ERROR([usb.h not found, use ./configure LIBUSB_CFLAGS=...]) ])

	LIBS="$LIBS $COREFOUNDATION $IOKIT"

	AC_MSG_CHECKING([for usb_init])
	AC_TRY_LINK_FUNC(usb_init, [ AC_VERBOSE([yes]) ],
		[ AC_MSG_ERROR([libusb not found, use ./configure LIBUSB_LIBS=...]) ])

	AC_MSG_CHECKING([for usb_get_string_simple])
	AC_TRY_LINK_FUNC(usb_get_string_simple, [ AC_VERBOSE([yes]) ],
		[ AC_MSG_ERROR([your libusb is too old. install version 0.1.7 or above]) ])

	# everything needed for libusb support is present
	use_libusb=yes

	CPPFLAGS="$saved_CPPFLAGS"
	LIBS="$saved_LIBS"
fi
AC_SUBST(LIBUSB_CFLAGS)
AC_SUBST(LIBUSB_LIBS)

if test x$use_libusb = xyes; then
  AC_DEFINE(HAVE_LIBUSB, 1, [Libusb is available])
fi
AC_VERBOSE([enable libusb support         : $use_libusb])

# --enable-usbdropdir=DIR
AC_ARG_ENABLE(usbdropdir,
  AS_HELP_STRING(--enable-usbdropdir=DIR,directory containing USB
				  drivers (default /usr/local/pcsc/drivers)),
[usbdropdir="${enableval}"], [usbdropdir=false])
if test x${usbdropdir} = xfalse ; then
	if test "x$prefix" != xNONE; then
		usbdropdir="$prefix/pcsc/drivers"
	else
		usbdropdir="$ac_default_prefix/pcsc/drivers"
	fi
fi
AC_VERBOSE([enable USB drop directory     : $usbdropdir])
AC_DEFINE_UNQUOTED(PCSCLITE_HP_DROPDIR, "$usbdropdir", [directory containing USB drivers])

# --enable-debugatr
AC_ARG_ENABLE(debugatr,
  AS_HELP_STRING(--enable-debugatr,enable ATR debug messages from pcscd),
[ case "${enableval}" in
  yes)	debugatr=true ;;
  no)	debugatr=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debugatr]) ;;
esac], [debugatr=false])

AC_VERBOSE([enable ATR parsing messages   : $debugatr])

if test x${debugatr} = xtrue ; then
  AC_DEFINE(ATR_DEBUG, 1, [display ATR parsing debug messages.])
fi

# --enable-scf
AC_ARG_ENABLE(scf,
  AS_HELP_STRING(--enable-scf,use SCF for reader support),
[ case "${enableval}" in
  yes)	scf=true ;;
  no)	scf=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-scf]) ;;
esac], [scf=false])

AC_SUBST(LIBSMARTCARD)
if test x$scf = xtrue -a x$ac_cv_header_smartcard_scf_h = xyes; then
  AC_CHECK_LIB(smartcard, SCF_strerror, [LIBSMARTCARD="$LIBSMARTCARD -lsmartcard" scf=true], scf=false)
else
  scf=false
fi
AC_VERBOSE([enable SCF reader support     : $scf])
AM_CONDITIONAL(HAVE_SCF, test x$scf = xtrue)

# --enable-rtlib=DIR
AC_ARG_ENABLE(rtlibdir,
	AS_HELP_STRING(--enable-rtlib=DIR, daemon-specific runtime path for library path, (default /usr/lib/smartcard)), 
	[rtlibdir="${enableval}"], [rtlibdir=false])

if test x${rtlibdir} != xfalse ; then
	AC_VERBOSE([enable rtlibdir               : $rtlibdir])
else
	rtlibdir="/usr/lib/smartcard"
	AC_VERBOSE([enable rtlibdir               : /usr/lib/smartcard (default)])
fi

# --enable-confdir=DIR
AC_ARG_ENABLE(confdir,
	AS_HELP_STRING(--enable-confdir=DIR,directory containing pcsc.conf
			(default /etc)),
	[confdir="${enableval}"], [confdir=false])

if test x${confdir} != xfalse ; then
	AC_VERBOSE([enable confdir                : $confdir])
else
	confdir="/etc"
	AC_VERBOSE([enable confdir                : /etc (default)])
fi

# --enable-runpid=FILE
AC_ARG_ENABLE(runpid,
  AS_HELP_STRING(--enable-runpid=FILE,file containing pcscd pid),
[runpid="${enableval}"], [runpid=false])

AC_VERBOSE([enable runpid                 : $runpid])

# HAVE_RUNPID is for pcscd.8
if test x${runpid} != xfalse ; then
	AC_DEFINE_UNQUOTED(USE_RUN_PID, "$runpid", [file containing pcscd pid])
	AC_SUBST(HAVE_RUNPID,'')
else
	AC_SUBST(HAVE_RUNPID,'.\" ')
fi

# --enable-ipcdir=DIR
AC_ARG_ENABLE(ipcdir,
  AS_HELP_STRING(--enable-ipcdir=DIR,directory containing IPC files
				  (default /var/run)),
[ipcdir="${enableval}"], [ipcdir=false])

if test x${ipcdir} != xfalse ; then
	AC_VERBOSE([enable ipcdir                 : $ipcdir])

	AC_DEFINE_UNQUOTED(USE_IPCDIR, "$ipcdir", [directory containing IPC files (default /var/run)])
else
	AC_VERBOSE([enable ipcdir                 : /var/run (default)])
fi

CPPFLAGS="-I\${top_srcdir}/src $CPPFLAGS"

# HOST_TO_CCID
if test "x$ac_cv_c_bigendian" = "xyes"; then
	AC_SUBST(host_to_ccid_16, ['((((x) >> 8) & 0xFF) + ((x & 0xFF) << 8))'])
	AC_SUBST(host_to_ccid_32, ['((((x) >> 24) & 0xFF) + (((x) >> 8) & 0xFF00) + ((x & 0xFF00) << 8) + (((x) & 0xFF) << 24))'])
	AC_VERBOSE([plateform endianess           : big endian])
else
	AC_SUBST(host_to_ccid_16, ['(x)'])
	AC_SUBST(host_to_ccid_32, ['(x)'])
	AC_VERBOSE([plateform endianess           : little endian])
fi

# Setup dist stuff
AC_SUBST(usbdropdir)
AC_SUBST(confdir)
AC_SUBST(rtlibdir)
AC_SUBST(xtag)
AC_SUBST(libdir)
AC_SUBST(runpid)
AC_SUBST(host_to_ccid_16)
AC_SUBST(host_to_ccid_32)
AS_AC_EXPAND(confdir_exp,$confdir) 
AS_AC_EXPAND(rtlibdir_exp,$rtlibdir)
AS_AC_EXPAND(libdir_exp,$libdir)
AS_AC_EXPAND(xservers_file_exp,$xtag)
AS_AC_EXPAND(sysconfdir_exp,$sysconfdir) 
AS_AC_EXPAND(sbindir_exp,$sbindir)
AS_AC_EXPAND(localstatedir_exp,$localstatedir)

# Write Makefiles
AC_CONFIG_FILES([
Makefile
m4/Makefile
doc/Makefile
doc/doxygen.conf
doc/pcscd.8
doc/reader.conf.5
doc/example/Makefile
etc/Makefile
etc/pcscd.init
etc/reader.conf
etc/update-reader.conf
src/Makefile
src/PCSC/pcsclite.h
src/PCSC/reader.h
src/utils/Makefile
src/modules/Makefile
src/libpcsclite.pc
win32/Makefile
])
AC_OUTPUT

