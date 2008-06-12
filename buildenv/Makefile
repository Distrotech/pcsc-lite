BASH = /bin/bash

RM	= /usr/bin/rm
CHMOD   = /bin/chmod
CURDIR:sh =pwd
LIB 	= ./proto/usr/lib
LIB64	= ./proto/usr/lib/64
SCLIB 	= $(LIB)/smartcard
INC 	= $./proto/usr/include/smartcard
SCINC	= $(INC)/PCSC
DATE:sh= date +"%a_%m-%d-%Y_%H:%M" | sed 's/ /_/g'
BLD   	= _$(DATE)
PLATFORM:sh =uname -p

default:
	@echo ""
	@echo " Valid make targets: "
	@echo ""
	@echo "   config   - Configure PC/SC-Lite workspace for building" 
	@echo "   all      - Build everything, and make packages"
	@echo "   clean    - Remove built files from source directories" 
	@echo "   clobber  - Remove proto and architecture-specific packages"
	@echo ""

all:	pcsclite solaris install pkg

pcsclite: FRC
	. env; cd pcsclite; make

solaris:	FRC
	cd solaris; make

pkg: FRC
	cd pkgbld; make

config: FRC
	cd pcsclite; $(RM) -f config.log config.status
	PRODUCT_BLD=$(BLD); . env; ./setup $(CURDIR)/proto

install:	FRC
	. env $(BLD); cd pcsclite/src; make install

clean:	FRC
	cd pcsclite; make clean
	cd pcsclite; $(CHMOD) -R 777 m4 doc etc win32 stamp-h1
	cd pkgbld; make clean

DISTFILES  = $(INC)/debug.h 
DISTFILES += $(SCINC)/clientcred.h 
DISTFILES += $(SCINC)/ifdhandler.h
DISTFILES += $(SCINC)/reader.h 
DISTFILES += $(SCINC)/wintypes.h 
DISTFILES += $(SCINC)/debuglog.h
DISTFILES += $(SCINC)/pcscd-validate.h 
DISTFILES += $(SCINC)/pcscd-auth.h
DISTFILES += $(SCLIB)/pcscd 
DISTFILES += $(SCLIB)/installifd 
DISTFILES += $(SCLIB)/formaticc
DISTFILES += $(SCINC)/pcsclite.h 
DISTFILES += $(SCINC)/winscard.h
DISTFILES += $(LIB)/libpcsclite.* 
DISTFILES += $(LIB)/pkgconfig

clobber:
	$(RM) -rf proto $(DISTFILES)
	$(RM) -rf dist/$(PLATFORM)

.PRECIOUS:
	config 

FRC:
