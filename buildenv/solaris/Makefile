
RM		= /usr/bin/rm
MKDIR		= /usr/bin/mkdir

SMF		= ../proto/smf
ETC		= ../proto/etc/smartcard
LIB             = ../proto/usr/lib/smartcard

DISTDIRS	= $(SMF) $(ETC) $(LIB)
SMF_FILES	= pcscd.xml pcscd-svc
ETC_FILES	= pcscd.conf pcscd-Local.conf
LIB_FILES       = pcscd-Local

all:	install
	
install:	$(DISTDIRS)
	cp $(SMF_FILES) $(SMF)
	cp $(ETC_FILES) $(ETC)
	cp $(LIB_FILES) $(LIB)

$(DISTDIRS):	FRC
	[ -d $@ ] || $(MKDIR) -p $@ 

clean:
	$(RM) -f $(SMF)/pcscd.xml
	$(RM) -f $(SMF)/pcscd-svc
	$(RM) -f $(ETC)/pcscd.conf
	$(RM) -f $(ETC)/pcscd-Local.conf

config:

clobber:

pkg:

FRC:
