DATE:sh= date +"%a_%m-%d-%Y_%H:%M" | sed 's/ /_/g'

#PODUCT_NAME  = PC/SC-Lite for Solaris
#PRODUCT_LABEL = pcsclite
PRODUCT_REL   = 100
PRODUCT_BLD   = DEVBLD_$(DATE)

thedate:sh =/bin/date '+%m-%d-%y--%H:%M'
CMD=basename $(DOT)
ARCH:sh=uname -p
OS:sh = uname -s
OSVER:sh = uname -r
PSTAMPDATE:sh = date +"20%y%m%d%H%M%S"
PLATFORM:sh =uname -p
DIST=../dist/$(PLATFORM)
PROTO=../proto
all:
	[ -d $(DIST) ] || mkdir -p $(DIST)
	chmod 755 $(DIST)
	pkgmk \
	  -o \
	  -a $(ARCH) \
	  -d $(DIST) \
	  -r $(PROTO) \
	  -p $(OS)_$(OSVER)_$(PSTAMPDATE) \
	  -v $(PRODUCT_REL)_$(PRODUCT_BLD) \
	1>pkgmk.log 2>&1

clobber:
	rm -rf ../dist/SolarisPCSC

config:

clean:
